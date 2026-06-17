package troad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"sync"

	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"

	"github.com/jing-zhou/tun2socks/v2/dialer"
	M "github.com/jing-zhou/tun2socks/v2/metadata"
	"github.com/jing-zhou/tun2socks/v2/proxy"
	"github.com/jing-zhou/tun2socks/v2/proxy/internal/utils"
	"github.com/jing-zhou/tun2socks/v2/transport/troad"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/elliptic"
)

var (

	_ proxy.Proxy = (*Troad)(nil)

	// ADD THIS: Thread-safe storage for the live authentication header
	activeHeader []byte
	headerMutex  sync.RWMutex

)

type Troad struct {
	addr   string
	cacert string
	sni    string
	mtu    int
	unix   bool
}

// UpdateHeader is exported to Android to hot-provision renewed tokens on-the-fly.
func UpdateHeader(newHeader []byte) error {
	headerMutex.Lock()
	// Create a deep copy of the slice to remain thread-safe from JVM garbage collection
	activeHeader = make([]byte, len(newHeader))
	copy(activeHeader, newHeader)
	headerMutex.Unlock()
	return nil
}

// GetHeader retrieves the current token string safely across threads.
func GetHeader() []byte {
	headerMutex.RLock()
	defer headerMutex.RUnlock()
	return activeHeader
}

func NewTroad(addr, cacert, sni string, mtu int) (*Troad, error) {
	unix := len(addr) > 0 && addr[0] == '/'

	// For support Linux abstract namespace
	if len(addr) > 2 && addr[1] == '@' || addr[1] == 0x00 {
		addr = addr[1:]
	}

	return &Troad{
		addr:   addr,
		cacert: cacert,
		sni:    sni,
		mtu:    mtu,
		unix:   unix,
	}, nil
}

func (td *Troad) DialContext(ctx context.Context, metadata *M.Metadata) (net.Conn, error) {
	network := "tcp"
	if td.unix {
		network = "unix"
	}

	// Dial the raw underlying connection
	rawConn, err := dialer.DialContext(ctx, network, td.addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", td.addr, err)
	}

	// Get TLS configuration
	tlsConfig, err := td.getTLSConfig()
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	// Upgrade the connection to TLS
	tlsConn := tls.Client(rawConn, tlsConfig)

	// Perform handshake with context timeout support
	err = tlsConn.HandshakeContext(ctx)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("tls handshake: %w", err)
	}

	// Now proceed with your protocol-specific handshake (Trojan/Troad)
	_, err = troad.ClientHandshake(tlsConn, troad.SerializeAddr("", metadata.DstIP, metadata.DstPort), troad.CmdConnect, GetHeader())
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (td *Troad) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	// 1. Establish the Secure Control Channel (TCP + TLS)
	ctx, cancel := context.WithTimeout(context.Background(), utils.TCPConnectTimeout)
	defer cancel()

	rawConn, err := dialer.DialContext(ctx, "tcp", td.addr)
	if err != nil {
		return nil, fmt.Errorf("dial control: %w", err)
	}

	tlsConf, _ := td.getTLSConfig()
	tlsConn := tls.Client(rawConn, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("control tls handshake: %w", err)
	}

	// 2. Authenticate and Request UDP Associate
	// Server verifies 'td.header' here and returns a temporary Bind Address
	var targetAddr troad.Addr = []byte{troad.AtypIPv4, 0, 0, 0, 0, 0, 0}
	addr, err := troad.ClientHandshake(tlsConn, targetAddr, troad.CmdUDPAssociate, GetHeader())
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("troad associate: %w", err)
	}

	// 3. Initiate DTLS on the Bind Address
	bindAddr := addr.UDPAddr()
	if bindAddr == nil {
		tlsConn.Close()
		return nil, errors.New("invalid bind address from server")
	}

	dtlsConf, err := td.getDTLSClientOptions()
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Connect DTLS to the ephemeral port provided by the server
	dtlsConn, err := dtls.DialWithOptions("udp", bindAddr, dtlsConf...)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dtls handshake on %s: %w", bindAddr, err)
	}

	// 4. Maintenance: Link TCP life to DTLS life
	go func() {
		// Keep TCP open; if it closes (EOF), close the DTLS relay
		io.Copy(io.Discard, tlsConn)
		tlsConn.Close()
		dtlsConn.Close()
	}()

	return &socksPacketConn{
		PacketConn: &dtlsConnWrapper{dtlsConn},
		rAddr:      bindAddr,
		tcpConn:    tlsConn,
	}, nil
}

func (td *Troad) getTLSConfig() (*tls.Config, error) {
	certPool, err := x509.SystemCertPool()
	if err != nil {
		certPool = x509.NewCertPool()
	}

	if td.cacert != "" {
		caPEM, err := os.ReadFile(td.cacert)
		if err != nil {
			return nil, fmt.Errorf("read cacert: %w", err)
		}
		if ok := certPool.AppendCertsFromPEM(caPEM); !ok {
			return nil, errors.New("failed to parse CA certificate")
		}
	}

	// Determine the ServerName for the TLS handshake
	serverName := td.sni
	if serverName == "" && !td.unix {
		// If no SNI provided, extract host from addr (e.g., "1.2.3.4:443" -> "1.2.3.4")
		host, _, err := net.SplitHostPort(td.addr)
		if err == nil {
			serverName = host
		} else {
			serverName = td.addr
		}
	}

	return &tls.Config{
		RootCAs:            certPool,
		ServerName:         serverName,       // This MUST match the CN/SAN in the certificate
		InsecureSkipVerify: serverName == "", // Add this as a safety net
	}, nil
}

func (td *Troad) getDTLSClientOptions() ([]dtls.ClientOption, error) {
	tlsConf, err := td.getTLSConfig()
	if err != nil {
		return nil, err
	}

	options := []dtls.ClientOption{
		// Root CAs and ServerName from your TLS config
		dtls.WithRootCAs(tlsConf.RootCAs),
		dtls.WithServerName(tlsConf.ServerName),

		// InsecureSkipVerify
		dtls.WithInsecureSkipVerify(tlsConf.InsecureSkipVerify),

		// MTU configuration
		dtls.WithMTU(td.mtu),

		// Elliptic Curves (Note: v3 has migrated toward ecdh-based options)
		dtls.WithEllipticCurves(elliptic.P256),

		// Cipher Suites
		dtls.WithCipherSuites(
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		),
	}

	return options, nil
}

type socksPacketConn struct {
	net.PacketConn // This is actually your *dtlsConnWrapper
	rAddr          net.Addr
	tcpConn        net.Conn
}

func (pc *socksPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// 1. Wrap the raw UDP packet with Troad/SOCKS5 header
	// [RSV][RSV][FRAG][ATYP][DST.ADDR][DST.PORT][DATA]
	var packet []byte
	var err error

	if ma, ok := addr.(*M.Addr); ok {
		packet, err = troad.EncodeUDPPacket(troad.SerializeAddr("", ma.Metadata().DstIP, ma.Metadata().DstPort), b)
	} else {
		packet, err = troad.EncodeUDPPacket(troad.ParseAddr(addr), b)
	}
	if err != nil {
		return 0, err
	}

	// 2. Send through DTLS. Since it's a 'dialed' DTLS conn,
	// we just call Write (via our WriteTo shim).
	return pc.PacketConn.WriteTo(packet, pc.rAddr)
}

func (pc *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// 1. Read from DTLS (decryption happens automatically)
	n, _, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	// 2. Strip the Troad/SOCKS5 header to get the raw payload
	addr, payload, err := troad.DecodeUDPPacket(b[:n])
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, fmt.Errorf("invalid UDP addr: %v", addr)
	}

	// 3. Move payload to the front of the slice for tun2socks
	copy(b, payload)
	return len(payload), udpAddr, nil
}

func (pc *socksPacketConn) Close() error {
	pc.tcpConn.Close()
	return pc.PacketConn.Close()
}

func Parse(u *url.URL) (proxy.Proxy, error) {
	address := u.Host
	if address == "" {
		address = u.Path
	}

	query := u.Query()
	caCertPath := query.Get("cacert")
	sni := query.Get("sni")
	

	// Parse MTU from string to int
	mtuStr := query.Get("mtu")
	mtu, _ := strconv.Atoi(mtuStr)
	if mtu <= 0 {
		mtu = 1500 // Default fallback if not provided
	}

	return &Troad{
		addr:   address,
		cacert: caCertPath,
		sni:    sni,
		unix:   len(address) > 0 && address[0] == '/',
		mtu:    mtu,
	}, nil
}

func init() {
	proxy.RegisterProtocol("troad", Parse)
}

/**
  * A typical URL for your Troad protocol follows the standard URI scheme used by other proxy tools (like Trojan, V2Ray, or Shadowsocks).
  * Since you are using header-based authentication (no password) and require TLS configuration, it should look like this:
  *
  *1. Standard Production URL
  *	This is the most common format using an IP address and a domain for SNI:

  *	troad://1.2.3.4:443?header=your-secret-token&cacert=/etc/ssl/certs/ca.pem&sni=myserver.com&mtu=1300
  *
  *2. Simple Domain-based URL
  *	If the server's domain matches its certificate, you can omit the sni parameter:

  *	troad://proxy.example.com:443?header=your-secret-token&cacert=./ca.crt&mtu=1300
  *
  *3. Unix Domain Socket (UDS) URL
  *	If you are connecting to a local provider via a socket file:

  *	troad:///tmp/troad.sock?header=your-token&cacert=/path/to/cert&mtu=1300
  *
  3. Typical URL with MTU
	Your configuration URL will now look like this:
	troad://1.2.3.4:443?header=SGVsbG8=&sni=myserver.com&mtu=1300

   Breakdown of the Components:
	Component			Part of URL			Purpose
	------------------------------------------------------------
	Scheme				troad://		Triggers your proxy.RegisterProtocol("troad", Parse)
	Address				1.2.3.4:443		The physical server you are connecting to
	Header				?header=...		Your custom authentication token (extracted in Parse)
	CA Cert				&cacert=...		Path to the .pem or .crt file on your local machine
	SNI					&sni=...		The hostname used for the TLS handshake (Server Name Indication)
	MTU					&mtu=...		Optional parameter to specify the MTU for DTLS (default is 1500)

Pro-Tip for Configuration
When using these URLs in a shell or a config file, remember to URL-encode special characters in your header (e.g., if your header contains a & or #, it must be written as %26 or %23).

*/
