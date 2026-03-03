package troad

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"

	"github.com/jing-zhou/tun2socks/v2/dialer"
	M "github.com/jing-zhou/tun2socks/v2/metadata"
	"github.com/jing-zhou/tun2socks/v2/proxy"
	"github.com/jing-zhou/tun2socks/v2/proxy/internal/utils"
	"github.com/jing-zhou/tun2socks/v2/transport/troad"
	"github.com/pion/dtls/v2"
)

var _ proxy.Proxy = (*Troad)(nil)

type Troad struct {
	addr   string
	cacert string
	header []byte
	sni    string // <--- Add this
	unix   bool
}

func NewTroad(addr, cacert, sni string, header []byte) (*Troad, error) {
	unix := len(addr) > 0 && addr[0] == '/'

	// For support Linux abstract namespace
	if len(addr) > 2 && addr[1] == '@' || addr[1] == 0x00 {
		addr = addr[1:]
	}

	return &Troad{
		addr:   addr,
		cacert: cacert,
		header: header,
		sni:    sni,
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
	_, err = troad.ClientHandshake(tlsConn, troad.SerializeAddr("", metadata.DstIP, metadata.DstPort), troad.CmdConnect, td.header)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

func (td *Troad) DialUDP(metadata *M.Metadata) (net.PacketConn, error) {
	// 1. Setup TCP/TLS Control Channel
	ctx, cancel := context.WithTimeout(context.Background(), utils.TCPConnectTimeout)
	defer cancel()

	rawConn, err := dialer.DialContext(ctx, "tcp", td.addr)
	if err != nil {
		return nil, err
	}

	tlsConf, _ := td.getTLSConfig()
	tlsConn := tls.Client(rawConn, tlsConf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}

	// 2. Request UDP Associate & Get Bind Address
	// Sending 0.0.0.0:0 as per SOCKS5 spec
	var targetAddr troad.Addr = []byte{troad.AtypIPv4, 0, 0, 0, 0, 0, 0}
	addr, err := troad.ClientHandshake(tlsConn, targetAddr, troad.CmdUDPAssociate, td.header)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	// 3. Initiate DTLS Handshake on the returned Bind Address
	bindAddr := addr.UDPAddr()
	dtlsConf, err := td.getDTLSConfig()
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	// Connect DTLS to the dynamic port the server just gave us
	dtlsConn, err := dtls.Dial("udp", bindAddr, dtlsConf)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dtls handshake failed on %s: %w", bindAddr, err)
	}

	// 4. Maintenance: If TCP drops, DTLS must drop
	go func() {
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
		RootCAs:    certPool,
		ServerName: serverName, // This MUST match the CN/SAN in the certificate
	}, nil
}

func (td *Troad) getDTLSConfig() (*dtls.Config, error) {
	tlsConf, err := td.getTLSConfig()
	if err != nil {
		return nil, err
	}

	return &dtls.Config{
		RootCAs:            tlsConf.RootCAs,
		ServerName:         tlsConf.ServerName,
		InsecureSkipVerify: tlsConf.InsecureSkipVerify,
		// Standard secure ciphers for DTLS
		CipherSuites: []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}, nil
}

type socksPacketConn struct {
	net.PacketConn

	rAddr   net.Addr
	tcpConn net.Conn
}

func (pc *socksPacketConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	var packet []byte
	if ma, ok := addr.(*M.Addr); ok {
		packet, err = troad.EncodeUDPPacket(troad.SerializeAddr("", ma.Metadata().DstIP, ma.Metadata().DstPort), b)
	} else {
		packet, err = troad.EncodeUDPPacket(troad.ParseAddr(addr), b)
	}

	if err != nil {
		return n, err
	}
	return pc.PacketConn.WriteTo(packet, pc.rAddr)
}

func (pc *socksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, _, err := pc.PacketConn.ReadFrom(b)
	if err != nil {
		return 0, nil, err
	}

	addr, payload, err := troad.DecodeUDPPacket(b)
	if err != nil {
		return 0, nil, err
	}

	udpAddr := addr.UDPAddr()
	if udpAddr == nil {
		return 0, nil, fmt.Errorf("convert %s to UDPAddr is nil", addr)
	}

	// due to DecodeUDPPacket is mutable, record addr length
	copy(b, payload)
	return n - len(addr) - 3, udpAddr, nil
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
	headerStr := query.Get("header")

	var headerBytes []byte
	var err error

	if headerStr != "" {
		// Attempt to decode as URL-Safe Base64 first
		headerBytes, err = base64.URLEncoding.DecodeString(headerStr)
		if err != nil {
			// Fallback: Try Standard Base64 if URL-Safe fails
			headerBytes, err = base64.StdEncoding.DecodeString(headerStr)
			if err != nil {
				// Final Fallback: If not valid Base64, treat as raw string bytes
				headerBytes = []byte(headerStr)
			}
		}
	}

	return &Troad{
		addr:   address,
		cacert: caCertPath,
		header: headerBytes,
		sni:    sni,
		unix:   len(address) > 0 && address[0] == '/',
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

  *	troad://1.2.3.4:443?header=your-secret-token&cacert=/etc/ssl/certs/ca.pem&sni=myserver.com
  *
  *2. Simple Domain-based URL
  *	If the server's domain matches its certificate, you can omit the sni parameter:

  *	troad://proxy.example.com:443?header=your-secret-token&cacert=./ca.crt
  *
  *3. Unix Domain Socket (UDS) URL
  *	If you are connecting to a local provider via a socket file:

  *	troad:///tmp/troad.sock?header=your-token&cacert=/path/to/cert
  *

   Breakdown of the Components:
	Component			Part of URL			Purpose
	------------------------------------------------------------
	Scheme				troad://		Triggers your proxy.RegisterProtocol("troad", Parse)
	Address				1.2.3.4:443		The physical server you are connecting to
	Header				?header=...		Your custom authentication token (extracted in Parse)
	CA Cert				&cacert=...		Path to the .pem or .crt file on your local machine
	SNI					&sni=...		The hostname used for the TLS handshake (Server Name Indication)


Pro-Tip for Configuration
When using these URLs in a shell or a config file, remember to URL-encode special characters in your header (e.g., if your header contains a & or #, it must be written as %26 or %23).

*/
