package troad

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/jing-zhou/tun2socks/v2/transport/internal/bufferpool"
)

// Version is the protocol version as defined in RFC 1928 section 4.
const Version = 0x05

// Command is request commands as defined in RFC 1928 section 4.
type Command uint8

// SOCKS request commands as defined in RFC 1928 section 4.
const (
	CmdConnect      Command = 0x01
	CmdBind         Command = 0x02
	CmdUDPAssociate Command = 0x03
)

func (c Command) String() string {
	switch c {
	case CmdConnect:
		return "CONNECT"
	case CmdBind:
		return "BIND"
	case CmdUDPAssociate:
		return "UDP ASSOCIATE"
	default:
		return "UNDEFINED"
	}
}

type Atyp = uint8

// SOCKS address types as defined in RFC 1928 section 5.
const (
	AtypIPv4       Atyp = 0x01
	AtypDomainName Atyp = 0x03
	AtypIPv6       Atyp = 0x04
)

// Reply field as defined in RFC 1928 section 6.
type Reply uint8

func (r Reply) String() string {
	switch r {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("unassigned <%#02x>", uint8(r))
	}
}

// MaxAddrLen is the maximum size of SOCKS address in bytes.
const MaxAddrLen = 1 + 1 + 255 + 2

// Addr represents a SOCKS address as defined in RFC 1928 section 5.
type Addr []byte

func (a Addr) Valid() bool {
	if len(a) < 1+1+2 /* minimum length */ {
		return false
	}

	switch a[0] {
	case AtypDomainName:
		if len(a) < 1+1+int(a[1])+2 {
			return false
		}
	case AtypIPv4:
		if len(a) < 1+net.IPv4len+2 {
			return false
		}
	case AtypIPv6:
		if len(a) < 1+net.IPv6len+2 {
			return false
		}
	}
	return true
}

// String returns string of socks5.Addr.
func (a Addr) String() string {
	if !a.Valid() {
		return ""
	}

	var host, port string
	switch a[0] {
	case AtypDomainName:
		hostLen := int(a[1])
		host = string(a[2 : 2+hostLen])
		port = strconv.Itoa(int(binary.BigEndian.Uint16(a[2+hostLen:])))
	case AtypIPv4:
		host = net.IP(a[1 : 1+net.IPv4len]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(a[1+net.IPv4len:])))
	case AtypIPv6:
		host = net.IP(a[1 : 1+net.IPv6len]).String()
		port = strconv.Itoa(int(binary.BigEndian.Uint16(a[1+net.IPv6len:])))
	}
	return net.JoinHostPort(host, port)
}

// UDPAddr converts a socks5.Addr to *net.UDPAddr.
func (a Addr) UDPAddr() *net.UDPAddr {
	if !a.Valid() {
		return nil
	}

	var ip []byte
	var port int
	switch a[0] {
	case AtypDomainName /* unsupported */ :
		return nil
	case AtypIPv4:
		ip = make([]byte, net.IPv4len)
		copy(ip, a[1:1+net.IPv4len])
		port = int(binary.BigEndian.Uint16(a[1+net.IPv4len:]))
	case AtypIPv6:
		ip = make([]byte, net.IPv6len)
		copy(ip, a[1:1+net.IPv6len])
		port = int(binary.BigEndian.Uint16(a[1+net.IPv6len:]))
	}
	return &net.UDPAddr{IP: ip, Port: port}
}

// ClientHandshake fast-tracks SOCKS initialization to get target address to connect on client side.
// It enforces strict bounds on server-side pseudo-traffic used to obfuscate TLS-in-TLS fingerprinting.
func ClientHandshake(rw io.ReadWriter, addr Addr, command Command, header []byte) (Addr, error) {
	// Size the buffer to easily handle both MaxAddrLen and the strict max 900-byte pseudo payload.
	// This keeps all handshake reading entirely on the stack (zero allocation path).
	buf := make([]byte, 1024)

	// Prepare payload: VER, CMD, RSV, ADDR
	req := bufferpool.Get()
	defer bufferpool.Put(req)

	req.Grow(len(header) + 3 + MaxAddrLen)
	req.Write(header)
	req.WriteByte(Version)
	req.WriteByte(byte(command))
	req.WriteByte(0x00 /* RSV */)
	req.Write(addr)

	// Send the obfuscated header + SOCKS request to the server
	if _, err := rw.Write(req.Bytes()); err != nil {
		return nil, err
	}

	// 1. Read the 2-byte length field of the incoming pseudo-traffic
	if _, err := io.ReadFull(rw, buf[:2]); err != nil {
		return nil, fmt.Errorf("failed to read pseudo-traffic length header: %w", err)
	}
	
	// Interpret the length field (using network Big Endian)
	pseudoLength := binary.BigEndian.Uint16(buf[:2])

	// 2. Enforce strict upper bound constraint
	if pseudoLength > 900 {
		return nil, fmt.Errorf("protocol anomaly: pseudo-traffic length %d exceeds safety limit of 900", pseudoLength)
	}
	// The length field must be at least 600 bytes and end with CRLF trailer
	if pseudoLength < 600 {
		return nil, fmt.Errorf("protocol anomaly: pseudo-traffic length %d is too short", pseudoLength)
	}

	// 3. Read exactly the remainder of the pseudo-traffic payload.
	// Note: pseudoLength already includes the trailing CRLF bytes.
	pseudoBuf := buf[:pseudoLength]
	if _, err := io.ReadFull(rw, pseudoBuf); err != nil {
		return nil, fmt.Errorf("failed to swallow pseudo-traffic payload: %w", err)
	}

	// 4. Structural validation: Check the final two bytes for raw '\r' and '\n'
	if pseudoBuf[pseudoLength-2] != '\r' || pseudoBuf[pseudoLength-1] != '\n' {
		return nil, fmt.Errorf("protocol anomaly: pseudo-traffic missing trailing CRLF bytes")
	}

	// 5. Decoy bypassed. Read the authentic SOCKS reply header: VER, REP, RSV (3 bytes)
	if _, err := io.ReadFull(rw, buf[:3]); err != nil {
		return nil, fmt.Errorf("failed to read socks reply header: %w", err)
	}

	if rep := Reply(buf[1]); rep != 0x00 /* SUCCEEDED */ {
		return nil, fmt.Errorf("%s: proxy error code %s", command, rep)
	}

	// 6. Read and return the final bound address from the server
	return ReadAddr(rw, buf)
}


func ReadAddr(r io.Reader, b []byte) (Addr, error) {
	if len(b) < MaxAddrLen {
		return nil, io.ErrShortBuffer
	}

	// read 1st byte for address type
	if _, err := io.ReadFull(r, b[:1]); err != nil {
		return nil, err
	}

	switch b[0] /* ATYP */ {
	case AtypDomainName:
		// read 2nd byte for domain length
		if _, err := io.ReadFull(r, b[1:2]); err != nil {
			return nil, err
		}
		domainLength := uint16(b[1])
		_, err := io.ReadFull(r, b[2:2+domainLength+2])
		return b[:1+1+domainLength+2], err
	case AtypIPv4:
		_, err := io.ReadFull(r, b[1:1+net.IPv4len+2])
		return b[:1+net.IPv4len+2], err
	case AtypIPv6:
		_, err := io.ReadFull(r, b[1:1+net.IPv6len+2])
		return b[:1+net.IPv6len+2], err
	default:
		return nil, errors.New("invalid address type")
	}
}

// SplitAddr slices a SOCKS address from beginning of b. Returns nil if failed.
func SplitAddr(b []byte) Addr {
	addrLen := 1
	if len(b) < addrLen {
		return nil
	}

	switch b[0] {
	case AtypDomainName:
		if len(b) < 2 {
			return nil
		}
		addrLen = 1 + 1 + int(b[1]) + 2
	case AtypIPv4:
		addrLen = 1 + net.IPv4len + 2
	case AtypIPv6:
		addrLen = 1 + net.IPv6len + 2
	default:
		return nil
	}

	if len(b) < addrLen {
		return nil
	}

	return b[:addrLen]
}

// SerializeAddr serializes destination address and port to Addr.
// If a domain name is provided, AtypDomainName would be used first.
func SerializeAddr(domainName string, dstIP netip.Addr, dstPort uint16) Addr {
	var (
		buf  [][]byte
		port [2]byte
	)
	binary.BigEndian.PutUint16(port[:], dstPort)

	if domainName != "" /* Domain Name */ {
		length := len(domainName)
		buf = [][]byte{{AtypDomainName, uint8(length)}, []byte(domainName), port[:]}
	} else if dstIP.Is4() /* IPv4 */ {
		buf = [][]byte{{AtypIPv4}, dstIP.AsSlice(), port[:]}
	} else /* IPv6 */ {
		buf = [][]byte{{AtypIPv6}, dstIP.AsSlice(), port[:]}
	}
	return bytes.Join(buf, nil)
}

// ParseAddr parses a socks addr from net.Addr.
// This is a fast path of ParseAddrString(addr.String())
func ParseAddr(addr net.Addr) Addr {
	if v, ok := addr.(interface {
		AddrPort() netip.AddrPort
	}); ok {
		ap := v.AddrPort()
		return SerializeAddr("", ap.Addr(), ap.Port())
	}
	return ParseAddrString(addr.String())
}

// ParseAddrString parses the address in string s to Addr. Returns nil if failed.
func ParseAddrString(s string) Addr {
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return nil
	}

	dstPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil
	}

	if ip, _ := netip.ParseAddr(host); ip.IsValid() {
		return SerializeAddr("", ip, uint16(dstPort))
	}
	return SerializeAddr(host, netip.Addr{}, uint16(dstPort))
}

// DecodeUDPPacket splits `packet` into address and payload.
// This function is mutable and references the original packet slice for the payload.
func DecodeUDPPacket(packet []byte) (addr Addr, payload []byte, err error) {
	if len(packet) < 4 {
		return nil, nil, errors.New("insufficient length of packet")
	}

	// RSV: packet[0], packet[1] must be 0x00
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return nil, nil, errors.New("reserved fields must be zero")
	}

	// FRAG: packet[2]
	// Most implementations (including tun2socks) do not support SOCKS5 fragmentation.
	if packet[2] != 0x00 {
		return nil, nil, fmt.Errorf("fragmentation not supported: 0x%02x", packet[2])
	}

	// ATYP: packet[3] starts the address
	addr = SplitAddr(packet[3:])
	if addr == nil {
		return nil, nil, errors.New("failed to parse address in UDP packet")
	}

	// The payload starts immediately after the address
	payloadOffset := 3 + len(addr)
	if len(packet) < payloadOffset {
		return nil, nil, errors.New("packet too short for payload")
	}

	return addr, packet[payloadOffset:], nil
}

// EncodeUDPPacket wraps the payload with the SOCKS5 UDP header.
func EncodeUDPPacket(addr Addr, payload []byte) ([]byte, error) {
	if addr == nil {
		return nil, errors.New("nil address")
	}

	// Header: RSV(2) + FRAG(1) + ADDR(len) + PAYLOAD
	buf := make([]byte, 3+len(addr)+len(payload))
	buf[0] = 0x00 // RSV
	buf[1] = 0x00 // RSV
	buf[2] = 0x00 // FRAG (no fragmentation)

	copy(buf[3:], addr)
	copy(buf[3+len(addr):], payload)

	return buf, nil
}
