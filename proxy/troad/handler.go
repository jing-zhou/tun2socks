package troad

import (
	"net"
	"time"
)

type dtlsConnWrapper struct {
	net.Conn
}

func (d *dtlsConnWrapper) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = d.Read(p)
	return n, d.RemoteAddr(), err
}

func (d *dtlsConnWrapper) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	// We ignore 'addr' because DTLS is already dialed to the bindAddr
	return d.Write(p)
}

func (d *dtlsConnWrapper) LocalAddr() net.Addr                { return d.Conn.LocalAddr() }
func (d *dtlsConnWrapper) SetDeadline(t time.Time) error      { return d.Conn.SetDeadline(t) }
func (d *dtlsConnWrapper) SetReadDeadline(t time.Time) error  { return d.Conn.SetReadDeadline(t) }
func (d *dtlsConnWrapper) SetWriteDeadline(t time.Time) error { return d.Conn.SetWriteDeadline(t) }
