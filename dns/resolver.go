package dns

import (
	"net"

	"github.com/jing-zhou/tun2socks/v2/dialer"
)

func init() {
	// We must use this DialContext to query DNS
	// when using net default resolver.
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = dialer.DialContext
}
