package troadengine

import (
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"syscall"

	"github.com/jing-zhou/tun2socks/v2/engine"
	"github.com/jing-zhou/tun2socks/v2/proxy/troad"

	log "github.com/sirupsen/logrus"
)


var (

	// Global channel to manage lifecycle from Android
	stopCh       = make(chan struct{}, 1)	
)

// UpdateHeader is exported to Android to hot-provision renewed tokens on-the-fly.
func UpdateHeader(newHeader []byte) error {
	return troad.UpdateHeader(newHeader)
}

// StartTroad starts the tun2socks engine with Troad protocol
// Parameters:
//   - serverAddr: server address (e.g., "1.2.3.4:443" or "proxy.example.com:443")
//   - header: authentication header/token (will be base64 encoded if needed)
//   - cacertPath: path to CA certificate file (optional, use "" for system certs)
//   - sni: Server Name Indication for TLS (optional, will use serverAddr if empty)
//   - mtu: Maximum Transmission Unit for DTLS (use 0 for default 1500)
//
// Example usage:
//
//	StartTroad("proxy.example.com:443", "my-token", "/path/to/ca.pem", "myserver.com", 1300)
//	StartTroad("1.2.3.4:443", "SGVsbG8=", "", "", 0)
//
// StartTroad now accepts the Android TUN file descriptor (tunFd)
func StartTroad(tunFd int, serverAddr string, header []byte, cacertPath, sni string, mtu int) error {
	
	// Initialize the memory register with the first configuration payload
	troad.UpdateHeader(header)

	// CRITICAL SHIFT: Pass a functional closure or hook to your underlying proxy implementation 
	// instead of a immutable query token string if 'engine' executes single-shot parsing.
	troadURL := buildTroadURL(serverAddr, cacertPath, sni, mtu)

	key := &engine.Key{
		Proxy:    troadURL,
		Device:   fmt.Sprintf("fd://%d", tunFd),
		LogLevel: "info",
		MTU:      mtu,
	}

	engine.Insert(key)

	engine.Start()

	// Wait for either a system signal OR a programmatic stop call
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-sigCh:
		log.Info("Stop triggered by OS signal")
	case <-stopCh:
		log.Info("Stop triggered programmatically by Android")
	}

	engine.Stop()

	// ADD THIS: Drain the stopCh to clear any stale signals for the next run
	select {
	case <-stopCh:
	default:
	}

	log.Info("Troad Tun2Socks engine stopped successfully")
	return nil
}

func StopTroad() error {
	// Close the channel to unblock the Start function
	select {
	case stopCh <- struct{}{}:
	default:
		// Already stopping or no one listening
	}
	return nil
}

// buildTroadURL constructs a Troad protocol URL from parameters
// Format: troad://serverAddr?header=xxx&cacert=xxx&sni=xxx&mtu=xxx
//
// The resulting URL follows the standard format:
//
//	troad://1.2.3.4:443?header=your-secret-token&cacert=/etc/ssl/certs/ca.pem&sni=myserver.com&mtu=1300
//
// URL Component Breakdown:
//   - Scheme: troad:// - Triggers the Troad protocol parser
//   - Address: 1.2.3.4:443 - The physical server address
//   - header: Authentication token (can be base64 encoded or plain text)
//   - cacert: Path to CA certificate file on local machine
//   - sni: Server Name Indication for TLS handshake
//   - mtu: Maximum Transmission Unit for DTLS (default: 1500)
//
// Example URLs:
//  1. Standard production: troad://proxy.example.com:443?header=token&cacert=/path/to/ca.pem&sni=myserver.com&mtu=1300
//  2. With IP and SNI: troad://1.2.3.4:443?header=SGVsbG8=&sni=myserver.com&mtu=1300
//  3. Unix socket: troad:///tmp/troad.sock?header=token&cacert=/path/to/cert&mtu=1300
//  4. Minimal setup: troad://proxy.example.com:443?header=my-token
func buildTroadURL(serverAddr, cacertPath, sni string, mtu int) string {
	if serverAddr == "" {
		log.Fatal("Troad server address cannot be empty")
	}

	// Start with base URL
	troadURL := fmt.Sprintf("troad://%s", serverAddr)

	// Build query parameters
	params := url.Values{}

	if cacertPath != "" {
		params.Add("cacert", cacertPath)
	}

	if sni != "" {
		params.Add("sni", sni)
	}

	if mtu > 0 {
		params.Add("mtu", fmt.Sprintf("%d", mtu))
	}

	// Append query parameters if any exist
	if len(params) > 0 {
		troadURL += "?" + params.Encode()
	}

	log.Infof("Troad proxy URL: %s", troadURL)
	return troadURL
}
