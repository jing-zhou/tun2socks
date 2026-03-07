package engine

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	// Standard tun2socks v2 import
)

var (
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	running bool
)

// StartTun2Socks - Setup and Start
func StartTun2Socks(fd int, addr string, port int, mtu int, cert string, header string, sni string) int {
	mu.Lock()
	if running {
		mu.Unlock()
		return 0
	}

	// 1. Setup Context for Stopping
	ctx, ctxCancel := context.WithCancel(context.Background())
	cancel = ctxCancel
	running = true
	mu.Unlock()

	// 2. Wrap the Android File Descriptor
	tunFile := os.NewFile(uintptr(fd), "tun")
	if tunFile == nil {
		return 1
	}
	defer tunFile.Close()

	// 3. Setup SOCKS5 Configuration
	// Format: socks5://host:port
	proxyURL := fmt.Sprintf("socks5://%s:%d", addr, port)

	cfg := &engine.Config{
		Proxy:  proxyURL,
		MTU:    mtu,
		Device: fmt.Sprintf("fd://%d", fd), // Using the FD directly
	}

	log.Printf("Starting SOCKS5: %s", proxyURL)

	// 4. Start the Engine
	// This registers the configuration and starts the internal stack
	if err := engine.Insert(cfg); err != nil {
		log.Printf("Insert error: %v", err)
		return 1
	}

	if err := engine.Start(); err != nil {
		log.Printf("Start error: %v", err)
		return 1
	}

	// 5. Block until Context is Cancelled
	<-ctx.Done()

	// 6. Clean up
	engine.Stop()

	mu.Lock()
	running = false
	mu.Unlock()

	log.Println("SOCKS5 Engine Stopped")
	return 0
}

// StopTun2Socks - Stop
func StopTun2Socks() {
	mu.Lock()
	defer mu.Unlock()
	if cancel != nil {
		log.Println("Signaling SOCKS5 Stop...")
		cancel() // This triggers <-ctx.Done() in StartTun2Socks
	}
}
