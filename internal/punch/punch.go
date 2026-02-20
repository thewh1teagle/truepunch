package punch

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ReuseControl sets SO_REUSEADDR and SO_REUSEPORT on the socket.
func ReuseControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		if opErr != nil {
			return
		}
		opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}
	return opErr
}

// Punch performs TCP hole punching via SYN spray and proxies the connection to localTarget.
// localPort is the port to bind for both punch and listen.
// remoteAddr is Client B's IP:port.
// localTarget is the local service to proxy to (e.g. "127.0.0.1:8080").
// Returns a done channel that is closed when the spray finishes.
func Punch(ctx context.Context, localPort int, remoteAddr, localTarget string) (chan struct{}, error) {
	localBind := fmt.Sprintf(":%d", localPort)
	sprayDone := make(chan struct{})

	// Start listener first with reuse
	lc := net.ListenConfig{
		Control: ReuseControl,
	}
	ln, err := lc.Listen(ctx, "tcp4", localBind)
	if err != nil {
		close(sprayDone)
		return sprayDone, fmt.Errorf("listen on %s: %w", localBind, err)
	}
	log.Printf("[punch] listening on %s", localBind)

	// Extract remote IP
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}

	// SYN spray: send SYNs to all ephemeral ports on Client B's IP
	go func() {
		synSpray(ctx, localPort, remoteIP)
		close(sprayDone)
	}()

	// Accept inbound connection from Client B — wait up to 60s
	go func() {
		defer ln.Close()
		acceptCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()

		type result struct {
			conn net.Conn
			err  error
		}
		ch := make(chan result, 1)
		go func() {
			conn, err := ln.Accept()
			ch <- result{conn, err}
		}()

		select {
		case <-acceptCtx.Done():
			log.Printf("punch: timeout waiting for inbound connection")
		case r := <-ch:
			if r.err != nil {
				log.Printf("punch: accept error: %v", r.err)
				return
			}
			log.Printf("[punch] accepted connection from %s", r.conn.RemoteAddr())
			proxyConn(r.conn, localTarget)
		}
	}()

	return sprayDone, nil
}

// synSpray sends SYN packets from localPort to all ephemeral ports on remoteIP.
// Each SYN creates a NAT mapping: (localPort, remoteIP, destPort) -> allow inbound.
func synSpray(ctx context.Context, localPort int, remoteIP string) {
	const (
		startPort   = 1024
		endPort     = 65535
		concurrency = 4096 // high parallelism for speed
	)

	var sent atomic.Int64
	sem := make(chan struct{}, concurrency)
	start := time.Now()

	log.Printf("[spray] starting SYN spray to %s ports %d-%d from :%d", remoteIP, startPort, endPort, localPort)

	for port := startPort; port <= endPort; port++ {
		if ctx.Err() != nil {
			break
		}

		sem <- struct{}{}
		go func(p int) {
			defer func() { <-sem }()

			dialer := net.Dialer{
				LocalAddr: &net.TCPAddr{Port: localPort},
				// Short timeout — we only need the SYN to go out,
				// don't care about the response
				Timeout: 50 * time.Millisecond,
				Control: ReuseControl,
			}
			target := fmt.Sprintf("%s:%d", remoteIP, p)
			conn, err := dialer.DialContext(ctx, "tcp4", target)
			if err == nil {
				conn.Close()
			}
			sent.Add(1)
		}(port)
	}

	// Wait for remaining goroutines
	for i := 0; i < concurrency; i++ {
		sem <- struct{}{}
	}

	elapsed := time.Since(start).Round(time.Millisecond)
	log.Printf("[spray] done: %d SYNs sent in %v", sent.Load(), elapsed)
}

func proxyConn(clientConn net.Conn, localTarget string) {
	defer clientConn.Close()

	local, err := net.DialTimeout("tcp", localTarget, 5*time.Second)
	if err != nil {
		log.Printf("[proxy] failed to connect to %s: %v", localTarget, err)
		return
	}
	defer local.Close()

	log.Printf("[proxy] connected %s <-> %s", clientConn.RemoteAddr(), localTarget)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(local, clientConn)
	}()
	go func() {
		defer wg.Done()
		io.Copy(clientConn, local)
	}()
	wg.Wait()
}
