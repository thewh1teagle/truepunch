package punch

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// reuseControl sets SO_REUSEADDR and SO_REUSEPORT on the socket.
func reuseControl(network, address string, c syscall.RawConn) error {
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

// Punch performs TCP hole punching and proxies the connection to localAddr.
// localPort is the port to bind for both punch and listen.
// remoteAddr is Client B's IP:port to punch toward.
// localTarget is the local service to proxy to (e.g. "127.0.0.1:8080").
func Punch(ctx context.Context, localPort int, remoteAddr, localTarget string) error {
	localBind := fmt.Sprintf(":%d", localPort)

	// Start listener first with reuse
	lc := net.ListenConfig{
		Control: reuseControl,
	}
	ln, err := lc.Listen(ctx, "tcp", localBind)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", localBind, err)
	}
	defer ln.Close()
	log.Printf("[punch] listening on %s", localBind)

	// Send outbound SYNs (punch) to create NAT mapping
	// Punch to multiple ports to increase chance of NAT mapping match
	remoteIP := remoteAddr
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		remoteIP = host
	}
	punchTargets := []string{
		net.JoinHostPort(remoteIP, "80"),
		net.JoinHostPort(remoteIP, "443"),
		remoteAddr,
	}
	for _, target := range punchTargets {
		target := target
		go func() {
			dialer := net.Dialer{
				LocalAddr: &net.TCPAddr{Port: localPort},
				Timeout:   3 * time.Second,
				Control:   reuseControl,
			}
			conn, err := dialer.DialContext(ctx, "tcp", target)
			if err != nil {
				log.Printf("[punch] SYN to %s (expected): %v", target, err)
				return
			}
			log.Printf("[punch] SYN to %s succeeded", target)
			go proxyConn(conn, localTarget)
		}()
	}

	// Accept inbound connection from Client B
	acceptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
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
		return fmt.Errorf("timeout waiting for inbound connection")
	case r := <-ch:
		if r.err != nil {
			return fmt.Errorf("accept: %w", r.err)
		}
		log.Printf("[punch] accepted connection from %s", r.conn.RemoteAddr())
		proxyConn(r.conn, localTarget)
		return nil
	}
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
