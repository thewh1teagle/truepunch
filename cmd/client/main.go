package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/stun"
	"github.com/spf13/cobra"
	"github.com/truepunch/truepunch/internal/punch"
	sig "github.com/truepunch/truepunch/internal/signal"
)

func main() {
	var (
		relayURL   string
		tunnelName string
		localPort  int
		punchPort  int
	)

	root := &cobra.Command{
		Use:   "client",
		Short: "TruePunch client — exposes a local port via NAT punch",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Generate random tunnel name if not provided
			if tunnelName == "" {
				b := make([]byte, 4)
				rand.Read(b)
				tunnelName = hex.EncodeToString(b)
			}

			// Discover public IP via STUN
			publicIP, err := discoverPublicIP()
			if err != nil {
				return fmt.Errorf("stun discovery: %w", err)
			}
			log.Printf("public IP: %s", publicIP)

			// Extract relay host for ALG connections
			relayHTTP := strings.Replace(relayURL, "ws://", "http://", 1)
			relayHTTP = strings.Replace(relayHTTP, "wss://", "https://", 1)
			relayHost := strings.TrimPrefix(relayHTTP, "http://")
			relayHost = strings.TrimPrefix(relayHost, "https://")
			relayIP := relayHost
			if h, _, err := net.SplitHostPort(relayHost); err == nil {
				relayIP = h
			}

			// Try NAT ALG exploitation to open the port
			// SIP ALG (port 5060) — most common on home routers
			sipAddr := net.JoinHostPort(relayIP, "5060")
			sipConn, err := punch.ExploitSIPALG(sipAddr, publicIP, punchPort)
			if err != nil {
				log.Printf("SIP ALG failed: %v", err)
			} else {
				defer sipConn.Close()
				log.Printf("SIP ALG connection established — port %d should be open", punchPort)
			}

			// FTP ALG (port 21) — fallback
			ftpAddr := net.JoinHostPort(relayIP, "21")
			ftpConn, err := punch.ExploitFTPALG(ftpAddr, publicIP, punchPort)
			if err != nil {
				log.Printf("FTP ALG failed: %v", err)
			} else {
				defer ftpConn.Close()
				log.Printf("FTP ALG connection established — port %d should be open", punchPort)
			}

			// Also try port discovery for external mapping
			extPort, keepAlive, err := discoverExternalPort(relayHTTP, punchPort)
			if err != nil {
				log.Printf("port discovery failed: %v (using internal port %d)", err, punchPort)
				extPort = punchPort
			} else {
				log.Printf("NAT mapping: local :%d -> external :%d", punchPort, extPort)
				defer keepAlive.Close()
				go func() {
					ticker := time.NewTicker(20 * time.Second)
					defer ticker.Stop()
					for {
						select {
						case <-ctx.Done():
							return
						case <-ticker.C:
							keepAlive.SetDeadline(time.Now().Add(5 * time.Second))
							_, err := keepAlive.Write([]byte("k"))
							if err != nil {
								log.Printf("keepalive failed: %v", err)
								return
							}
						}
					}
				}()
			}

			// Connect to relay
			wsURL := fmt.Sprintf("%s/ws", relayURL)
			log.Printf("connecting to relay: %s", wsURL)
			conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
			if err != nil {
				return fmt.Errorf("ws connect: %w", err)
			}
			defer conn.Close()

			// Register with external port
			err = conn.WriteJSON(sig.Message{
				Type:       sig.MsgRegister,
				TunnelName: tunnelName,
				PublicIP:   publicIP,
				PunchPort:  extPort,
			})
			if err != nil {
				return fmt.Errorf("register: %w", err)
			}
			log.Printf("registered tunnel: %s", tunnelName)

			// Print access URL
			log.Printf("access from anywhere: curl -L http://%s/t/%s", relayHost, tunnelName)

			// Close websocket when context is cancelled
			go func() {
				<-ctx.Done()
				conn.Close()
			}()

			// Listen for punch signals
			localTarget := fmt.Sprintf("127.0.0.1:%d", localPort)
			for {
				var msg sig.Message
				if err := conn.ReadJSON(&msg); err != nil {
					if ctx.Err() != nil {
						log.Println("shutting down")
						return nil
					}
					return fmt.Errorf("ws read: %w", err)
				}

				if msg.Type != sig.MsgPunch {
					continue
				}

				remoteAddr := fmt.Sprintf("%s:%d", msg.ClientIP, msg.ClientPort)
				log.Printf("punch signal: client=%s subdomain=%s", remoteAddr, msg.Subdomain)

				// Perform punch, get spray done channel
				sprayDone, err := punch.Punch(ctx, punchPort, remoteAddr, localTarget)
				if err != nil {
					log.Printf("punch setup failed: %v", err)
					continue
				}

				// Wait for spray to finish, then tell relay we're ready
				go func() {
					<-sprayDone
					log.Println("spray done, signaling relay")
					conn.WriteJSON(sig.Message{Type: sig.MsgReady})
				}()
			}
		},
	}

	root.Flags().StringVarP(&relayURL, "relay", "r", "ws://localhost:8080", "relay WebSocket URL")
	root.Flags().StringVarP(&tunnelName, "tunnel", "t", "", "tunnel name")
	root.Flags().IntVarP(&localPort, "port", "p", 8080, "local port to expose")
	root.Flags().IntVar(&punchPort, "punch-port", 41234, "port used for TCP punch")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

// discoverExternalPort connects to the relay's /discover endpoint FROM the punch port
// to learn the NAT's external mapping. Returns the external port and the keepalive connection.
func discoverExternalPort(relayHTTP string, localPort int) (int, net.Conn, error) {
	// Parse relay host:port
	u := strings.TrimPrefix(relayHTTP, "http://")
	u = strings.TrimPrefix(u, "https://")

	// Dial TCP from the punch port with SO_REUSEPORT
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{Port: localPort},
		Timeout:   5 * time.Second,
		Control:   punch.ReuseControl,
	}
	conn, err := dialer.Dial("tcp4", u)
	if err != nil {
		return 0, nil, fmt.Errorf("dial relay: %w", err)
	}

	// Send HTTP request manually on this connection
	req := fmt.Sprintf("GET /discover HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", u)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(req))
	if err != nil {
		conn.Close()
		return 0, nil, fmt.Errorf("write request: %w", err)
	}

	// Read response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return 0, nil, fmt.Errorf("read response: %w", err)
	}

	// Parse JSON body from HTTP response
	resp := string(buf[:n])
	bodyIdx := strings.Index(resp, "\r\n\r\n")
	if bodyIdx == -1 {
		conn.Close()
		return 0, nil, fmt.Errorf("invalid http response")
	}
	body := resp[bodyIdx+4:]

	var result struct {
		IP   string `json:"ip"`
		Port int    `json:"port"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		conn.Close()
		return 0, nil, fmt.Errorf("parse response: %w (body: %s)", err, body)
	}

	conn.SetDeadline(time.Time{}) // clear deadline
	return result.Port, conn, nil
}

func discoverPublicIP() (string, error) {
	// Force IPv4 by resolving to udp4
	conn, err := stun.Dial("udp4", "stun.l.google.com:19302")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	var publicIP string
	errCh := make(chan error, 1)

	err = conn.Start(message, func(res stun.Event) {
		if res.Error != nil {
			errCh <- res.Error
			return
		}
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err != nil {
			errCh <- err
			return
		}
		publicIP = xorAddr.IP.String()
		errCh <- nil
	})
	if err != nil {
		return "", err
	}

	select {
	case err := <-errCh:
		if err != nil {
			return "", err
		}
		return publicIP, nil
	case <-time.After(5 * time.Second):
		return "", fmt.Errorf("stun timeout")
	}
}

// suppress unused import
var _ = http.Get
var _ = io.EOF
