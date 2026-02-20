package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strings"
	"os/signal"
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

			// Connect to relay
			wsURL := fmt.Sprintf("%s/ws", relayURL)
			log.Printf("connecting to relay: %s", wsURL)
			conn, _, err := websocket.DefaultDialer.DialContext(ctx, wsURL, nil)
			if err != nil {
				return fmt.Errorf("ws connect: %w", err)
			}
			defer conn.Close()

			// Register
			err = conn.WriteJSON(sig.Message{
				Type:       sig.MsgRegister,
				TunnelName: tunnelName,
				PublicIP:   publicIP,
				PunchPort:  punchPort,
			})
			if err != nil {
				return fmt.Errorf("register: %w", err)
			}
			log.Printf("registered tunnel: %s", tunnelName)

			// Extract relay host for the access URL
			relayHost := strings.TrimPrefix(relayURL, "ws://")
			relayHost = strings.TrimPrefix(relayHost, "wss://")
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

				// Perform punch in background
				go func(remote, target string) {
					if err := punch.Punch(ctx, punchPort, remote, target); err != nil {
						log.Printf("punch failed: %v", err)
					}
				}(remoteAddr, localTarget)

				// Tell relay we're ready
				conn.WriteJSON(sig.Message{Type: sig.MsgReady})
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
