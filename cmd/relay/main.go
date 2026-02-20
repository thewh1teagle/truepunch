package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/truepunch/truepunch/internal/dns"
	sig "github.com/truepunch/truepunch/internal/signal"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type tunnel struct {
	ws        *websocket.Conn
	publicIP  string
	punchPort int
	mu        sync.Mutex
}

type relay struct {
	tunnels map[string]*tunnel
	mu      sync.RWMutex
	dns     *dns.Manager
	domain  string
}

func main() {
	var (
		port     int
		cfToken  string
		zoneID   string
		domain   string
	)

	_ = godotenv.Load()

	root := &cobra.Command{
		Use:   "relay",
		Short: "TruePunch relay server",
		RunE: func(cmd *cobra.Command, args []string) error {
			dnsMgr, err := dns.New(cfToken, zoneID, domain)
			if err != nil {
				return err
			}

			r := &relay{
				tunnels: make(map[string]*tunnel),
				dns:     dnsMgr,
				domain:  domain,
			}

			mux := http.NewServeMux()
			mux.HandleFunc("/ws", r.handleWS)
			mux.HandleFunc("/t/", r.handleTunnel)
			mux.HandleFunc("/health", func(w http.ResponseWriter, req *http.Request) {
				log.Printf("health check from %s", req.RemoteAddr)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("ok\n"))
			})
			// Returns caller's IP:port as seen by the relay (for NAT mapping discovery)
			mux.HandleFunc("/discover", func(w http.ResponseWriter, req *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				host, portStr, _ := net.SplitHostPort(req.RemoteAddr)
				fmt.Fprintf(w, `{"ip":"%s","port":%s}`, host, portStr)
			})

			addr := fmt.Sprintf(":%d", port)
			srv := &http.Server{Addr: addr, Handler: mux}

			// Graceful shutdown
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			go func() {
				<-ctx.Done()
				log.Println("shutting down...")
				dnsMgr.CleanupAll(context.Background())
				srv.Close()
			}()

			// Get public IP for convenience
			req, _ := http.NewRequest("GET", "https://api.ipify.org", nil)
			if resp, err := http.DefaultClient.Do(req); err == nil {
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				ip := strings.TrimSpace(string(b))
				log.Printf("relay listening on %s | public: http://%s:%d/health", addr, ip, port)
				log.Printf("connect client: ./client --relay ws://%s:%d --tunnel <name> --port <local-port>", ip, port)
			} else {
				log.Printf("relay listening on %s", addr)
			}
			return srv.ListenAndServe()
		},
	}

	root.Flags().IntVarP(&port, "port", "p", 8080, "listen port")
	root.Flags().StringVar(&cfToken, "cf-token", os.Getenv("CF_API_TOKEN"), "Cloudflare API token")
	root.Flags().StringVar(&zoneID, "zone-id", os.Getenv("CF_ZONE_ID"), "Cloudflare zone ID")
	root.Flags().StringVar(&domain, "domain", os.Getenv("TUNNEL_DOMAIN"), "base domain (e.g. tunnel.example.com)")

	// Only require --domain if not set via .env
	if os.Getenv("TUNNEL_DOMAIN") == "" {
		root.MarkFlagRequired("domain")
	}

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func (r *relay) handleWS(w http.ResponseWriter, req *http.Request) {
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		log.Printf("ws upgrade: %v", err)
		return
	}
	defer conn.Close()

	// Wait for register message
	var msg sig.Message
	if err := conn.ReadJSON(&msg); err != nil {
		log.Printf("ws read: %v", err)
		return
	}
	if msg.Type != sig.MsgRegister || msg.TunnelName == "" {
		conn.WriteJSON(sig.Message{Type: "error"})
		return
	}

	t := &tunnel{ws: conn, publicIP: msg.PublicIP, punchPort: msg.PunchPort}
	r.mu.Lock()
	r.tunnels[msg.TunnelName] = t
	r.mu.Unlock()

	log.Printf("tunnel registered: %s (ip: %s)", msg.TunnelName, msg.PublicIP)

	defer func() {
		r.mu.Lock()
		delete(r.tunnels, msg.TunnelName)
		r.mu.Unlock()
		log.Printf("tunnel deregistered: %s", msg.TunnelName)
	}()

	// Keep connection alive — read messages (e.g. ready signals)
	for {
		var m sig.Message
		if err := conn.ReadJSON(&m); err != nil {
			return
		}
		if m.Type == sig.MsgReady {
			log.Printf("tunnel %s: client ready for punch", msg.TunnelName)
		}
	}
}

func (r *relay) handleTunnel(w http.ResponseWriter, req *http.Request) {
	// Extract tunnel name: /t/{name}
	path := strings.TrimPrefix(req.URL.Path, "/t/")
	tunnelName := strings.Split(path, "/")[0]
	if tunnelName == "" {
		http.Error(w, "missing tunnel name", http.StatusBadRequest)
		return
	}

	r.mu.RLock()
	t, ok := r.tunnels[tunnelName]
	r.mu.RUnlock()
	if !ok {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}

	// Get Client B's IP:port
	clientIP, clientPort, err := extractAddr(req)
	if err != nil {
		http.Error(w, "cannot determine client address", http.StatusBadRequest)
		return
	}

	// Generate unique subdomain
	subdomain, err := randomSubdomain()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Create DNS record pointing to Client A
	fullSub := subdomain + "." + tunnelName
	if err := r.dns.CreateRecord(req.Context(), fullSub, t.publicIP); err != nil {
		log.Printf("dns create failed: %v", err)
		http.Error(w, "dns error", http.StatusInternalServerError)
		return
	}

	// Clean up DNS record after 60 seconds
	go func() {
		time.Sleep(60 * time.Second)
		r.dns.DeleteRecord(context.Background(), fullSub)
		log.Printf("cleaned up DNS record: %s", fullSub)
	}()

	// Signal Client A to punch
	t.mu.Lock()
	err = t.ws.WriteJSON(sig.Message{
		Type:       sig.MsgPunch,
		ClientIP:   clientIP,
		ClientPort: clientPort,
		Subdomain:  fullSub,
	})
	t.mu.Unlock()
	if err != nil {
		log.Printf("signal punch failed: %v", err)
		http.Error(w, "signal error", http.StatusInternalServerError)
		return
	}

	// Wait for DNS to propagate before redirecting
	fqdn := fullSub + "." + r.domain
	log.Printf("waiting for DNS propagation: %s", fqdn)
	for i := 0; i < 10; i++ {
		ips, err := net.LookupHost(fqdn)
		if err == nil && len(ips) > 0 {
			log.Printf("DNS resolved: %s -> %v", fqdn, ips)
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// 302 redirect to the unique subdomain on the punch port
	redirectURL := fmt.Sprintf("http://%s.%s:%d/", fullSub, r.domain, t.punchPort)
	log.Printf("redirecting Client B to %s", redirectURL)
	http.Redirect(w, req, redirectURL, http.StatusFound)
}

func extractAddr(req *http.Request) (string, int, error) {
	// Check X-Forwarded-For first
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ip := strings.TrimSpace(strings.Split(xff, ",")[0])
		return ip, 0, nil
	}
	host, portStr, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return "", 0, err
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return host, port, nil
}

func randomSubdomain() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

