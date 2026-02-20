package dns

import (
	"context"
	"fmt"
	"sync"
	"time"

	cloudflare "github.com/cloudflare/cloudflare-go"
)

// Manager handles Cloudflare DNS record lifecycle.
type Manager struct {
	api    *cloudflare.API
	zoneID string
	domain string

	mu      sync.Mutex
	records map[string]string // subdomain -> record ID
}

func New(apiToken, zoneID, domain string) (*Manager, error) {
	api, err := cloudflare.NewWithAPIToken(apiToken)
	if err != nil {
		return nil, fmt.Errorf("cloudflare api: %w", err)
	}
	return &Manager{
		api:     api,
		zoneID:  zoneID,
		domain:  domain,
		records: make(map[string]string),
	}, nil
}

// CreateRecord creates an A record: <subdomain>.<domain> -> ip with TTL=1.
func (m *Manager) CreateRecord(ctx context.Context, subdomain, ip string) error {
	fqdn := subdomain + "." + m.domain
	proxied := false
	ttl := 1 // auto/minimum

	rc := cloudflare.ZoneIdentifier(m.zoneID)
	rec, err := m.api.CreateDNSRecord(ctx, rc, cloudflare.CreateDNSRecordParams{
		Type:    "A",
		Name:    fqdn,
		Content: ip,
		TTL:     ttl,
		Proxied: &proxied,
	})
	if err != nil {
		return fmt.Errorf("create dns record: %w", err)
	}

	m.mu.Lock()
	m.records[subdomain] = rec.ID
	m.mu.Unlock()
	return nil
}

// DeleteRecord removes a previously created record.
func (m *Manager) DeleteRecord(ctx context.Context, subdomain string) error {
	m.mu.Lock()
	id, ok := m.records[subdomain]
	if ok {
		delete(m.records, subdomain)
	}
	m.mu.Unlock()

	if !ok {
		return nil
	}

	rc := cloudflare.ZoneIdentifier(m.zoneID)
	return m.api.DeleteDNSRecord(ctx, rc, id)
}

// CleanupAll removes all tracked records. Call on shutdown.
func (m *Manager) CleanupAll(ctx context.Context) {
	m.mu.Lock()
	ids := make(map[string]string)
	for k, v := range m.records {
		ids[k] = v
	}
	m.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rc := cloudflare.ZoneIdentifier(m.zoneID)
	for sub, id := range ids {
		_ = m.api.DeleteDNSRecord(ctx, rc, id)
		m.mu.Lock()
		delete(m.records, sub)
		m.mu.Unlock()
	}
}

// FQDN returns the full domain for a subdomain.
func (m *Manager) FQDN(subdomain string) string {
	return subdomain + "." + m.domain
}
