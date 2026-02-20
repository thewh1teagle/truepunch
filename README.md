# TruePunch

P2P TCP tunnel via DNS redirect and NAT hole punching. Zero application traffic through the relay.

## How it works

1. Client A connects to relay, registers a tunnel name
2. Client B curls `http://your-relay:8080/t/{tunnel-name}`
3. Relay creates a Cloudflare DNS record pointing to Client A, signals Client A to punch, returns 302
4. Client A sends outbound TCP SYN to Client B (creates NAT mapping)
5. Client B follows redirect, connects directly to Client A through the punched hole
6. Client A proxies the connection to your local service

## Setup

### Prerequisites

- A domain on Cloudflare (free plan works)
- A VPS for the relay (cheapest tier, it does almost nothing)
- Cloudflare API token with DNS edit permission for your zone
- Go 1.21+

### Build

```
go build -o relay ./cmd/relay/
go build -o client ./cmd/client/
```

### DNS

Point your domain to the relay VPS:

```
A   tunnel.example.com    → <relay-vps-ip>
```

Subdomains are managed automatically via Cloudflare API.

### Run relay (on VPS)

```
export CF_API_TOKEN=your-cloudflare-api-token
export CF_ZONE_ID=your-zone-id

./relay --domain tunnel.example.com --port 8080
```

Or with flags:

```
./relay --domain tunnel.example.com --cf-token xxx --zone-id xxx --port 8080
```

### Run client (on your machine behind NAT)

```
# Expose local port 3000 through tunnel named "myapp"
./client --relay ws://tunnel.example.com:8080 --tunnel myapp --port 3000
```

### Try it

Terminal 1 — start the demo server:

```
python3 scripts/demo-server.py
```

Terminal 2 — expose it through the tunnel:

```
./client --relay ws://tunnel.example.com:8080 --tunnel myapp --port 3000
```

From anywhere:

```
curl -L http://tunnel.example.com:8080/t/myapp
```

## Flags

### Relay

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--port` | - | 8080 | Listen port |
| `--domain` | `TUNNEL_DOMAIN` | required | Base domain |
| `--cf-token` | `CF_API_TOKEN` | required | Cloudflare API token |
| `--zone-id` | `CF_ZONE_ID` | required | Cloudflare zone ID |

### Client

| Flag | Default | Description |
|------|---------|-------------|
| `--relay` | `ws://localhost:8080` | Relay WebSocket URL |
| `--tunnel` | required | Tunnel name |
| `--port` | 8080 | Local port to expose |
| `--punch-port` | 41234 | Port used for TCP hole punch |

## Limitations

- Fails on symmetric NAT (~20% of networks)
- Linux/macOS only (SO_REUSEPORT required)
- Single connection per punch (new curl = new punch cycle)
