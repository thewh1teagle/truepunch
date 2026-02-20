package signal

// Message types for WebSocket signaling between relay and client.
type MsgType string

const (
	MsgRegister MsgType = "register"
	MsgPunch    MsgType = "punch"
	MsgReady    MsgType = "ready"
)

// Message is the WebSocket envelope.
type Message struct {
	Type       MsgType `json:"type"`
	TunnelName string  `json:"tunnel_name,omitempty"`
	PublicIP   string  `json:"public_ip,omitempty"`
	ClientIP   string  `json:"client_ip,omitempty"`
	ClientPort int     `json:"client_port,omitempty"`
	Subdomain  string  `json:"subdomain,omitempty"`
}
