package punch

import (
	"fmt"
	"log"
	"net"
	"time"
)

// ExploitSIPALG sends a crafted SIP REGISTER through the NAT to trigger
// the router's SIP ALG into opening a port for inbound traffic.
// relayAddr should be the relay's IP:5060 (SIP port triggers ALG inspection).
// internalIP is Client A's INTERNAL/local IP (the NAT will rewrite it to public).
// targetPort is the port we want opened.
// Returns the keepalive connection (must stay open to maintain ALG mapping).
func ExploitSIPALG(relayAddr, internalIP string, targetPort int) (net.Conn, error) {
	// Connect to relay on port 5060 — NAT inspects traffic on this port
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{Port: targetPort},
		Timeout:   5 * time.Second,
		Control:   ReuseControl,
	}

	log.Printf("[alg] connecting to relay SIP endpoint: %s from :%d", relayAddr, targetPort)
	conn, err := dialer.Dial("tcp4", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial relay sip: %w", err)
	}

	// Craft SIP REGISTER — the NAT's ALG parses the Contact header.
	// CRITICAL: Contact must contain the INTERNAL IP, not public.
	// The NAT validates Contact IP == source internal IP, then rewrites
	// the internal IP to the public IP in the packet.
	// The NAT only opens the port AFTER receiving a valid SIP 200 OK response.
	sipRegister := fmt.Sprintf(
		"REGISTER sip:truepunch SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP %s:%d;branch=z9hG4bK776asdhds\r\n"+
			"From: <sip:punch@truepunch>;tag=767sxkm\r\n"+
			"To: <sip:punch@truepunch>\r\n"+
			"Call-ID: 843817637684230@truepunch\r\n"+
			"CSeq: 1826 REGISTER\r\n"+
			"Contact: <sip:punch@%s:%d;transport=tcp>\r\n"+
			"Expires: 7200\r\n"+
			"Content-Length: 0\r\n\r\n",
		internalIP, targetPort,
		internalIP, targetPort,
	)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(sipRegister))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write sip register: %w", err)
	}

	// Read the SIP 200 OK response from relay
	// The NAT sees this response and opens the port
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read sip response: %w", err)
	}
	conn.SetDeadline(time.Time{})

	log.Printf("[alg] SIP response received (%d bytes) — NAT ALG should open port %d", n, targetPort)
	return conn, nil
}

// GetInternalIP returns the machine's local/internal IP address.
func GetInternalIP() (string, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}
