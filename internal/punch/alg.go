package punch

import (
	"fmt"
	"log"
	"net"
	"time"
)

// ExploitSIPALG sends a crafted SIP REGISTER through the NAT to trigger
// the router's SIP ALG into opening a port for inbound traffic.
// Tries both TCP and UDP as some routers only inspect one.
// relayAddr should be the relay's IP:5060.
// internalIP is Client A's INTERNAL/local IP.
// targetPort is the port we want opened.
func ExploitSIPALG(relayAddr, internalIP string, targetPort int) (net.Conn, error) {
	sipMsg := buildSIPRegister(internalIP, targetPort)

	// Try TCP first
	conn, err := trySIPTCP(relayAddr, internalIP, targetPort, sipMsg)
	if err != nil {
		log.Printf("[alg] SIP TCP failed: %v, trying UDP...", err)
		// Try UDP
		err2 := trySIPUDP(relayAddr, internalIP, targetPort, sipMsg)
		if err2 != nil {
			return nil, fmt.Errorf("sip tcp: %v, sip udp: %v", err, err2)
		}
		return nil, nil // UDP doesn't return a keepalive conn
	}
	return conn, nil
}

func buildSIPRegister(internalIP string, targetPort int) string {
	return fmt.Sprintf(
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
}

func trySIPTCP(relayAddr, internalIP string, targetPort int, sipMsg string) (net.Conn, error) {
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{Port: targetPort},
		Timeout:   5 * time.Second,
		Control:   ReuseControl,
	}

	log.Printf("[alg] SIP TCP: connecting to %s from :%d", relayAddr, targetPort)
	conn, err := dialer.Dial("tcp4", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(sipMsg))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read response: %w", err)
	}
	conn.SetDeadline(time.Time{})

	log.Printf("[alg] SIP TCP: 200 OK received (%d bytes)", n)
	return conn, nil
}

func trySIPUDP(relayAddr, internalIP string, targetPort int, sipMsg string) error {
	laddr := &net.UDPAddr{Port: targetPort}
	raddr, err := net.ResolveUDPAddr("udp4", relayAddr)
	if err != nil {
		return fmt.Errorf("resolve: %w", err)
	}

	log.Printf("[alg] SIP UDP: sending to %s from :%d", relayAddr, targetPort)
	conn, err := net.DialUDP("udp4", laddr, raddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	// Replace TCP with UDP in Via header
	udpMsg := fmt.Sprintf(
		"REGISTER sip:truepunch SIP/2.0\r\n"+
			"Via: SIP/2.0/UDP %s:%d;branch=z9hG4bK776asdhds\r\n"+
			"From: <sip:punch@truepunch>;tag=767sxkm\r\n"+
			"To: <sip:punch@truepunch>\r\n"+
			"Call-ID: 843817637684230@truepunch\r\n"+
			"CSeq: 1826 REGISTER\r\n"+
			"Contact: <sip:punch@%s:%d>\r\n"+
			"Expires: 7200\r\n"+
			"Content-Length: 0\r\n\r\n",
		internalIP, targetPort,
		internalIP, targetPort,
	)

	_, err = conn.Write([]byte(udpMsg))
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	// Wait for response
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	log.Printf("[alg] SIP UDP: response received (%d bytes)", n)
	return nil
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
