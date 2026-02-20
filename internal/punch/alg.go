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
// publicIP is Client A's public IP.
// targetPort is the port we want opened.
// Returns the keepalive connection (must stay open to maintain ALG mapping).
func ExploitSIPALG(relayAddr, publicIP string, targetPort int) (net.Conn, error) {
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

	// Craft SIP REGISTER — the NAT's ALG parses the Contact header
	// and opens targetPort for inbound connections
	sipRegister := fmt.Sprintf(
		"REGISTER sip:%s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP %s:%d;branch=z9hG4bK776asdhds\r\n"+
			"From: <sip:punch@%s>;tag=767sxkm\r\n"+
			"To: <sip:punch@%s>\r\n"+
			"Call-ID: 843817637684230@%s\r\n"+
			"CSeq: 1826 REGISTER\r\n"+
			"Contact: <sip:punch@%s:%d;transport=tcp>\r\n"+
			"Expires: 7200\r\n"+
			"Content-Length: 0\r\n\r\n",
		publicIP,
		publicIP, targetPort,
		publicIP,
		publicIP,
		publicIP,
		publicIP, targetPort,
	)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(sipRegister))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write sip register: %w", err)
	}
	conn.SetDeadline(time.Time{})

	log.Printf("[alg] SIP REGISTER sent — NAT ALG should open port %d", targetPort)
	return conn, nil
}

// ExploitFTPALG sends a crafted FTP PORT command to trigger the router's
// FTP ALG into opening a port.
// relayAddr should be relay's IP:21.
func ExploitFTPALG(relayAddr, publicIP string, targetPort int) (net.Conn, error) {
	dialer := net.Dialer{
		LocalAddr: &net.TCPAddr{Port: targetPort},
		Timeout:   5 * time.Second,
		Control:   ReuseControl,
	}

	log.Printf("[alg] connecting to relay FTP endpoint: %s from :%d", relayAddr, targetPort)
	conn, err := dialer.Dial("tcp4", relayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial relay ftp: %w", err)
	}

	// FTP PORT command: PORT h1,h2,h3,h4,p1,p2
	// where IP = h1.h2.h3.h4 and port = p1*256 + p2
	ip := net.ParseIP(publicIP).To4()
	if ip == nil {
		conn.Close()
		return nil, fmt.Errorf("invalid IPv4: %s", publicIP)
	}
	p1 := targetPort / 256
	p2 := targetPort % 256

	ftpPort := fmt.Sprintf("PORT %d,%d,%d,%d,%d,%d\r\n",
		ip[0], ip[1], ip[2], ip[3], p1, p2)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write([]byte(ftpPort))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("write ftp port: %w", err)
	}
	conn.SetDeadline(time.Time{})

	log.Printf("[alg] FTP PORT sent — NAT ALG should open port %d", targetPort)
	return conn, nil
}
