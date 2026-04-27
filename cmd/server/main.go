// Package server implements a minimal RADIUS authentication server.
// It listens on UDP port 1812 and responds to Access-Request packets
// with Access-Accept or Access-Reject based on username prefix logic.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/spf13/pflag"
)

// ResponseWriter abstracts the response sending mechanism for testing.
type ResponseWriter interface {
	SendTo(addr net.Addr, data []byte) error
}

func main() {
	pflag.CommandLine = pflag.NewFlagSet("fakeradius-server", pflag.ExitOnError)

	secret := pflag.String("secret", "", "Shared secret for RADIUS authentication (required)")
	addr := pflag.String("addr", ":1812", "Address to listen on")

	pflag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "Error: -secret flag is required")
		pflag.Usage()
		os.Exit(1)
	}

	fmt.Printf("Fake RADIUS Server starting on %s\n", *addr)
	fmt.Printf("Shared secret: %s\n", *secret)

	conn, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *addr, err)
	}
	defer conn.Close()

	fmt.Printf("Listening on %s\n", conn.LocalAddr())

	// Handle CTRL+C gracefully
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		close(done)
	}()

	for {
		select {
		case <-done:
			fmt.Println("\nShutting down...")
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			log.Printf("Read error: %v", err)
			continue
		}

		packet := buf[:n]
		go handlePacket(conn, clientAddr, packet, *secret)
	}
}

// UDPConn implements ResponseWriter for net.UDPConn.
type UDPConn struct {
	conn *net.UDPConn
}

func (u *UDPConn) SendTo(addr net.Addr, data []byte) error {
	_, err := u.conn.WriteToUDP(data, addr.(*net.UDPAddr))
	return err
}

func handlePacket(conn net.PacketConn, clientAddr net.Addr, packet []byte, secret string) {
	fmt.Printf("\n--- Received packet from %s (%d bytes) ---\n", clientAddr, len(packet))

	if len(packet) < 20 {
		fmt.Println("Packet too short to be valid RADIUS")
		return
	}

	code := packet[0]
	identifier := packet[1]
	length := uint16(packet[2])<<8 | uint16(packet[3])

	fmt.Printf("Code: %d, Identifier: %d, Length: %d\n", code, identifier, length)

	if code != AccessRequest {
		fmt.Printf("Ignoring non-Access-Request packet (code=%d)\n", code)
		return
	}

	// Validate Message-Authenticator if present
	if hasMessageAuthenticator(packet) {
		if !validateMessageAuthenticator(packet, secret) {
			fmt.Println("Invalid Message-Authenticator - rejecting")
			response := buildResponsePacket(packet, secret, AccessReject, identifier, "Message-Authenticator validation failed")
			writer := &UDPConn{conn.(*net.UDPConn)}
			writer.SendTo(clientAddr, response)
			return
		}
		fmt.Println("Message-Authenticator: valid")
	}

	// Parse the request
	username, err := extractUsername(packet)
	if err != nil {
		fmt.Printf("Error extracting username: %v\n", err)
	}

	// Use handler to determine response
	handler := &Handler{secret: secret}
	responseCode, replyMessage := handler.ServeRadius(username)

	// Build and send response
	response := buildResponsePacket(packet, secret, responseCode, identifier, replyMessage)

	writer := &UDPConn{conn.(*net.UDPConn)}
	if err := writer.SendTo(clientAddr, response); err != nil {
		log.Printf("Failed to send response: %v", err)
		return
	}

	fmt.Printf("Sent %s response to %s\n", codeToString(responseCode), clientAddr)
}

func codeToString(code byte) string {
	switch code {
	case AccessRequest:
		return "Access-Request"
	case AccessAccept:
		return "Access-Accept"
	case AccessReject:
		return "Access-Reject"
	default:
		return fmt.Sprintf("Unknown(%d)", code)
	}
}
