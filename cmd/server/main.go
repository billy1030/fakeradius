// Package server implements a minimal RADIUS authentication server.
// It listens on UDP port 1812 and responds to Access-Request packets
// with Access-Accept or Access-Reject based on username prefix logic.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
)

// Logger handles both console and file output with timestamps.
type Logger struct {
	file   *os.File
	stdout *os.File
}

// NewLogger creates a logger that writes to both console and file.
func NewLogger(logPath string) (*Logger, error) {
	logger := &Logger{
		stdout: os.Stdout,
	}

	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		logger.file = f
	}

	return logger, nil
}

// Close closes the log file.
func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

// Print writes to both console and log file with timestamp.
func (l *Logger) Print(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	line := fmt.Sprintf("[%s] %s\n", timestamp, fmt.Sprintf(format, args...))

	// Console
	fmt.Print(line)

	// File
	if l.file != nil {
		l.file.WriteString(line)
	}
}

// ResponseWriter abstracts the response sending mechanism for testing.
type ResponseWriter interface {
	SendTo(addr net.Addr, data []byte) error
}

func main() {
	pflag.CommandLine = pflag.NewFlagSet("fakeradius-server", pflag.ExitOnError)

	secret := pflag.String("secret", "", "Shared secret for RADIUS authentication (required)")
	addr := pflag.String("addr", ":1812", "Address to listen on")
	logFile := pflag.String("log", "", "Log file path (default: console only)")

	pflag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "Error: -secret flag is required")
		pflag.Usage()
		os.Exit(1)
	}

	logger, err := NewLogger(*logFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close()

	logger.Print("Fake RADIUS Server starting on %s", *addr)
	logger.Print("Shared secret: %s", *secret)
	if *logFile != "" {
		logger.Print("Logging to file: %s", *logFile)
	}

	conn, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *addr, err)
	}
	defer conn.Close()

	logger.Print("Listening on %s", conn.LocalAddr())

	// Handle CTRL+C gracefully using signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 4096)
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check for shutdown signal
				select {
				case <-sigChan:
					logger.Print("Shutting down...")
					return
				default:
				}
				continue
			}
			log.Printf("Read error: %v", err)
			continue
		}

		packet := buf[:n]
		go handlePacket(conn, clientAddr, packet, *secret, logger)
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

func handlePacket(conn net.PacketConn, clientAddr net.Addr, packet []byte, secret string, logger *Logger) {
	logger.Print("=== Received packet from %s (%d bytes) ===", clientAddr, len(packet))

	if len(packet) < 20 {
		logger.Print("ERROR: Packet too short to be valid RADIUS")
		return
	}

	code := packet[0]
	identifier := packet[1]
	length := uint16(packet[2])<<8 | uint16(packet[3])

	logger.Print("Request: Code=%d, Identifier=%d, Length=%d", code, identifier, length)

	if code != AccessRequest {
		logger.Print("Ignoring non-Access-Request packet (code=%d)", code)
		return
	}

	// Validate Message-Authenticator if present
	if hasMessageAuthenticator(packet) {
		if !validateMessageAuthenticator(packet, secret) {
			logger.Print("ERROR: Invalid Message-Authenticator - rejecting")
			response := buildResponsePacket(packet, secret, AccessReject, identifier, "Message-Authenticator validation failed")
			writer := &UDPConn{conn.(*net.UDPConn)}
			writer.SendTo(clientAddr, response)
			return
		}
		logger.Print("Message-Authenticator: valid")
	}

	// Parse the request
	username, err := extractUsername(packet)
	if err != nil {
		logger.Print("Error extracting username: %v", err)
	}

	logger.Print("Username: %s", username)

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

	logger.Print("=== Sent %s to %s ===", codeToString(responseCode), clientAddr)
	logger.Print("Reply-Message: %s", replyMessage)
	logger.Print("")
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
