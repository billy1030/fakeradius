// Package server implements a minimal RADIUS authentication server.
// It listens on UDP port 1812 and responds to Access-Request packets
// with Access-Accept or Access-Reject based on username prefix logic.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
)

var verbose bool

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

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

func (l *Logger) Print(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	line := fmt.Sprintf("[%s] %s\n", timestamp, fmt.Sprintf(format, args...))

	fmt.Print(line)

	if l.file != nil {
		l.file.WriteString(line)
	}
}

type ResponseWriter interface {
	SendTo(addr net.Addr, data []byte) error
}

func main() {
	pflag.CommandLine = pflag.NewFlagSet("fakeradius-server", pflag.ExitOnError)

	secret := pflag.StringP("secret", "s", "", "Shared secret for RADIUS authentication (required)")
	addr := pflag.StringP("addr", "a", ":1812", "Address to listen on")
	logFile := pflag.StringP("log", "l", "", "Log file path (default: console only)")
	pflag.BoolVarP(&verbose, "verbose", "v", false, "Enable detailed protocol debugging")

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

	logger.Print("═══════════════════════════════════════════════════════")
	logger.Print("  Fake RADIUS Server v0.1a")
	logger.Print("═══════════════════════════════════════════════════════")
	logger.Print("")
	logger.Print("  Listening:      %s", *addr)
	logger.Print("  Shared secret:  %s", *secret)
	if *logFile != "" {
		logger.Print("  Log file:       %s", *logFile)
	}
	logger.Print("")
	logger.Print("  Auth Modes:     PAP, CHAP, MS-CHAP v1/v2")
	logger.Print("  Auth Logic:     Allow all except 'no_' prefix")
	logger.Print("  Reject Usernames: no_admin, no_user, no_* (any)")
	logger.Print("")
	logger.Print("  Disclaimer: This is a testing tool. Use at your own risk.")
	logger.Print("")
	logger.Print("  Note: Use -a <IP:Port> to bind to a specific server address.")
	logger.Print("")
	logger.Print("  Note: If you encounter timeouts (Disable UDP Checksum Offloading):")
	logger.Print("        sudo ethtool -K <interface> tx off")
	logger.Print("")
	logger.Print("  Ready to accept connections...")
	logger.Print("═══════════════════════════════════════════════════════")

	conn, err := net.ListenPacket("udp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *addr, err)
	}
	defer conn.Close()

	logger.Print("  Listening on %s", conn.LocalAddr())

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 2048)
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
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

type UDPConn struct {
	conn *net.UDPConn
}

func (u *UDPConn) SendTo(addr net.Addr, data []byte) error {
	_, err := u.conn.WriteToUDP(data, addr.(*net.UDPAddr))
	return err
}

func handlePacket(conn net.PacketConn, clientAddr net.Addr, packet []byte, secret string, logger *Logger) {
	if len(packet) < 20 {
		logger.Print("[%s] ERROR: Packet too short (%d bytes) - ignored", clientAddr, len(packet))
		return
	}

	code := packet[0]
	identifier := packet[1]
	length := uint16(packet[2])<<8 | uint16(packet[3])

	// Fix #5: Added bounds check for the declared packet length
	if int(length) > len(packet) {
		logger.Print("[%s] ERROR: Declared length (%d) exceeds actual payload (%d) - ignored", clientAddr, length, len(packet))
		return
	}

	// Strictly slice packet to length to ignore UDP padding
	packet = packet[:length]

	if code != AccessRequest {
		logger.Print("[%s] IGNORED: Non-Access-Request packet (Code=%d, Id=%d, Len=%d)", clientAddr, code, identifier, length)
		return
	}

	authType := "PAP"
	if hasMSCHAPAttributes(packet) {
		authType = "MS-CHAP"
	} else if hasCHAPAttributes(packet) {
		authType = "CHAP"
	}

	if hasMessageAuthenticator(packet) {
		valid, detectedAlgo := validateMessageAuthenticator(packet, secret)
		if !valid {
			logger.Print("[%s] AUTH FAILED: Invalid Message-Authenticator", clientAddr)
			logger.Print("  | Auth Type:  %s", authType)
			logger.Print("  | Identifier:  %d", identifier)
			logger.Print("  | Packet Len:  %d bytes", length)
			logger.Print("  | Error:       Message-Authenticator validation failed")
			logger.Print("  | Algorithm:    HMAC-MD5 (RFC 2869)")

			logger.Print("  | DEBUG Hex:  %s", hex.EncodeToString(packet))
			showMABreakdown(logger, packet, secret, clientAddr)

			response := buildResponsePacket(packet, secret, AccessReject, identifier, "Message-Authenticator validation failed")
			writer := &UDPConn{conn.(*net.UDPConn)}
			writer.SendTo(clientAddr, response)
			return
		}
		if detectedAlgo != "" {
			logger.Print("[%s] MA Algorithm detected: %s", clientAddr, detectedAlgo)
		}
	}

	username, err := extractUsername(packet)
	if err != nil {
		username = "(unknown)"
	}

	var responseCode byte
	var replyMessage string
	if hasMSCHAPAttributes(packet) {
		mschapData, err := extractMSCHAPAttribute(packet)
		if err != nil {
			logger.Print("[%s] MS-CHAP extraction error: %v", clientAddr, err)
		}
		var parsedMSCHAP *MSCHAPData
		if err == nil {
			parsedMSCHAP, err = parseMSCHAPData(mschapData)
			if err != nil {
				logger.Print("[%s] MS-CHAP parse error: %v", clientAddr, err)
			}
		}
		handler := &Handler{secret: secret}
		responseCode, replyMessage = handler.ServeRadiusWithMSCHAP(username, parsedMSCHAP)
	} else if hasCHAPAttributes(packet) {
		chapResponse, err := extractCHAPResponse(packet)
		if err != nil {
			logger.Print("[%s] CHAP response extraction error: %v", clientAddr, err)
		}
		chapChallenge, err := extractCHAPChallenge(packet)
		if err != nil {
			logger.Print("[%s] CHAP challenge extraction error: %v", clientAddr, err)
		}
		handler := &Handler{secret: secret}
		responseCode, replyMessage = handler.ServeRadiusWithCHAP(username, chapResponse, chapChallenge)
	} else {
		handler := &Handler{secret: secret}
		responseCode, replyMessage = handler.ServeRadius(username)
	}

	response := buildResponsePacket(packet, secret, responseCode, identifier, replyMessage)
	writer := &UDPConn{conn.(*net.UDPConn)}
	writer.SendTo(clientAddr, response)

	responseStr := codeToString(responseCode)
	if responseCode == AccessAccept {
		logger.Print("[%s] %s | Auth: %s | User: %s | Id: %d | Len: %d bytes | Msg: %s",
			clientAddr, responseStr, authType, username, identifier, length, replyMessage)
	} else {
		logger.Print("[%s] %s | Auth: %s | User: %s | Id: %d | Len: %d bytes | Reject: %s",
			clientAddr, responseStr, authType, username, identifier, length, replyMessage)
	}

	if verbose {
		showResponseDebug(logger, response, secret, clientAddr)
	}
}

func extractMA(packet []byte) ([]byte, int) {
	if len(packet) < 20 {
		return nil, 0
	}
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrType == 80 && attrLen == 18 {
			ma := make([]byte, 16)
			copy(ma, packet[pos+2:pos+18])
			return ma, pos
		}
		if attrLen < 2 || pos+attrLen > len(packet) {
			break
		}
		pos += attrLen
	}
	return nil, 0
}

func showMABreakdown(logger *Logger, packet []byte, secret string, clientAddr net.Addr) {
	ma, maAttrOffset := extractMA(packet)

	logger.Print("  | DEBUG MA Attr Offset:  %d (0x%02x)", maAttrOffset, maAttrOffset)
	if ma != nil {
		logger.Print("  | DEBUG Received MA:     %s", hex.EncodeToString(ma))
	}

	length := uint16(packet[2])<<8 | uint16(packet[3])
	zeroMA := make([]byte, 16)
	
	// Sliced to avoid potential UDP padding 
	attrsWithZeroedMA := replaceOrAddMA(packet[20:length], zeroMA)

	authData := new(bytes.Buffer)
	authData.WriteByte(packet[0])
	authData.WriteByte(packet[1])
	authData.WriteByte(byte(length >> 8))
	authData.WriteByte(byte(length & 0xff))
	authData.Write(packet[4:20]) 
	authData.Write(attrsWithZeroedMA)

	h := hmac.New(md5.New, []byte(secret))
	h.Write(authData.Bytes())
	expectedMA := h.Sum(nil)

	logger.Print("  | DEBUG Secret used:     %q (len=%d)", secret, len(secret))
	logger.Print("  | DEBUG Expected MA:     %s", hex.EncodeToString(expectedMA))
	logger.Print("  | DEBUG Hashed Data:     %s", hex.EncodeToString(authData.Bytes()))
	logger.Print("  | DEBUG Packet Header:   Code=%d Id=%d Len=%d", packet[0], packet[1], length)
	logger.Print("  | DEBUG Authenticator:  %s", hex.EncodeToString(packet[4:20]))
	logger.Print("  | DEBUG Full Hex:        %s", hex.EncodeToString(packet))
}

func showResponseDebug(logger *Logger, packet []byte, secret string, clientAddr net.Addr) {
	if len(packet) < 20 {
		return
	}
	code := packet[0]
	id := packet[1]
	length := uint16(packet[2])<<8 | uint16(packet[3])
	respAuth := packet[4:20]

	logger.Print("[%s] DEBUG Response Handshake:", clientAddr)
	logger.Print("  | Code:       %d (%s)", code, codeToString(code))
	logger.Print("  | Identifier: %d", id)
	logger.Print("  | Length:     %d bytes", length)
	logger.Print("  | Resp Auth:  %s", hex.EncodeToString(respAuth))

	ma, _ := extractMA(packet)
	if ma != nil {
		logger.Print("  | Message-Auth: %s", hex.EncodeToString(ma))
	}
	logger.Print("  | Full Hex:   %s", hex.EncodeToString(packet))
	logger.Print("  | [Note: Response Authenticator is MD5(Code+ID+Len+ReqAuth+Attrs+Secret)]")
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
