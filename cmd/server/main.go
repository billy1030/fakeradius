// Package server implements a minimal RADIUS authentication server.
// It listens on UDP port 1812 and responds to Access-Request packets
// with Access-Accept or Access-Reject based on username prefix logic.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/pflag"
)

var verbose bool

// EAPSession tracks the state of an ongoing EAP conversation.
type EAPSession struct {
	ID        byte
	Type      byte
	State     int // 0: Start, 1: Identity, 2: TLS-Handshake, 3: Authenticated
	Username  string
	LastSeen  time.Time
	
	// TLS State
	TLSBufIn  bytes.Buffer
	TLSBufOut bytes.Buffer
	TLSConn   net.Conn
	HandshakeDone bool
}

var (
	sessions  = make(map[string]*EAPSession)
	sessionMu sync.Mutex
	serverCert tls.Certificate
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
	certFile := pflag.StringP("cert", "c", "cert/server.pem", "Path to server certificate")
	keyFile := pflag.StringP("key", "k", "cert/server.key", "Path to server private key")

	pflag.Parse()

	// Load certificates for EAP-TTLS
	var err error
	serverCert, err = tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		// We don't exit here to allow standard PAP/CHAP to work even if certs are missing
	}

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "Error: -secret flag is required")
		pflag.Usage()
		os.Exit(1)
	}

	if *addr == "ddr" {
		fmt.Fprintln(os.Stderr, "Error: Typo detected in address ('ddr').")
		fmt.Fprintln(os.Stderr, "Did you use a single dash '-addr' by mistake? Please use double dashes '--addr' or shorthand '-a'.")
		os.Exit(1)
	}
	if *secret == "ecret" {
		fmt.Fprintln(os.Stderr, "Error: Typo detected in secret ('ecret').")
		fmt.Fprintln(os.Stderr, "Did you use a single dash '-secret' by mistake? Please use double dashes '--secret' or shorthand '-s'.")
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
	if serverCert.Certificate != nil {
		logger.Print("  Certificate:    %s [LOADED]", *certFile)
	} else {
		logger.Print("  Certificate:    %s [MISSING/INVALID]", *certFile)
		logger.Print("  EAP-TTLS:       DISABLED")
	}
	logger.Print("  Private Key:    %s", *keyFile)
	logger.Print("  Auth Modes:     PAP, CHAP, MS-CHAP v1/v2, EAP-TTLS")
	logger.Print("  Auth Logic:     Allow all except 'no_' prefix")
	logger.Print("  Reject Usernames: no_admin, no_user, no_* (any)")
	logger.Print("")
	logger.Print("  Disclaimer: This is a testing tool. Use at your own risk.")
	logger.Print("")
	logger.Print("  Note: Use -a <IP:Port> to bind to a specific server address (recommended).")
	logger.Print("        If you encounter timeouts (Disable UDP Checksum Offloading):")
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

	if hasEAPAttributes(packet) {
		handleEAP(conn.(*net.UDPConn), clientAddr.(*net.UDPAddr), packet, secret, logger)
		return
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
	case AccessChallenge:
		return "Access-Challenge"
	default:
		return fmt.Sprintf("Unknown(%d)", code)
	}
}

func handleEAP(conn *net.UDPConn, clientAddr *net.UDPAddr, packet []byte, secret string, logger *Logger) {
	eapData, err := extractEAPMessage(packet)
	if err != nil {
		logger.Print("[%s] EAP error: %v", clientAddr, err)
		return
	}

	if len(eapData) < 4 {
		return
	}

	eapCode := eapData[0]
	eapID := eapData[1]
	
	sessionMu.Lock()
	session, exists := sessions[clientAddr.String()]
	if !exists {
		session = &EAPSession{
			ID:       eapID,
			LastSeen: time.Now(),
		}
		sessions[clientAddr.String()] = session
	}
	session.LastSeen = time.Now()
	sessionMu.Unlock()

	var respCode byte = AccessChallenge
	var eapResp []byte

	switch eapCode {
	case EAPResponse:
		eapType := eapData[4]
		switch eapType {
		case EAPTypeIdentity:
			session.Username = string(eapData[5:])
			session.State = 1
			logger.Print("[%s] EAP Identity: %s", clientAddr, session.Username)
			
			// Send TTLS Start
			ttlsStart := []byte{TTLSFlagStart}
			eapResp = buildEAPPacket(EAPRequest, eapID+1, ETypeTTLS, ttlsStart)
			session.ID = eapID + 1
			session.Type = ETypeTTLS
			
		case ETypeTTLS:
			if len(eapData) < 6 {
				return
			}
			flags := eapData[5]
			pos := 6
			if flags&TTLSFlagLength != 0 {
				pos += 4 // Skip length field
			}
			if pos > len(eapData) {
				return
			}
			tlsData := eapData[pos:]
			
			// Process TLS data
			eapResp = handleTLSHandshake(session, tlsData, eapID, logger)
		}

	case EAPRequest:
		// Should not happen on server
	}

	if eapResp != nil {
		// 1. Create the base attributes list
		var attributes []byte
		
		// Add EAP-Message attribute (First)
		// RFC 2869: Split EAP-Message if > 253 octets
		data := eapResp
		for len(data) > 0 {
			chunkSize := 253
			if len(data) < chunkSize {
				chunkSize = len(data)
			}
			attributes = append(attributes, buildAttribute(EAPMessageType, data[:chunkSize])...)
			data = data[chunkSize:]
		}
		
		// Add State attribute
		stateVal := []byte(fmt.Sprintf("%02x%08x", eapID, time.Now().UnixNano()))
		attributes = append(attributes, buildAttribute(StateAttributeType, stateVal)...)
		
		// Add Message-Authenticator (Zeroed out for calculation)
		zeroMA := make([]byte, 16)
		attributes = append(attributes, buildAttribute(MessageAuthenticatorType, zeroMA)...)
		
		// 2. Calculate Message-Authenticator
		// RFC 2869: Use Request Authenticator from original packet for MA calculation
		requestAuth := packet[4:20]
		totalLen := uint16(20 + len(attributes))
		
		ma := calculateMessageAuthenticator(respCode, packet[1], totalLen, requestAuth, secret, attributes)
		
		// Replace the zeroed MA with the real one
		copy(attributes[len(attributes)-16:], ma)
		
		// 3. Calculate Response Authenticator (The Header Signature)
		// RFC 2865: MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
		authData := make([]byte, 4+16+len(attributes)+len(secret))
		authData[0] = respCode
		authData[1] = packet[1]
		binary.BigEndian.PutUint16(authData[2:4], totalLen)
		copy(authData[4:20], requestAuth)
		copy(authData[20:20+len(attributes)], attributes)
		copy(authData[20+len(attributes):], []byte(secret))
		
		respAuth := md5.Sum(authData)
		
		// 4. Assemble the final packet
		finalPacket := make([]byte, totalLen)
		finalPacket[0] = respCode
		finalPacket[1] = packet[1]
		binary.BigEndian.PutUint16(finalPacket[2:4], totalLen)
		copy(finalPacket[4:20], respAuth[:])
		copy(finalPacket[20:], attributes)
		
		conn.WriteToUDP(finalPacket, clientAddr)
		logger.Print("[%s] %s | EAP: %s | Id: %d | User: %s", clientAddr, codeToString(respCode), "TTLS-Start", eapID, session.Username)
	}
}

func extractEAPMessage(packet []byte) ([]byte, error) {
	var eapData []byte
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrLen < 2 || pos+attrLen > len(packet) {
			break
		}
		if attrType == EAPMessageType {
			eapData = append(eapData, packet[pos+2:pos+attrLen]...)
		}
		pos += attrLen
	}
	if len(eapData) == 0 {
		return nil, fmt.Errorf("EAP-Message attribute not found")
	}
	return eapData, nil
}

func buildEAPPacket(code, id byte, eapType byte, data []byte) []byte {
	length := uint16(4)
	if eapType != 0 {
		length += 1 + uint16(len(data))
	}
	packet := make([]byte, length)
	packet[0] = code
	packet[1] = id
	packet[2] = byte(length >> 8)
	packet[3] = byte(length & 0xFF)
	if eapType != 0 {
		packet[4] = eapType
		copy(packet[5:], data)
	}
	return packet
}

// Global constants used in EAP handler
const (
	EAPRequest  = 1
	EAPResponse = 2
	EAPTypeIdentity = 1
	ETypeTTLS = 21
	TTLSFlagStart = 0x20
	AccessChallenge = 11
)
// Global constants used in EAP handler
const (
	ETypeTTLS = 21
)

// EAP-TTLS Flags
const (
	TTLSFlagLength = 0x80
	TTLSFlagMore   = 0x40
	TTLSFlagStart  = 0x20
)

// MemConn implements net.Conn for in-memory TLS processing
type MemConn struct {
	in  *bytes.Buffer
	out *bytes.Buffer
	mu  sync.Mutex
}

func (m *MemConn) Read(b []byte) (n int, err error) {
	for m.in.Len() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.in.Read(b)
}

func (m *MemConn) Write(b []byte) (n int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.out.Write(b)
}

func (m *MemConn) Close() error                       { return nil }
func (m *MemConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (m *MemConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (m *MemConn) SetDeadline(t time.Time) error      { return nil }
func (m *MemConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *MemConn) SetWriteDeadline(t time.Time) error { return nil }

func handleTLSHandshake(session *EAPSession, data []byte, eapID byte, logger *Logger) []byte {
	// 1. Pump new data into the TLS input buffer
	if len(data) > 0 {
		session.TLSBufIn.Write(data)
	}

	// 2. If this is the first data packet, start the TLS server in a goroutine
	if session.TLSConn == nil {
		mConn := &MemConn{in: &session.TLSBufIn, out: &session.TLSBufOut}
		session.TLSConn = mConn
		session.State = 2 // Initialize to TLS Handshake state
		
		go func() {
			tlsServer := tls.Server(mConn, &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				MinVersion:   tls.VersionTLS12,
			})
			if err := tlsServer.Handshake(); err != nil {
				// Errors here are often just the connection closing after handshake
			}
			session.HandshakeDone = true
		}()
	}

	// 3. Wait a moment for the TLS engine to produce output
	for i := 0; i < 50; i++ {
		if session.TLSBufOut.Len() > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	// 4. Handle Fragmentation (RFC 5281)
	output := session.TLSBufOut.Bytes()
	totalLen := uint32(len(output))
	chunkSize := 1000 // Conservative chunk size
	
	if len(output) > chunkSize {
		// More fragments to follow
		flags := TTLSFlagMore
		
		// RFC 5281: L bit only on the first fragment
		if session.State == 2 {
			flags |= TTLSFlagLength
			session.State = 21 // Transition to "Sending Fragments" state
		}
		
		chunk := output[:chunkSize]
		session.TLSBufOut.Next(chunkSize)
		
		var respData []byte
		if flags&TTLSFlagLength != 0 {
			respData = make([]byte, 1+4+len(chunk))
			respData[0] = byte(flags)
			binary.BigEndian.PutUint32(respData[1:5], totalLen)
			copy(respData[5:], chunk)
		} else {
			respData = append([]byte{byte(flags)}, chunk...)
		}
		
		return buildEAPPacket(EAPRequest, eapID+1, ETypeTTLS, respData)
	}

	// 5. Final chunk or small response
	if session.State == 2 || session.State == 21 {
		session.State = 3 // Handshake phase finishing
	}
	
	session.TLSBufOut.Reset()
	flags := byte(0)
	respData := append([]byte{flags}, output...)
	return buildEAPPacket(EAPRequest, eapID+1, ETypeTTLS, respData)
}
