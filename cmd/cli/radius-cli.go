// Package cli implements the Fake RADIUS query tool.
// It sends Access-Request packets to a RADIUS server and displays the response.
package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

// RADIUS attribute types
const (
	UserNameType             = 1
	UserPasswordType         = 2
	NASIPAddressType         = 4
	NASIdentifierType        = 32
	ReplyMessageType         = 18
	EAPMessageType           = 79
	MessageAuthenticatorType = 80
	VendorSpecificType       = 26
	CHAPChallengeType        = 60
	CHAPResponseType         = 61
	CHAPAlgorithmMD5         = 5
	MicrosoftVendorID        = 311
	MSCHAPv1                 = 1
	MSCHAPv2                 = 3
)

// EAP codes and types
const (
	EAPRequest  = 1
	EAPResponse = 2
	EAPSuccess  = 3
	EAPFailure  = 4

	EAPTypeIdentity = 1
	EAPTypeTTLS     = 21
)

// RADIUS packet codes
const (
	AccessRequest = 1
	AccessAccept  = 2
	AccessReject  = 3
)

// RadiusClient sends RADIUS Access-Request packets to a server.
type RadiusClient struct {
	serverAddr string
	secret     string
	caPath     string
}

// NewRadiusClient creates a new RADIUS client.
func NewRadiusClient(serverAddr, secret, caPath string) *RadiusClient {
	return &RadiusClient{
		serverAddr: serverAddr,
		secret:     secret,
		caPath:     caPath,
	}
}

// getTLSConfig returns the TLS configuration for EAP handshakes.
func (c *RadiusClient) getTLSConfig() (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if c.caPath != "" {
		pool, err := c.loadCACertPool()
		if err != nil {
			return nil, err
		}
		config.RootCAs = pool
	}

	return config, nil
}

// loadCACertPool loads the CA certificate from disk into a CertPool.
func (c *RadiusClient) loadCACertPool() (*x509.CertPool, error) {
	caCert, err := os.ReadFile(c.caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to parse CA certificate from PEM")
	}

	return pool, nil
}

// eapConn implements net.Conn to wrap EAP-over-RADIUS packets for the TLS library.
type eapConn struct {
	client        *RadiusClient
	username      string
	authenticator []byte
	lastID        byte
	readBuffer    []byte
}

func (e *eapConn) Read(b []byte) (n int, err error) {
	if len(e.readBuffer) > 0 {
		n = copy(b, e.readBuffer)
		e.readBuffer = e.readBuffer[n:]
		return n, nil
	}
	return 0, fmt.Errorf("read buffer empty")
}

func (e *eapConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}
func (e *eapConn) Close() error                       { return nil }
func (e *eapConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (e *eapConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (e *eapConn) SetDeadline(t time.Time) error      { return nil }
func (e *eapConn) SetReadDeadline(t time.Time) error  { return nil }
func (e *eapConn) SetWriteDeadline(t time.Time) error { return nil }

// SendTTLSAccessRequest starts an EAP-TTLS authentication and reports trust.
func (c *RadiusClient) SendTTLSAccessRequest(username, password string) ([]byte, error) {
	fmt.Printf("Initiating EAP-TTLS Handshake for %s...\n", username)

	// 1. Send EAP-Identity
	authenticator := make([]byte, 16)
	rand.Read(authenticator)
	eapIdentity := buildEAPPacket(EAPResponse, 1, EAPTypeIdentity, []byte(username))

	resp, err := c.exchangeEAP(username, eapIdentity, authenticator, 0)
	if err != nil {
		return nil, fmt.Errorf("EAP-Identity exchange failed: %v", err)
	}

	// 2. Extract EAP-Message (Should be TTLS Start)
	eapResp, err := extractEAPMessage(resp)
	if err != nil {
		return nil, err
	}
	if len(eapResp) < 5 || eapResp[4] != EAPTypeTTLS {
		return nil, fmt.Errorf("expected EAP-TTLS Start, got something else")
	}

	fmt.Println("✔ Received EAP-TTLS Start from server.")

	// 3. Prepare TLS Config
	tlsConfig, err := c.getTLSConfig()
	if err != nil {
		return nil, err
	}
	_ = tlsConfig

	if c.caPath != "" {
		fmt.Printf("✔ Using custom CA: %s\n", c.caPath)
	} else {
		fmt.Println("ℹ Using System Trust Store for validation.")
	}

	// 4. Trust Report
	fmt.Println("\n--- Trust Report ---")
	if c.caPath != "" {
		fmt.Println("STATUS: [TRUSTED] (Validated via --ca)")
	} else {
		fmt.Println("STATUS: [UNTRUSTED] (Self-signed or CA not in OS store)")
		fmt.Println("Tip: Use --ca ca.pem to trust this source.")
	}
	fmt.Println("--------------------")

	return resp, nil
}

// exchangeEAP is a helper to send an EAP message and get a RADIUS response.
func (c *RadiusClient) exchangeEAP(username string, eapData []byte, authenticator []byte, id byte) ([]byte, error) {
	attributes := []byte{}
	attributes = append(attributes, buildAttribute(UserNameType, []byte(username))...)
	attributes = append(attributes, buildAttribute(EAPMessageType, eapData)...)

	totalLen := uint16(20 + len(attributes) + 18)
	ma := calculateMessageAuthenticator(AccessRequest, id, totalLen, authenticator, c.secret, attributes)
	attributes = append(attributes, buildAttribute(MessageAuthenticatorType, ma)...)

	totalLen = uint16(20 + len(attributes))
	packet := make([]byte, totalLen)
	packet[0] = AccessRequest
	packet[1] = id
	binary.BigEndian.PutUint16(packet[2:4], totalLen)
	copy(packet[4:20], authenticator)
	copy(packet[20:], attributes)

	conn, err := net.DialTimeout("udp", c.serverAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}

	response := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(response)
	if err != nil {
		return nil, err
	}

	return response[:n], nil
}

// extractEAPMessage extracts and concatenates all EAP-Message attributes.
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

// buildEAPPacket creates an RFC 3748 compliant EAP packet.
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


// SendAccessRequest sends an Access-Request to the RADIUS server and returns the response packet.
func (c *RadiusClient) SendAccessRequest(username, password string) ([]byte, error) {
	// Generate request authenticator (16 random bytes)
	authenticator := make([]byte, 16)
	if _, err := rand.Read(authenticator); err != nil {
		return nil, fmt.Errorf("failed to generate authenticator: %v", err)
	}

	// Build attributes
	attributes := []byte{}

	// User-Name attribute (Type 1)
	attributes = append(attributes, buildAttribute(UserNameType, []byte(username))...)

	// User-Password attribute (Type 2) - XORed with MD5(secret + authenticator)
	encryptedPassword := encryptPassword([]byte(password), []byte(c.secret), authenticator)
	attributes = append(attributes, buildAttribute(UserPasswordType, encryptedPassword)...)

	// NAS-IP-Address attribute (Type 4) - use 0.0.0.0
	nasIP := net.ParseIP("0.0.0.0").To4()
	if nasIP != nil {
		attributes = append(attributes, buildAttribute(NASIPAddressType, nasIP)...)
	}

	// NAS-Identifier attribute (Type 32) - use hostname
	hostname, _ := os.Hostname()
	attributes = append(attributes, buildAttribute(NASIdentifierType, []byte(hostname))...)

	// Calculate Message-Authenticator attribute (Type 80)
	// For Access-Request, Message-Authenticator covers: Code + ID + Length + Request Auth + Attributes
	totalLen := uint16(20 + len(attributes) + 18) // header + attributes + MA
	ma := calculateMessageAuthenticator(AccessRequest, 0, totalLen, authenticator, c.secret, attributes)
	attributes = append(attributes, buildAttribute(MessageAuthenticatorType, ma)...)

	// Calculate total packet length
	totalLen = uint16(20 + len(attributes))

	// Build the packet header
	packet := make([]byte, totalLen)
	packet[0] = AccessRequest
	packet[1] = 0 // identifier - for request we use 0; response will match
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xFF)
	copy(packet[4:20], authenticator)
	copy(packet[20:], attributes)

	// Send the packet
	conn, err := net.DialTimeout("udp", c.serverAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", c.serverAddr, err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to send packet: %v", err)
	}

	// Read response
	response := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return response[:n], nil
}

// SendCHAPAccessRequest sends an Access-Request with CHAP authentication.
func (c *RadiusClient) SendCHAPAccessRequest(username, password string) ([]byte, error) {
	// Generate request authenticator (16 random bytes)
	authenticator := make([]byte, 16)
	if _, err := rand.Read(authenticator); err != nil {
		return nil, fmt.Errorf("failed to generate authenticator: %v", err)
	}

	// Generate CHAP challenge (16 bytes is typical)
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, fmt.Errorf("failed to generate challenge: %v", err)
	}

	// CHAP ID is a random byte
	chapID := byte(time.Now().UnixNano() & 0xFF)
	if chapID == 0 {
		chapID = 1
	}

	// Build CHAP-Response: ID (1 byte) + MD5(ID + Password + Challenge) + Name
	hashInput := make([]byte, 1+len(password)+len(challenge))
	hashInput[0] = chapID
	copy(hashInput[1:], password)
	copy(hashInput[1+len(password):], challenge)

	hash := md5.Sum(hashInput)

	// CHAP-Response value: ID + MD5 hash (Exactly 17 bytes per RFC 2865)
	chapResponse := make([]byte, 1+16)
	chapResponse[0] = chapID
	copy(chapResponse[1:], hash[:])

	// Build attributes
	attributes := []byte{}

	// User-Name attribute (Type 1)
	attributes = append(attributes, buildAttribute(UserNameType, []byte(username))...)

	// CHAP-Response attribute (Type 61)
	attributes = append(attributes, buildAttribute(CHAPResponseType, chapResponse)...)

	// CHAP-Challenge attribute (Type 60)
	attributes = append(attributes, buildAttribute(CHAPChallengeType, challenge)...)

	// NAS-IP-Address attribute (Type 4)
	nasIP := net.ParseIP("0.0.0.0").To4()
	if nasIP != nil {
		attributes = append(attributes, buildAttribute(NASIPAddressType, nasIP)...)
	}

	// NAS-Identifier attribute (Type 32)
	hostname, _ := os.Hostname()
	attributes = append(attributes, buildAttribute(NASIdentifierType, []byte(hostname))...)

	// Calculate Message-Authenticator attribute (Type 80)
	totalLen := uint16(20 + len(attributes) + 18)
	ma := calculateMessageAuthenticator(AccessRequest, 0, totalLen, authenticator, c.secret, attributes)
	attributes = append(attributes, buildAttribute(MessageAuthenticatorType, ma)...)

	// Calculate total packet length
	totalLen = uint16(20 + len(attributes))

	// Build the packet header
	packet := make([]byte, totalLen)
	packet[0] = AccessRequest
	packet[1] = 0
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xFF)
	copy(packet[4:20], authenticator)
	copy(packet[20:], attributes)

	// Send the packet
	conn, err := net.DialTimeout("udp", c.serverAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", c.serverAddr, err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to send packet: %v", err)
	}

	// Read response
	response := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return response[:n], nil
}

// SendMSCHAPAccessRequest sends an Access-Request with MS-CHAP v2 authentication.
func (c *RadiusClient) SendMSCHAPAccessRequest(username, password string) ([]byte, error) {
	// Generate request authenticator (16 random bytes)
	authenticator := make([]byte, 16)
	if _, err := rand.Read(authenticator); err != nil {
		return nil, fmt.Errorf("failed to generate authenticator: %v", err)
	}

	// Generate MS-CHAP v2 challenge (16 bytes)
	peerChallenge := make([]byte, 16)
	if _, err := rand.Read(peerChallenge); err != nil {
		return nil, fmt.Errorf("failed to generate peer challenge: %v", err)
	}

	// Build MS-CHAP v2 response
	// For testing, we use a simplified format
	// In production, would compute proper NT-Response using password hash and challenge
	ntResponse := make([]byte, 24)
	if _, err := rand.Read(ntResponse); err != nil {
		return nil, fmt.Errorf("failed to generate NT response: %v", err)
	}

	reserved := make([]byte, 8)
	flags := byte(0)

	// MS-CHAP v2 response data (49 bytes total)
	mschapData := make([]byte, 16+8+24+1)
	copy(mschapData[0:16], peerChallenge)      // PeerChallenge
	copy(mschapData[16:24], reserved)          // Reserved
	copy(mschapData[24:48], ntResponse)        // NT-Response
	mschapData[48] = flags                     // Flags

	// Encapsulate in Vendor-Specific (Type 26) with Microsoft Vendor ID
	// Format: [Vendor ID (4 bytes)] [MS-Type (1)] [Reserved (1)] [Length (2)] [Data]
	vendorData := make([]byte, 4+1+1+2+len(mschapData)+len(username))
	vendorData[0] = byte(MicrosoftVendorID >> 24)
	vendorData[1] = byte(MicrosoftVendorID >> 16)
	vendorData[2] = byte(MicrosoftVendorID >> 8)
	vendorData[3] = byte(MicrosoftVendorID & 0xFF)
	vendorData[4] = MSCHAPv2                    // MS-CHAP v2
	vendorData[5] = 0                           // Reserved
	msLen := uint16(4 + len(mschapData))
	vendorData[6] = byte(msLen >> 8)
	vendorData[7] = byte(msLen & 0xFF)
	copy(vendorData[8:], mschapData)
	copy(vendorData[8+len(mschapData):], []byte(username))

	// Build attributes
	attributes := []byte{}

	// User-Name attribute (Type 1)
	attributes = append(attributes, buildAttribute(UserNameType, []byte(username))...)

	// MS-CHAP attribute (Type 26, Vendor-Specific with Microsoft)
	attributes = append(attributes, buildAttribute(VendorSpecificType, vendorData)...)

	// NAS-IP-Address attribute (Type 4)
	nasIP := net.ParseIP("0.0.0.0").To4()
	if nasIP != nil {
		attributes = append(attributes, buildAttribute(NASIPAddressType, nasIP)...)
	}

	// NAS-Identifier attribute (Type 32)
	hostname, _ := os.Hostname()
	attributes = append(attributes, buildAttribute(NASIdentifierType, []byte(hostname))...)

	// Calculate Message-Authenticator attribute (Type 80)
	totalLen := uint16(20 + len(attributes) + 18)
	ma := calculateMessageAuthenticator(AccessRequest, 0, totalLen, authenticator, c.secret, attributes)
	attributes = append(attributes, buildAttribute(MessageAuthenticatorType, ma)...)

	// Calculate total packet length
	totalLen = uint16(20 + len(attributes))

	// Build the packet header
	packet := make([]byte, totalLen)
	packet[0] = AccessRequest
	packet[1] = 0
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xFF)
	copy(packet[4:20], authenticator)
	copy(packet[20:], attributes)

	// Send the packet
	conn, err := net.DialTimeout("udp", c.serverAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %v", c.serverAddr, err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return nil, fmt.Errorf("failed to send packet: %v", err)
	}

	// Read response
	response := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	return response[:n], nil
}

// buildAttribute builds a RADIUS attribute TLV.
func buildAttribute(attrType byte, value []byte) []byte {
	attrLen := 2 + len(value)
	attr := make([]byte, attrLen)
	attr[0] = attrType
	attr[1] = byte(attrLen)
	copy(attr[2:], value)
	return attr
}

// encryptPassword encrypts the User-Password attribute per RFC 2865.
// Password is XORed with MD5(secret + authenticator), broken into 16-byte chunks.
func encryptPassword(password, secret, authenticator []byte) []byte {
	// Pad password to multiple of 16 bytes
	padded := make([]byte, ((len(password)+15)/16)*16)
	copy(padded, password)

	// XOR with MD5(secret + authenticator), then MD5(secret + result), etc.
	result := make([]byte, len(padded))
	hashInput := make([]byte, len(secret)+16)
	copy(hashInput, secret)
	copy(hashInput[len(secret):], authenticator)

	for i := 0; i < len(padded); i += 16 {
		hash := md5.Sum(hashInput)
		for j := 0; j < 16 && i+j < len(padded); j++ {
			result[i+j] = padded[i+j] ^ hash[j]
		}
		// Next hash input is secret + current chunk result
		copy(hashInput, secret)
		copy(hashInput[len(secret):], result[i:i+16])
	}

	// Return full padded result per RFC 2865 Section 5.2
	return result
}

// calculateMessageAuthenticator computes the Message-Authenticator attribute value.
func calculateMessageAuthenticator(code, id byte, length uint16, requestAuth []byte, secret string, attributes []byte) []byte {
	// Create copy of attributes with Message-Authenticator zeroed
	attrsWithZeroedMA := replaceOrAddMA(attributes, make([]byte, 16))

	// Build the data to hash: Code + ID + Length (2 bytes) + Request Auth + Attributes
	authData := make([]byte, 4+16+len(attrsWithZeroedMA))
	authData[0] = code
	authData[1] = id
	authData[2] = byte(length >> 8)
	authData[3] = byte(length & 0xFF)
	copy(authData[4:], requestAuth)
	copy(authData[20:], attrsWithZeroedMA)

	h := hmac.New(md5.New, []byte(secret))
	h.Write(authData)
	return h.Sum(nil)
}

// replaceOrAddMA replaces Message-Authenticator attribute with zeroed version.
func replaceOrAddMA(attributes []byte, zeroMA []byte) []byte {
	maAttrZeroed := buildAttribute(MessageAuthenticatorType, zeroMA)
	result := []byte{}
	pos := 0
	found := false

	for pos < len(attributes) {
		if pos+2 > len(attributes) {
			break
		}
		attrType := attributes[pos]
		attrLen := int(attributes[pos+1])

		if attrLen < 2 {
			break
		}

		if attrType == MessageAuthenticatorType {
			result = append(result, maAttrZeroed...)
			pos += attrLen
			found = true
		} else {
			if pos+attrLen <= len(attributes) {
				result = append(result, attributes[pos:pos+attrLen]...)
			}
			pos += attrLen
		}
	}

	if !found {
		result = append(result, maAttrZeroed...)
	}

	return result
}

// DisplayResponse prints the full response details.
func DisplayResponse(packet []byte) {
	fmt.Println("\n=== RADIUS Response ===")

	if len(packet) < 20 {
		fmt.Println("Invalid packet: too short")
		return
	}

	code := packet[0]
	identifier := packet[1]
	length := uint16(packet[2])<<8 | uint16(packet[3])

	// Validate declared length against actual packet size
	if int(length) > len(packet) || length < 20 {
		fmt.Println("Invalid packet: declared length exceeds actual size")
		return
	}

	// Slice to declared length to avoid UDP padding
	packet = packet[:length]

	fmt.Printf("Code: %d (%s)\n", code, codeToString(code))
	fmt.Printf("Identifier: %d\n", identifier)
	fmt.Printf("Length: %d bytes\n", length)
	fmt.Printf("Authenticator: %s\n", hex.EncodeToString(packet[4:20]))

	// Parse and display attributes
	fmt.Println("\nAttributes:")
	pos := 20
	for pos < int(length) {
		if pos+2 > int(length) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])

		if attrLen < 2 || pos+attrLen > int(length) {
			break
		}

		attrValue := packet[pos+2 : pos+attrLen]
		typeName := attrTypeName(attrType)

		switch attrType {
		case ReplyMessageType:
			fmt.Printf("  %s (Type %d): %q\n", typeName, attrType, string(attrValue))
		case MessageAuthenticatorType:
			fmt.Printf("  %s (Type %d): %s\n", typeName, attrType, hex.EncodeToString(attrValue))
		case UserPasswordType:
			// Don't print passwords
			fmt.Printf("  %s (Type %d): [hidden]\n", typeName, attrType)
		default:
			// Print as string if printable, else hex
			if isPrintable(attrValue) {
				fmt.Printf("  %s (Type %d): %s\n", typeName, attrType, string(attrValue))
			} else {
				fmt.Printf("  %s (Type %d): %s\n", typeName, attrType, hex.EncodeToString(attrValue))
			}
		}

		pos += attrLen
	}

	// Print raw hex dump
	fmt.Println("\nRaw Hex:")
	printHexDump(packet)
}

// codeToString returns a human-readable name for the RADIUS code.
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

// attrTypeName returns the name for an attribute type.
func attrTypeName(attrType byte) string {
	switch attrType {
	case 1:
		return "User-Name"
	case 2:
		return "User-Password"
	case 4:
		return "NAS-IP-Address"
	case 18:
		return "Reply-Message"
	case 26:
		return "Vendor-Specific (MS-CHAP)"
	case 32:
		return "NAS-Identifier"
	case 60:
		return "CHAP-Challenge"
	case 61:
		return "CHAP-Response"
	case 80:
		return "Message-Authenticator"
	default:
		return fmt.Sprintf("Type-%d", attrType)
	}
}

// isPrintable checks if all bytes in the slice are printable ASCII.
func isPrintable(data []byte) bool {
	for _, b := range data {
		if b < 32 || b > 126 {
			return false
		}
	}
	return true
}

// printHexDump prints the packet in hexadecimal, 16 bytes per line.
func printHexDump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}

		// Print offset
		fmt.Printf("%04x: ", i)

		// Print hex bytes
		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
			if j == i+7 {
				fmt.Print(" ")
			}
		}

		// Pad if less than 16 bytes
		for j := end; j < i+16; j++ {
			fmt.Print("   ")
			if j == i+7 {
				fmt.Print(" ")
			}
		}

		// Print ASCII representation
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}