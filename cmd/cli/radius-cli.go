// Package cli implements the Fake RADIUS query tool.
// It sends Access-Request packets to a RADIUS server and displays the response.
package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
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
	MessageAuthenticatorType = 80
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
}

// NewRadiusClient creates a new RADIUS client.
func NewRadiusClient(serverAddr, secret string) *RadiusClient {
	return &RadiusClient{
		serverAddr: serverAddr,
		secret:     secret,
	}
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

	// Trim to original password length
	return result[:len(password)]
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

		if attrType == MessageAuthenticatorType {
			result = append(result, maAttrZeroed...)
			pos += attrLen
			found = true
		} else {
			if attrLen >= 2 {
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

	fmt.Printf("Code: %d (%s)\n", code, codeToString(code))
	fmt.Printf("Identifier: %d\n", identifier)
	fmt.Printf("Length: %d bytes\n", length)
	fmt.Printf("Authenticator: %s\n", hex.EncodeToString(packet[4:20]))

	// Parse and display attributes
	fmt.Println("\nAttributes:")
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
	case 32:
		return "NAS-Identifier"
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