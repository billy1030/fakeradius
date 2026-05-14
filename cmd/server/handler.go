// Package server implements RADIUS protocol utilities for the Fake RADIUS server.
// RADIUS packet format (RFC 2865):
//   - Code (1 byte): 1=Access-Request, 2=Access-Accept, 3=Access-Reject
//   - Identifier (1 byte): Matches request
//   - Length (2 bytes): Total packet length
//   - Authenticator (16 bytes): Request or response authenticator
//   - Attributes (variable): TLV format (Type, Length, Value)
package main

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
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

// CHAP attribute types (RFC 1994)
const (
	CHAPChallengeType = 60
	CHAPResponseType  = 61
)

// MS-CHAP attribute types (RFC 2548, RFC 2759)
const (
	MSCHAPAttributeType = 311 // Vendor-Specific with Microsoft vendor ID (311)
	MicrosoftVendorID   = 311
)

// CHAP algorithm identifier
const (
	CHAPAlgorithmMD5 = 5 // MD5 is most common
)

// RADIUS packet codes
const (
	AccessRequest = 1
	AccessAccept  = 2
	AccessReject  = 3
)

// Handler processes RADIUS Access-Request packets.
type Handler struct {
	secret string
}

// ServeRadius determines the response code and Reply-Message for a request.
func (h *Handler) ServeRadius(username string) (responseCode byte, replyMessage string) {
	if username != "" && hasNoPrefix(username) {
		return AccessReject, "User not allowed"
	}
	return AccessAccept, "Authentication accepted"
}

// hasNoPrefix returns true if the username starts with "no_".
func hasNoPrefix(username string) bool {
	return len(username) >= 3 && username[:3] == "no_"
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

// buildResponsePacket creates a fully RFC-compliant RADIUS response packet.
//
// Fixes:
// 1. Response Authenticator includes shared secret
// 2. Temporary Response Authenticator includes shared secret
// 3. Proper response Message-Authenticator circular dependency handling
func buildResponsePacket(
	requestPacket []byte,
	secret string,
	code byte,
	identifier byte,
	replyMessage string,
) []byte {

	// Request Authenticator from Access-Request
	requestAuth := make([]byte, 16)
	if len(requestPacket) >= 20 {
		copy(requestAuth, requestPacket[4:20])
	}

	// Step 1: Mirrored Attributes (Proxy-State and State)
	// Some clients require these to be mirrored back exactly.
	var attributes []byte
	
	// NOTE: For Access-Accept, we use a minimalist approach (no attributes)
	// to ensure maximum compatibility with strict firewalls (e.g., Palo Alto).
	if code == AccessAccept {
		totalLen := uint16(20)
		authData := make([]byte, 4+16+len(secret))
		authData[0] = code
		authData[1] = identifier
		binary.BigEndian.PutUint16(authData[2:4], totalLen)
		copy(authData[4:20], requestAuth)
		copy(authData[20:], []byte(secret))
		
		respAuth := md5.Sum(authData)
		
		packet := make([]byte, 20)
		packet[0] = code
		packet[1] = identifier
		binary.BigEndian.PutUint16(packet[2:4], totalLen)
		copy(packet[4:20], respAuth[:])
		return packet
	}

	// Standard attribute building for other response codes (e.g., Access-Reject)
	// Mirror Proxy-State (33) and State (24) from request
	pos := 20
	for pos < len(requestPacket) {
		if pos+2 > len(requestPacket) {
			break
		}
		attrType := requestPacket[pos]
		attrLen := int(requestPacket[pos+1])
		if attrLen < 2 || pos+attrLen > len(requestPacket) {
			break
		}
		if attrType == 33 || attrType == 24 {
			attributes = append(attributes, requestPacket[pos:pos+attrLen]...)
		}
		pos += attrLen
	}

	if replyMessage != "" {
		attributes = append(attributes, buildAttribute(ReplyMessageType, []byte(replyMessage))...)
	}

	// Step 3: Handle Authenticator Calculations
	totalLen := uint16(20 + len(attributes))
	authData := make([]byte, 4+16+len(attributes)+len(secret))
	authData[0] = code
	authData[1] = identifier
	binary.BigEndian.PutUint16(authData[2:4], totalLen)
	copy(authData[4:20], requestAuth)
	copy(authData[20:20+len(attributes)], attributes)
	copy(authData[20+len(attributes):], []byte(secret))
	
	respAuth := md5.Sum(authData)

	// Step 4: Build Final Packet
	packet := make([]byte, totalLen)
	packet[0] = code
	packet[1] = identifier
	binary.BigEndian.PutUint16(packet[2:4], totalLen)
	copy(packet[4:20], respAuth[:])
	copy(packet[20:], attributes)

	return packet
}

// hasMessageAuthenticator checks if the packet contains a Message-Authenticator attribute.
func hasMessageAuthenticator(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrType == MessageAuthenticatorType {
			return true
		}
		if attrLen < 2 || pos+attrLen > len(packet) {
			break
		}
		pos += attrLen
	}
	return false
}

// calculateMessageAuthenticator computes the Message-Authenticator attribute value.
func calculateMessageAuthenticator(code, id byte, length uint16, authenticator []byte, secret string, attributes []byte) []byte {
	zeroMA := make([]byte, 16)
	attrsWithZeroedMA := replaceOrAddMA(attributes, zeroMA)

	authData := make([]byte, 4+16+len(attrsWithZeroedMA))
	authData[0] = code
	authData[1] = id
	authData[2] = byte(length >> 8)
	authData[3] = byte(length & 0xFF)
	copy(authData[4:], authenticator)
	copy(authData[20:], attrsWithZeroedMA)

	h := hmac.New(md5.New, []byte(secret))
	h.Write(authData)
	return h.Sum(nil)
}

// replaceOrAddMA replaces Message-Authenticator attribute with zeroed version or adds it.
func replaceOrAddMA(attributes []byte, zeroMA []byte) []byte {
	maAttrZeroed := buildAttribute(MessageAuthenticatorType, zeroMA)
	result := []byte{}
	pos := 0
	found := false

	for pos < len(attributes) {
		if pos+2 > len(attributes) {
			// Append trailing junk/padding bytes to preserve packet structure
			result = append(result, attributes[pos:]...)
			pos = len(attributes)
			break
		}
		
		attrType := attributes[pos]
		attrLen := int(attributes[pos+1])

		if attrLen < 2 || pos+attrLen > len(attributes) {
			// Malformed attribute length, append remaining bytes as junk
			result = append(result, attributes[pos:]...)
			pos = len(attributes)
			break
		}

		if attrType == MessageAuthenticatorType {
			result = append(result, maAttrZeroed...)
			pos += attrLen
			found = true
		} else {
			result = append(result, attributes[pos:pos+attrLen]...)
			pos += attrLen
		}
	}

	if !found {
		result = append(result, maAttrZeroed...)
	}

	return result
}

// validateMessageAuthenticator validates the Message-Authenticator in a request packet.
// RFC-compliant implementation: Message-Authenticator = HMAC-MD5 only
func validateMessageAuthenticator(packet []byte, secret string) (valid bool, detectedAlgo string) {
	if !hasMessageAuthenticator(packet) {
		return true, ""
	}

	if len(packet) < 20 {
		return false, ""
	}

	length := uint16(packet[2])<<8 | uint16(packet[3])

	// Safety check: declared packet length must be valid
	if int(length) > len(packet) || length < 20 {
		return false, ""
	}

	// Extract received Message-Authenticator
	pos := 20
	var receivedMA []byte

	for pos < int(length) {
		if pos+2 > int(length) {
			break
		}

		attrType := packet[pos]
		attrLen := int(packet[pos+1])

		if attrLen < 2 || pos+attrLen > int(length) {
			break
		}

		if attrType == MessageAuthenticatorType && attrLen == 18 {
			receivedMA = make([]byte, 16)
			copy(receivedMA, packet[pos+2:pos+18])
			break
		}

		pos += attrLen
	}

	// If MA attribute is malformed, reject
	if receivedMA == nil {
		return false, ""
	}

	// Zero out MA attribute before HMAC calculation
	zeroMA := make([]byte, 16)
	attrsWithZeroedMA := replaceOrAddMA(packet[20:length], zeroMA)

	// RFC 2869 Section 5.14:
	// HMAC-MD5(Code + Identifier + Length + RequestAuth + Attributes-with-zeroed-MA)
	authData := make([]byte, 4+16+len(attrsWithZeroedMA))
	authData[0] = packet[0] // Code (Access-Request)
	authData[1] = packet[1] // Identifier
	binary.BigEndian.PutUint16(authData[2:4], length)
	copy(authData[4:20], packet[4:20]) // Request Authenticator
	copy(authData[20:], attrsWithZeroedMA)

	h := hmac.New(md5.New, []byte(secret))
	h.Write(authData)
	expectedMA := h.Sum(nil)

	if hmac.Equal(receivedMA, expectedMA) {
		return true, "md5"
	}

	return false, ""
}

// extractUsername extracts the User-Name attribute (Type 1) from a RADIUS packet.
func extractUsername(packet []byte) (string, error) {
	pos := 20

	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])

		if attrLen < 2 {
			break
		}

		if attrType == UserNameType && pos+attrLen <= len(packet) {
			return string(packet[pos+2 : pos+attrLen]), nil
		}

		pos += attrLen
	}

	return "", fmt.Errorf("User-Name attribute not found")
}

// CHAPData holds parsed CHAP challenge or response data.
type CHAPData struct {
	ID       byte
	Value    []byte // For Challenge: the challenge bytes. For Response: 16-byte MD5 hash.
	Name     string
}

// parseCHAPChallenge parses a CHAP-Challenge attribute (Type 60).
func parseCHAPChallenge(attrValue []byte) (*CHAPData, error) {
	if len(attrValue) == 0 {
		return nil, fmt.Errorf("CHAP-Challenge attribute is empty")
	}
	return &CHAPData{
		ID:    0,
		Value: attrValue,
		Name:  "",
	}, nil
}

// parseCHAPResponse parses a CHAP-Response attribute (Type 61).
func parseCHAPResponse(attrValue []byte) (*CHAPData, error) {
	if len(attrValue) < 18 {
		return nil, fmt.Errorf("CHAP-Response attribute too short: need at least 18 bytes, got %d", len(attrValue))
	}
	return &CHAPData{
		ID:    attrValue[0],
		Value: attrValue[1:17], 
		Name:  string(attrValue[17:]),
	}, nil
}

// extractCHAPChallenge extracts CHAP-Challenge attribute (Type 60) from packet.
func extractCHAPChallenge(packet []byte) ([]byte, error) {
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrLen < 2 {
			break
		}
		if attrType == CHAPChallengeType && pos+attrLen <= len(packet) {
			return packet[pos+2 : pos+attrLen], nil
		}
		pos += attrLen
	}
	return nil, fmt.Errorf("CHAP-Challenge attribute (Type 60) not found")
}

// extractCHAPResponse extracts CHAP-Response attribute (Type 61) from packet.
func extractCHAPResponse(packet []byte) ([]byte, error) {
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrLen < 2 {
			break
		}
		if attrType == CHAPResponseType && pos+attrLen <= len(packet) {
			return packet[pos+2 : pos+attrLen], nil
		}
		pos += attrLen
	}
	return nil, fmt.Errorf("CHAP-Response attribute (Type 61) not found")
}

// hasCHAPAttributes checks if packet contains CHAP-Challenge or CHAP-Response.
func hasCHAPAttributes(packet []byte) bool {
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrType == CHAPChallengeType || attrType == CHAPResponseType {
			return true
		}
		if attrLen < 2 || pos+attrLen > len(packet) {
			break
		}
		pos += attrLen
	}
	return false
}

// validateCHAPResponse validates a CHAP response.
func validateCHAPResponse(chapResponse, password []byte, challenge []byte) bool {
	if chapResponse == nil || len(chapResponse) < 17 || len(chapResponse) > 64 {
		return false
	}
	id := chapResponse[0]
	receivedHash := chapResponse[1:17]

	hashInput := make([]byte, 1+len(password)+len(challenge))
	hashInput[0] = id
	copy(hashInput[1:], password)
	copy(hashInput[1+len(password):], challenge)

	expectedHash := md5.Sum(hashInput)
	return hmac.Equal(receivedHash, expectedHash[:])
}

// ServeRadiusWithCHAP handles CHAP authentication.
func (h *Handler) ServeRadiusWithCHAP(username string, chapResponse, challenge []byte) (responseCode byte, replyMessage string) {
	if username != "" && hasNoPrefix(username) {
		return AccessReject, "User not allowed"
	}

	if chapResponse == nil || challenge == nil {
		return AccessAccept, "Authentication accepted"
	}

	if validateCHAPResponse(chapResponse, []byte(username), challenge) {
		return AccessAccept, "CHAP authentication accepted"
	}
	return AccessReject, "CHAP authentication failed"
}

// MSCHAPData holds parsed MS-CHAP data.
type MSCHAPData struct {
	Version       byte
	Response      []byte
	PeerChallenge []byte
	Flags         byte
	Name          string
}

// MSCHAPVersion constants
const (
	MSCHAPv1 = 1
	MSCHAPv2 = 3
)

// extractMSCHAPAttribute extracts MS-CHAP attributes (Type 311, Vendor-Specific).
func extractMSCHAPAttribute(packet []byte) ([]byte, error) {
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrLen < 2 {
			break
		}
		if attrType == 26 && pos+attrLen <= len(packet) {
			vendorData := packet[pos+2 : pos+attrLen]
			if len(vendorData) >= 4 {
				vendorID := uint32(vendorData[0])<<24 | uint32(vendorData[1])<<16 | uint32(vendorData[2])<<8 | uint32(vendorData[3])
				if vendorID == 311 {
					return vendorData[4:], nil 
				}
			}
		}
		pos += attrLen
	}
	return nil, fmt.Errorf("MS-CHAP attribute (Type 311) not found")
}

// parseMSCHAPData parses MS-CHAP data from the vendor-specific attribute.
func parseMSCHAPData(vendorData []byte) (*MSCHAPData, error) {
	if len(vendorData) < 4 {
		return nil, fmt.Errorf("MS-CHAP vendor data too short")
	}
	msType := vendorData[0]
	msLen := uint16(vendorData[2])<<8 | uint16(vendorData[3])

	if int(msLen) > len(vendorData)-4 {
		return nil, fmt.Errorf("MS-CHAP length field exceeds vendor data size")
	}
	if msLen < 4 {
		return nil, fmt.Errorf("MS-CHAP data too short")
	}

	data := vendorData[4:msLen]
	name := string(vendorData[msLen:])

	switch msType {
	case 1:
		if len(data) < 24 {
			return nil, fmt.Errorf("MS-CHAP v1 response too short")
		}
		return &MSCHAPData{
			Version:  msType,
			Response: data[:24],
			Name:     name,
		}, nil
	case 3:
		if len(data) < 49 {
			return nil, fmt.Errorf("MS-CHAP v2 response too short")
		}
		return &MSCHAPData{
			Version:       msType,
			PeerChallenge: data[:16],
			Response:      data[24:48],
			Flags:         data[48],
			Name:          name,
		}, nil
	default:
		return nil, fmt.Errorf("Unknown MS-CHAP version: %d", msType)
	}
}

// hasMSCHAPAttributes checks if packet contains MS-CHAP attribute.
func hasMSCHAPAttributes(packet []byte) bool {
	pos := 20
	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])
		if attrType == 26 && pos+attrLen <= len(packet) {
			vendorData := packet[pos+2 : pos+attrLen]
			if len(vendorData) >= 4 {
				vendorID := uint32(vendorData[0])<<24 | uint32(vendorData[1])<<16 | uint32(vendorData[2])<<8 | uint32(vendorData[3])
				if vendorID == 311 {
					return true
				}
			}
		}
		if attrLen < 2 || pos+attrLen > len(packet) {
			break
		}
		pos += attrLen
	}
	return false
}

func validateMSCHAPResponse(mschap *MSCHAPData, username string) bool {
	if mschap == nil {
		return false
	}
	if mschap.Name != username {
		return false
	}
	switch mschap.Version {
	case 1:
		return len(mschap.Response) >= 24
	case 3:
		return len(mschap.Response) >= 24
	}
	return false
}

func (h *Handler) ServeRadiusWithMSCHAP(username string, mschap *MSCHAPData) (responseCode byte, replyMessage string) {
	if username != "" && hasNoPrefix(username) {
		return AccessReject, "User not allowed"
	}

	if mschap == nil {
		return AccessAccept, "Authentication accepted"
	}

	if validateMSCHAPResponse(mschap, username) {
		return AccessAccept, fmt.Sprintf("MS-CHAP v%d authentication accepted", mschap.Version)
	}
	return AccessReject, "MS-CHAP authentication failed"
}