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

// buildResponsePacket creates a RADIUS response packet.
func buildResponsePacket(requestPacket []byte, secret string, code byte, identifier byte, replyMessage string) []byte {
	// Response authenticator = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
	requestAuth := make([]byte, 16)
	if len(requestPacket) >= 36 {
		copy(requestAuth, requestPacket[4:20])
	}

	// Build attributes
	attributes := []byte{}

	if replyMessage != "" {
		attributes = append(attributes, buildAttribute(ReplyMessageType, []byte(replyMessage))...)
	}

	// Calculate Message-Authenticator if present in request
	if hasMessageAuthenticator(requestPacket) {
		totalWithMA := uint16(20 + len(attributes) + 18)
		ma := calculateMessageAuthenticator(code, identifier, totalWithMA, requestAuth, secret, attributes)
		attributes = append(attributes, buildAttribute(MessageAuthenticatorType, ma)...)
	}

	totalLen := 20 + len(attributes)

	// Build packet header
	packet := make([]byte, totalLen)
	packet[0] = code
	packet[1] = identifier
	packet[2] = byte(totalLen >> 8)
	packet[3] = byte(totalLen & 0xFF)

	// Response authenticator: MD5(code + id + len + request auth + attributes + secret)
	authData := make([]byte, 4+16+len(attributes))
	authData[0] = code
	authData[1] = identifier
	authData[2] = byte(totalLen >> 8)
	authData[3] = byte(totalLen & 0xFF)
	copy(authData[4:], requestAuth)
	copy(authData[20:], attributes)

	hash := md5.Sum(authData)
	copy(packet[4:20], hash[:])

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
		if attrLen < 2 {
			break
		}
		pos += attrLen
	}
	return false
}

// calculateMessageAuthenticator computes the Message-Authenticator attribute value.
func calculateMessageAuthenticator(code, id byte, length uint16, requestAuth []byte, secret string, attributes []byte) []byte {
	zeroMA := make([]byte, 16)
	attrsWithZeroedMA := replaceOrAddMA(attributes, zeroMA)

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

// replaceOrAddMA replaces Message-Authenticator attribute with zeroed version or adds it.
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

// validateMessageAuthenticator validates the Message-Authenticator in a request packet.
// Returns true if valid or if no Message-Authenticator is present.
func validateMessageAuthenticator(packet []byte, secret string) bool {
	if !hasMessageAuthenticator(packet) {
		return true
	}

	if len(packet) < 20 {
		return false
	}

	pos := 20
	var receivedMA []byte

	for pos < len(packet) {
		if pos+2 > len(packet) {
			break
		}
		attrType := packet[pos]
		attrLen := int(packet[pos+1])

		if attrType == MessageAuthenticatorType && attrLen == 18 {
			receivedMA = make([]byte, 16)
			copy(receivedMA, packet[pos+2:pos+18])
			break
		}
		if attrLen < 2 {
			break
		}
		pos += attrLen
	}

	if receivedMA == nil {
		return true
	}

	length := uint16(packet[2])<<8 | uint16(packet[3])

	zeroMA := make([]byte, 16)
	attrsWithZeroedMA := replaceOrAddMA(packet[20:], zeroMA)

	authData := make([]byte, 4+16+len(attrsWithZeroedMA))
	authData[0] = packet[0]
	authData[1] = packet[1]
	binary.BigEndian.PutUint16(authData[2:4], length)
	copy(authData[4:20], packet[4:20])
	copy(authData[20:], attrsWithZeroedMA)

	h := hmac.New(md5.New, []byte(secret))
	h.Write(authData)
	expectedMA := h.Sum(nil)

	return hmac.Equal(receivedMA, expectedMA)
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
