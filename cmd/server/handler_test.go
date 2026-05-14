package main

import (
	"testing"
)

func TestHasNoPrefix(t *testing.T) {
	tests := []struct {
		username string
		expected bool
	}{
		{"alice", false},
		{"admin", false},
		{"bob", false},
		{"no_admin", true},
		{"no_bob", true},
		{"no_", true},
		{"_admin", false},
		{"", false},
		{"no", false},
		{"n", false},
	}

	for _, tt := range tests {
		t.Run(tt.username, func(t *testing.T) {
			result := hasNoPrefix(tt.username)
			if result != tt.expected {
				t.Errorf("hasNoPrefix(%q) = %v, want %v", tt.username, result, tt.expected)
			}
		})
	}
}

func TestHandlerServeRadius(t *testing.T) {
	handler := &Handler{secret: "testsecret"}

	tests := []struct {
		name           string
		username       string
		expectedCode   byte
		expectedReply  string
	}{
		{"alice accepts", "alice", AccessAccept, "Authentication accepted"},
		{"admin accepts", "admin", AccessAccept, "Authentication accepted"},
		{"bob accepts", "bob", AccessAccept, "Authentication accepted"},
		{"no_admin rejects", "no_admin", AccessReject, "User not allowed"},
		{"no_bob rejects", "no_bob", AccessReject, "User not allowed"},
		{"no_ rejects", "no_", AccessReject, "User not allowed"},
		{"empty username accepts", "", AccessAccept, "Authentication accepted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, reply := handler.ServeRadius(tt.username)
			if code != tt.expectedCode {
				t.Errorf("ServeRadius(%q) code = %d, want %d", tt.username, code, tt.expectedCode)
			}
			if reply != tt.expectedReply {
				t.Errorf("ServeRadius(%q) reply = %q, want %q", tt.username, reply, tt.expectedReply)
			}
		})
	}
}

func TestBuildAttribute(t *testing.T) {
	tests := []struct {
		attrType byte
		value    []byte
		expected []byte
	}{
		{1, []byte("alice"), []byte{1, 7, 'a', 'l', 'i', 'c', 'e'}},
		{18, []byte("Authentication accepted"), []byte{18, 24, 'A', 'u', 't', 'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n', ' ', 'a', 'c', 'c', 'e', 'p', 't', 'e', 'd'}},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := buildAttribute(tt.attrType, tt.value)
			if len(result) != len(tt.expected) {
				t.Errorf("buildAttribute(%d, %v) len = %d, want %d", tt.attrType, tt.value, len(result), len(tt.expected))
			}
			if result[0] != tt.attrType {
				t.Errorf("buildAttribute type = %d, want %d", result[0], tt.attrType)
			}
			if result[1] != byte(len(result)) {
				t.Errorf("buildAttribute length byte = %d, want %d", result[1], len(result))
			}
		})
	}
}

func TestHasMessageAuthenticator(t *testing.T) {
	// Build a packet with Message-Authenticator attribute
	// Header: code(1) + id(1) + length(2) + authenticator(16) = 20 bytes
	// User-Name: type(1) + len(1) + value(5) = 7 bytes
	// Message-Authenticator: type(1) + len(1) + value(16) = 18 bytes
	// Total: 20 + 7 + 18 = 45 bytes
	packetWithMA := []byte{
		1,                   // Code: Access-Request
		1,                   // Identifier
		0, 45,               // Length: 45
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Request Authenticator (16 bytes)
		1, 7, 'a', 'l', 'i', 'c', 'e', // User-Name (type=1, len=7, "alice")
		80, 18,             // Message-Authenticator Type, Length (18)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 bytes of MA value
	}

	// Packet without Message-Authenticator: header(20) + User-Name(7) = 27 bytes
	packetWithoutMA := []byte{
		1,                   // Code: Access-Request
		1,                   // Identifier
		0, 27,               // Length: 27
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Request Authenticator (16 bytes)
		1, 7, 'a', 'l', 'i', 'c', 'e', // User-Name (type=1, len=7, "alice")
	}

	if !hasMessageAuthenticator(packetWithMA) {
		t.Error("hasMessageAuthenticator(packetWithMA) = false, want true")
	}

	if hasMessageAuthenticator(packetWithoutMA) {
		t.Error("hasMessageAuthenticator(packetWithoutMA) = true, want false")
	}
}
