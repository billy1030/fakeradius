// Package tacacs implements TACACS+ protocol parsing and packet processing per RFC 8907.
package tacacs

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
)

// TACACS+ Packet Header Version & Constants (RFC 8907)
const (
	HeaderLen = 12

	// Major versions
	MajorVer12 = 0x0C // TACACS+ major version (12)

	// Minor versions
	MinorVerDefault = 0x00
	MinorVerOne     = 0x01

	// Combined Version byte shortcuts
	Version120 = (MajorVer12 << 4) | MinorVerDefault // 0xC0
	Version121 = (MajorVer12 << 4) | MinorVerOne     // 0xC1

	// Packet Types
	TypeAuthen = 0x01 // Authentication
	TypeAuthor = 0x02 // Authorization
	TypeAcct   = 0x03 // Accounting

	// Header Flags
	FlagUnencrypted   = 0x01 // 0x01: Body unencrypted
	FlagSingleConnect = 0x04 // 0x04: Multiplexing allowed

	// Authentication Actions
	AuthenActionLogin    = 0x01
	AuthenActionCHPASS   = 0x02
	AuthenActionSendAuth = 0x04

	// Authentication Types
	AuthenTypeASCII  = 0x01
	AuthenTypePAP    = 0x02
	AuthenTypeCHAP   = 0x03
	AuthenTypeMSCHAP = 0x04

	// Authentication Services
	AuthenServiceLogin  = 0x01
	AuthenServiceEnable = 0x02
	AuthenServicePPP    = 0x03

	// Authentication Status Replies
	AuthenStatusPass    = 0x01
	AuthenStatusFail    = 0x02
	AuthenStatusGetData = 0x03
	AuthenStatusGetUser = 0x04
	AuthenStatusGetPass = 0x05
	AuthenStatusRestart = 0x06
	AuthenStatusError   = 0x07

	// Authorization Status Replies
	AuthorStatusPassAdd  = 0x01
	AuthorStatusPassRepl = 0x02
	AuthorStatusFail     = 0x10
	AuthorStatusError    = 0x11
)

// Header represents the 12-byte TACACS+ header.
type Header struct {
	Version   uint8  // Major (4 bits) | Minor (4 bits)
	Type      uint8  // Authen (1), Author (2), Acct (3)
	SeqNo     uint8  // Sequence number (starts at 1)
	Flags     uint8  // FlagUnencrypted, FlagSingleConnect
	SessionID uint32 // Session identifier
	Length    uint32 // Body length excluding 12-byte header
}

// DecodeHeader parses a 12-byte buffer into a TACACS+ Header struct.
func DecodeHeader(data []byte) (*Header, error) {
	if len(data) < HeaderLen {
		return nil, fmt.Errorf("header too short: expected %d bytes, got %d", HeaderLen, len(data))
	}

	hdr := &Header{
		Version:   data[0],
		Type:      data[1],
		SeqNo:     data[2],
		Flags:     data[3],
		SessionID: binary.BigEndian.Uint32(data[4:8]),
		Length:    binary.BigEndian.Uint32(data[8:12]),
	}

	major := hdr.Version >> 4
	if major != MajorVer12 {
		return nil, fmt.Errorf("unsupported major version: 0x%X (expected 0x%X)", major, MajorVer12)
	}

	return hdr, nil
}

// Encode serializes a TACACS+ Header into a 12-byte buffer.
func (h *Header) Encode() []byte {
	buf := make([]byte, HeaderLen)
	buf[0] = h.Version
	buf[1] = h.Type
	buf[2] = h.SeqNo
	buf[3] = h.Flags
	binary.BigEndian.PutUint32(buf[4:8], h.SessionID)
	binary.BigEndian.PutUint32(buf[8:12], h.Length)
	return buf
}

// CryptPayload performs MD5 XOR stream cipher obfuscation/de-obfuscation on TACACS+ packet body per RFC 8907 §4.2.
// Pseudo-pad sequence generator:
//   Pad_1 = MD5(session_id + secret + version + seq_no)
//   Pad_n = MD5(session_id + secret + version + seq_no + Pad_{n-1})
func CryptPayload(hdr *Header, payload []byte, secret string) ([]byte, error) {
	if len(payload) == 0 {
		return []byte{}, nil
	}

	// If unencrypted flag is set, return payload directly
	if hdr.Flags&FlagUnencrypted != 0 {
		result := make([]byte, len(payload))
		copy(result, payload)
		return result, nil
	}

	if secret == "" {
		return nil, errors.New("shared secret cannot be empty for encrypted payload")
	}

	result := make([]byte, len(payload))
	secBytes := []byte(secret)
	sessBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(sessBytes, hdr.SessionID)

	var lastPad []byte
	pos := 0

	for pos < len(payload) {
		h := md5.New()
		h.Write(sessBytes)
		h.Write(secBytes)
		h.Write([]byte{hdr.Version, hdr.SeqNo})
		if len(lastPad) > 0 {
			h.Write(lastPad)
		}

		pad := h.Sum(nil)
		lastPad = pad

		for i := 0; i < len(pad) && pos < len(payload); i++ {
			result[pos] = payload[pos] ^ pad[i]
			pos++
		}
	}

	return result, nil
}
