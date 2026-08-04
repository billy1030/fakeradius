package tacacs

import (
	"encoding/binary"
	"fmt"
)

// AuthenStart represents TACACS+ Authentication START packet body (RFC 8907 §5.1).
type AuthenStart struct {
	Action     uint8
	PrivLvl    uint8
	AuthenType uint8
	Service    uint8
	User       string
	Port       string
	RemAddr    string
	Data       []byte
}

// DecodeAuthenStart parses TACACS+ START body bytes.
func DecodeAuthenStart(data []byte) (*AuthenStart, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("authen start packet body too short: %d bytes", len(data))
	}

	userLen := int(data[4])
	portLen := int(data[5])
	remAddrLen := int(data[6])
	dataLen := int(data[7])

	expectedLen := 8 + userLen + portLen + remAddrLen + dataLen
	if len(data) < expectedLen {
		return nil, fmt.Errorf("authen start declared length (%d) exceeds actual payload (%d)", expectedLen, len(data))
	}

	pos := 8
	user := string(data[pos : pos+userLen])
	pos += userLen

	port := string(data[pos : pos+portLen])
	pos += portLen

	remAddr := string(data[pos : pos+remAddrLen])
	pos += remAddrLen

	dataBytes := make([]byte, dataLen)
	copy(dataBytes, data[pos:pos+dataLen])

	return &AuthenStart{
		Action:     data[0],
		PrivLvl:    data[1],
		AuthenType: data[2],
		Service:    data[3],
		User:       user,
		Port:       port,
		RemAddr:    remAddr,
		Data:       dataBytes,
	}, nil
}

// AuthenReply represents TACACS+ Authentication REPLY packet body (RFC 8907 §5.2).
type AuthenReply struct {
	Status    uint8
	Flags     uint8
	ServerMsg string
	Data      []byte
}

// Encode serializes AuthenReply into raw bytes.
func (r *AuthenReply) Encode() []byte {
	msgBytes := []byte(r.ServerMsg)
	msgLen := uint16(len(msgBytes))
	dataLen := uint16(len(r.Data))

	buf := make([]byte, 6+msgLen+dataLen)
	buf[0] = r.Status
	buf[1] = r.Flags
	binary.BigEndian.PutUint16(buf[2:4], msgLen)
	binary.BigEndian.PutUint16(buf[4:6], dataLen)

	copy(buf[6:6+msgLen], msgBytes)
	copy(buf[6+msgLen:], r.Data)
	return buf
}

// hasNoPrefix checks if username starts with "no_".
func hasNoPrefix(username string) bool {
	return len(username) >= 3 && username[:3] == "no_"
}

// ProcessAuthenStart evaluates authentication logic for a TACACS+ START packet.
func ProcessAuthenStart(start *AuthenStart) *AuthenReply {
	if start.User != "" && hasNoPrefix(start.User) {
		return &AuthenReply{
			Status:    AuthenStatusFail,
			ServerMsg: "User not allowed",
		}
	}

	// For ASCII prompt mode where username might be empty in initial START packet,
	// ask for user if user is empty.
	if start.User == "" && start.AuthenType == AuthenTypeASCII {
		return &AuthenReply{
			Status:    AuthenStatusGetUser,
			ServerMsg: "User: ",
		}
	}

	return &AuthenReply{
		Status:    AuthenStatusPass,
		ServerMsg: "Authentication successful",
	}
}
