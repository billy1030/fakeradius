package tacacs

import (
	"encoding/binary"
	"fmt"
)

// AuthorRequest represents TACACS+ Authorization Request packet body (RFC 8907 §6.1).
type AuthorRequest struct {
	AuthenMethod uint8
	PrivLvl      uint8
	AuthenType   uint8
	AuthenService uint8
	User         string
	Port         string
	RemAddr      string
	Args         []string
}

// DecodeAuthorRequest parses TACACS+ Authorization Request body bytes.
func DecodeAuthorRequest(data []byte) (*AuthorRequest, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("author request packet body too short: %d bytes", len(data))
	}

	argCnt := int(data[4])
	userLen := int(data[5])
	portLen := int(data[6])
	remAddrLen := int(data[7])

	hdrLen := 8 + argCnt
	if len(data) < hdrLen {
		return nil, fmt.Errorf("author request header too short for %d args", argCnt)
	}

	argLens := make([]int, argCnt)
	totalArgLen := 0
	for i := 0; i < argCnt; i++ {
		argLens[i] = int(data[8+i])
		totalArgLen += argLens[i]
	}

	expectedLen := hdrLen + userLen + portLen + remAddrLen + totalArgLen
	if len(data) < expectedLen {
		return nil, fmt.Errorf("author request declared length (%d) exceeds actual payload (%d)", expectedLen, len(data))
	}

	pos := hdrLen
	user := string(data[pos : pos+userLen])
	pos += userLen

	port := string(data[pos : pos+portLen])
	pos += portLen

	remAddr := string(data[pos : pos+remAddrLen])
	pos += remAddrLen

	args := make([]string, argCnt)
	for i := 0; i < argCnt; i++ {
		args[i] = string(data[pos : pos+argLens[i]])
		pos += argLens[i]
	}

	return &AuthorRequest{
		AuthenMethod: data[0],
		PrivLvl:      data[1],
		AuthenType:   data[2],
		AuthenService: data[3],
		User:         user,
		Port:         port,
		RemAddr:      remAddr,
		Args:         args,
	}, nil
}

// AuthorResponse represents TACACS+ Authorization Response packet body (RFC 8907 §6.2).
type AuthorResponse struct {
	Status    uint8
	ServerMsg string
	Data      []byte
	Args      []string
}

// Encode serializes AuthorResponse into raw bytes.
func (r *AuthorResponse) Encode() []byte {
	msgBytes := []byte(r.ServerMsg)
	msgLen := uint16(len(msgBytes))
	dataLen := uint16(len(r.Data))
	argCnt := uint8(len(r.Args))

	hdrLen := 6 + int(argCnt)
	argBytesList := make([][]byte, argCnt)
	totalArgLen := 0

	for i, arg := range r.Args {
		argBytesList[i] = []byte(arg)
		totalArgLen += len(argBytesList[i])
	}

	buf := make([]byte, hdrLen+int(msgLen)+int(dataLen)+totalArgLen)
	buf[0] = r.Status
	buf[1] = argCnt
	binary.BigEndian.PutUint16(buf[2:4], msgLen)
	binary.BigEndian.PutUint16(buf[4:6], dataLen)

	for i, argBytes := range argBytesList {
		buf[6+i] = uint8(len(argBytes))
	}

	pos := hdrLen
	copy(buf[pos:pos+int(msgLen)], msgBytes)
	pos += int(msgLen)

	copy(buf[pos:pos+int(dataLen)], r.Data)
	pos += int(dataLen)

	for _, argBytes := range argBytesList {
		copy(buf[pos:pos+len(argBytes)], argBytes)
		pos += len(argBytes)
	}

	return buf
}

// ProcessAuthorRequest evaluates authorization logic for a TACACS+ AUTHOR request.
func ProcessAuthorRequest(req *AuthorRequest) *AuthorResponse {
	if req.User != "" && hasNoPrefix(req.User) {
		return &AuthorResponse{
			Status:    AuthorStatusFail,
			ServerMsg: "Authorization denied",
		}
	}

	return &AuthorResponse{
		Status:    AuthorStatusPassAdd,
		ServerMsg: "Authorization allowed",
		Args:      req.Args, // Mirror requested arguments
	}
}
