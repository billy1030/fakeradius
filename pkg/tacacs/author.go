package tacacs

import (
	"encoding/binary"
	"fmt"
	"strings"
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
// RFC 8907 §6.1 body layout:
//   [0]  auth_method
//   [1]  priv_lvl
//   [2]  authen_type
//   [3]  authen_service
//   [4]  user_len
//   [5]  port_len
//   [6]  rem_addr_len
//   [7]  arg_cnt
//   [8..8+arg_cnt-1]  arg_len[i]
//   then: user | port | rem_addr | arg_1 | ... | arg_N
func DecodeAuthorRequest(data []byte) (*AuthorRequest, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("author request packet body too short: %d bytes (hex: %x)", len(data), data)
	}

	// Correct RFC 8907 §6.1 field offsets
	userLen    := int(data[4])
	portLen    := int(data[5])
	remAddrLen := int(data[6])
	argCnt     := int(data[7])

	hdrLen := 8 + argCnt
	if len(data) < hdrLen {
		return nil, fmt.Errorf("author request header too short: need %d bytes for %d args, have %d (hex: %x)",
			hdrLen, argCnt, len(data), data)
	}

	argLens := make([]int, argCnt)
	totalArgLen := 0
	for i := 0; i < argCnt; i++ {
		argLens[i] = int(data[8+i])
		totalArgLen += argLens[i]
	}

	expectedLen := hdrLen + userLen + portLen + remAddrLen + totalArgLen
	if len(data) < expectedLen {
		return nil, fmt.Errorf(
			"author request declared length (%d) exceeds actual payload (%d) "+
				"[user_len=%d port_len=%d rem_addr_len=%d arg_cnt=%d arg_lens=%v] (hex: %x)",
			expectedLen, len(data), userLen, portLen, remAddrLen, argCnt, argLens, data)
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
		AuthenMethod:  data[0],
		PrivLvl:       data[1],
		AuthenType:    data[2],
		AuthenService: data[3],
		User:          user,
		Port:          port,
		RemAddr:       remAddr,
		Args:          args,
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
// For a fake/testing server we always PASS_ADD, mirroring any requested AV-pairs
// back to the client (including service=, protocol=, cmd= attributes from PA/Cisco).
func ProcessAuthorRequest(req *AuthorRequest) *AuthorResponse {
	if req.User != "" && hasNoPrefix(req.User) {
		return &AuthorResponse{
			Status:    AuthorStatusFail,
			ServerMsg: "Authorization denied",
		}
	}

	// Mirror all AV-pairs back (required by many NAS devices including PA firewall
	// which sends service=PaloAlto, protocol=firewall, cmd= etc.)
	return &AuthorResponse{
		Status:    AuthorStatusPassAdd,
		ServerMsg: "Authorization allowed",
		Args:      req.Args,
	}
}

// FormatAuthorArgs returns a human-readable string of AV-pairs for logging.
func FormatAuthorArgs(args []string) string {
	if len(args) == 0 {
		return "(none)"
	}
	return strings.Join(args, ", ")
}
