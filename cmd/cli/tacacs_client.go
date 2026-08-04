package main

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/fakeradius/fakeradius/pkg/tacacs"
)

// SendTACACSAuthenRequest connects over TCP to a TACACS+ server and sends an Authen START request.
func SendTACACSAuthenRequest(serverAddr, secret, username, password string) error {
	conn, err := net.DialTimeout("tcp", serverAddr, 3*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to TACACS+ server at %s: %w", serverAddr, err)
	}
	defer conn.Close()

	// Construct AuthenStart payload
	userBytes := []byte(username)
	portBytes := []byte("tty1")
	remAddrBytes := []byte("127.0.0.1")
	passBytes := []byte(password)

	startBody := make([]byte, 8+len(userBytes)+len(portBytes)+len(remAddrBytes)+len(passBytes))
	startBody[0] = tacacs.AuthenActionLogin
	startBody[1] = 1 // PrivLvl
	startBody[2] = tacacs.AuthenTypeASCII
	startBody[3] = tacacs.AuthenServiceLogin
	startBody[4] = uint8(len(userBytes))
	startBody[5] = uint8(len(portBytes))
	startBody[6] = uint8(len(remAddrBytes))
	startBody[7] = uint8(len(passBytes))

	pos := 8
	copy(startBody[pos:], userBytes)
	pos += len(userBytes)
	copy(startBody[pos:], portBytes)
	pos += len(portBytes)
	copy(startBody[pos:], remAddrBytes)
	pos += len(remAddrBytes)
	copy(startBody[pos:], passBytes)

	hdr := &tacacs.Header{
		Version:   tacacs.Version120,
		Type:      tacacs.TypeAuthen,
		SeqNo:     1,
		Flags:     0,
		SessionID: 1001,
		Length:    uint32(len(startBody)),
	}

	encryptedBody, err := tacacs.CryptPayload(hdr, startBody, secret)
	if err != nil {
		return fmt.Errorf("failed to encrypt body: %w", err)
	}

	packet := append(hdr.Encode(), encryptedBody...)
	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to write TACACS+ packet: %w", err)
	}

	// Read response header
	respHeaderBuf := make([]byte, tacacs.HeaderLen)
	_, err = io.ReadFull(conn, respHeaderBuf)
	if err != nil {
		return fmt.Errorf("failed to read TACACS+ response header: %w", err)
	}

	respHdr, err := tacacs.DecodeHeader(respHeaderBuf)
	if err != nil {
		return fmt.Errorf("failed to decode TACACS+ response header: %w", err)
	}

	respBodyBuf := make([]byte, respHdr.Length)
	if respHdr.Length > 0 {
		_, err = io.ReadFull(conn, respBodyBuf)
		if err != nil {
			return fmt.Errorf("failed to read TACACS+ response body: %w", err)
		}
	}

	decryptedRespBody, err := tacacs.CryptPayload(respHdr, respBodyBuf, secret)
	if err != nil {
		return fmt.Errorf("failed to decrypt response body: %w", err)
	}

	if len(decryptedRespBody) < 6 {
		return fmt.Errorf("invalid TACACS+ reply body length: %d", len(decryptedRespBody))
	}

	status := decryptedRespBody[0]
	msgLen := uint16(decryptedRespBody[2])<<8 | uint16(decryptedRespBody[3])
	msg := ""
	if int(msgLen) <= len(decryptedRespBody)-6 {
		msg = string(decryptedRespBody[6 : 6+msgLen])
	}

	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Println("  TACACS+ Response Received")
	fmt.Println("═══════════════════════════════════════════════════════")
	fmt.Printf("  Status:     %s (0x%02X)\n", formatTACACSStatus(status), status)
	fmt.Printf("  Session ID: %d\n", respHdr.SessionID)
	if msg != "" {
		fmt.Printf("  Message:    %s\n", msg)
	}
	fmt.Println("═══════════════════════════════════════════════════════")

	return nil
}

func formatTACACSStatus(status uint8) string {
	switch status {
	case tacacs.AuthenStatusPass:
		return "PASS (Access-Accept equivalent)"
	case tacacs.AuthenStatusFail:
		return "FAIL (Access-Reject equivalent)"
	case tacacs.AuthenStatusGetData:
		return "GETDATA"
	case tacacs.AuthenStatusGetUser:
		return "GETUSER"
	case tacacs.AuthenStatusGetPass:
		return "GETPASS"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", status)
	}
}
