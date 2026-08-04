package tacacs

import (
	"fmt"
	"io"
	"net"
	"sync"
)

// ServerLogger defines logging interface for TACACS+ server.
type ServerLogger interface {
	Print(format string, args ...interface{})
}

// Server represents a TACACS+ TCP server instance.
type Server struct {
	Addr   string
	Secret string
	Logger ServerLogger
	
	listener net.Listener
	mu       sync.Mutex
	closed   bool
}

// NewServer creates a new TACACS+ server instance.
func NewServer(addr, secret string, logger ServerLogger) *Server {
	return &Server{
		Addr:   addr,
		Secret: secret,
		Logger: logger,
	}
}

// ListenAndServe starts the TACACS+ TCP listener.
func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on TACACS+ address %s: %w", s.Addr, err)
	}
	s.listener = l

	s.log("TACACS+ Server listening on %s (TCP)", l.Addr())

	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			isClosed := s.closed
			s.mu.Unlock()
			if isClosed {
				return nil
			}
			s.log("TACACS+ accept error: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

// Close stops the TACACS+ server.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) log(format string, args ...interface{}) {
	if s.Logger != nil {
		s.Logger.Print(format, args...)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr()

	for {
		// Read 12-byte header
		headerBuf := make([]byte, HeaderLen)
		_, err := io.ReadFull(conn, headerBuf)
		if err != nil {
			if err != io.EOF {
				s.log("[%s] TACACS+ connection read header error: %v", remoteAddr, err)
			}
			return
		}

		hdr, err := DecodeHeader(headerBuf)
		if err != nil {
			s.log("[%s] TACACS+ header decode error: %v", remoteAddr, err)
			return
		}

		// Read payload body
		bodyBuf := make([]byte, hdr.Length)
		if hdr.Length > 0 {
			_, err = io.ReadFull(conn, bodyBuf)
			if err != nil {
				s.log("[%s] TACACS+ body read error: %v", remoteAddr, err)
				return
			}
		}

		// De-obfuscate payload using shared secret
		decryptedBody, err := CryptPayload(hdr, bodyBuf, s.Secret)
		if err != nil {
			s.log("[%s] TACACS+ payload decrypt error: %v", remoteAddr, err)
			return
		}

		var respHeader *Header
		var respBody []byte
		var logMsg string

		switch hdr.Type {
		case TypeAuthen:
			start, err := DecodeAuthenStart(decryptedBody)
			if err != nil {
				s.log("[%s] TACACS+ AuthenStart decode error: %v", remoteAddr, err)
				return
			}

			reply := ProcessAuthenStart(start)
			respBody = reply.Encode()

			respHeader = &Header{
				Version:   hdr.Version,
				Type:      TypeAuthen,
				SeqNo:     hdr.SeqNo + 1,
				Flags:     hdr.Flags,
				SessionID: hdr.SessionID,
				Length:    uint32(len(respBody)),
			}

			statusStr := "PASS"
			if reply.Status == AuthenStatusFail {
				statusStr = "FAIL"
			}
			logMsg = fmt.Sprintf("Authen | User: %s | Status: %s | SessionID: %d", start.User, statusStr, hdr.SessionID)

		case TypeAuthor:
			req, err := DecodeAuthorRequest(decryptedBody)
			if err != nil {
				s.log("[%s] TACACS+ AuthorRequest decode error: %v", remoteAddr, err)
				return
			}

			resp := ProcessAuthorRequest(req)
			respBody = resp.Encode()

			respHeader = &Header{
				Version:   hdr.Version,
				Type:      TypeAuthor,
				SeqNo:     hdr.SeqNo + 1,
				Flags:     hdr.Flags,
				SessionID: hdr.SessionID,
				Length:    uint32(len(respBody)),
			}

			statusStr := "PASS_ADD"
			if resp.Status == AuthorStatusFail {
				statusStr = "FAIL"
			}
			logMsg = fmt.Sprintf("Author | User: %s | Status: %s | SessionID: %d", req.User, statusStr, hdr.SessionID)

		default:
			s.log("[%s] TACACS+ unsupported packet type: %d", remoteAddr, hdr.Type)
			return
		}

		// Encrypt response payload body
		encryptedRespBody, err := CryptPayload(respHeader, respBody, s.Secret)
		if err != nil {
			s.log("[%s] TACACS+ response payload encrypt error: %v", remoteAddr, err)
			return
		}

		// Send header + payload
		respPacket := append(respHeader.Encode(), encryptedRespBody...)
		_, err = conn.Write(respPacket)
		if err != nil {
			s.log("[%s] TACACS+ send response error: %v", remoteAddr, err)
			return
		}

		s.log("[%s] TACACS+ %s", remoteAddr, logMsg)

		// If single connect flag is not set, close after single request-reply per RFC 8907
		if hdr.Flags&FlagSingleConnect == 0 {
			return
		}
	}
}
