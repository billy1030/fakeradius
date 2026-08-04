package tacacs_test

import (
	"bytes"
	"testing"

	"github.com/fakeradius/fakeradius/pkg/tacacs"
)

func TestHeaderEncodeDecode(t *testing.T) {
	original := &tacacs.Header{
		Version:   tacacs.Version120,
		Type:      tacacs.TypeAuthen,
		SeqNo:     1,
		Flags:     tacacs.FlagSingleConnect,
		SessionID: 0x12345678,
		Length:    32,
	}

	encoded := original.Encode()
	if len(encoded) != tacacs.HeaderLen {
		t.Fatalf("expected header length %d, got %d", tacacs.HeaderLen, len(encoded))
	}

	decoded, err := tacacs.DecodeHeader(encoded)
	if err != nil {
		t.Fatalf("failed to decode header: %v", err)
	}

	if decoded.Version != original.Version || decoded.Type != original.Type ||
		decoded.SeqNo != original.SeqNo || decoded.Flags != original.Flags ||
		decoded.SessionID != original.SessionID || decoded.Length != original.Length {
		t.Errorf("decoded header mismatch: %+v vs %+v", decoded, original)
	}
}

func TestCryptPayload(t *testing.T) {
	hdr := &tacacs.Header{
		Version:   tacacs.Version120,
		Type:      tacacs.TypeAuthen,
		SeqNo:     1,
		Flags:     0,
		SessionID: 9999,
		Length:    13,
	}

	secret := "testing123"
	plaintext := []byte("hello tacacs+")

	encrypted, err := tacacs.CryptPayload(hdr, plaintext, secret)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Fatal("encrypted payload should not equal plaintext")
	}

	decrypted, err := tacacs.CryptPayload(hdr, encrypted, secret)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted payload (%s) does not match original (%s)", string(decrypted), string(plaintext))
	}
}

func TestAuthenLogic(t *testing.T) {
	startPass := &tacacs.AuthenStart{
		User:       "alice",
		AuthenType: tacacs.AuthenTypeASCII,
	}
	replyPass := tacacs.ProcessAuthenStart(startPass)
	if replyPass.Status != tacacs.AuthenStatusPass {
		t.Errorf("expected PASS for alice, got 0x%02X", replyPass.Status)
	}

	startFail := &tacacs.AuthenStart{
		User:       "no_admin",
		AuthenType: tacacs.AuthenTypeASCII,
	}
	replyFail := tacacs.ProcessAuthenStart(startFail)
	if replyFail.Status != tacacs.AuthenStatusFail {
		t.Errorf("expected FAIL for no_admin, got 0x%02X", replyFail.Status)
	}
}
