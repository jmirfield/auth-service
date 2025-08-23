package secret

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

// testKey32 is a fixed 32-byte key for deterministic tests.
var testKey32 = bytes.Repeat([]byte{0xAB}, 32)

func newMgr(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(&Config{
		Key:    testKey32,
		Prefix: "gcm:v1",
	})
	if err != nil {
		t.Fatalf("New manager: %v", err)
	}
	return m
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	m := newMgr(t)
	plain := "top secret 🌶️"

	blob, err := m.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := m.Decrypt(blob)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plain {
		t.Fatalf("round-trip mismatch: want %q, got %q", plain, got)
	}
}

func TestEncrypt_RandomNonce_ChangesCiphertext(t *testing.T) {
	m := newMgr(t)
	plain := "same message"

	blob1, err := m.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt #1: %v", err)
	}
	blob2, err := m.Encrypt(plain)
	if err != nil {
		t.Fatalf("Encrypt #2: %v", err)
	}
	if blob1 == blob2 {
		t.Fatalf("expected different blobs due to random nonce")
	}

	// Also check the nonce segment differs
	p1 := strings.Split(blob1, ":")
	p2 := strings.Split(blob2, ":")
	if len(p1) != 4 || len(p2) != 4 {
		t.Fatalf("unexpected format; got %v and %v", len(p1), len(p2))
	}
	if p1[2] == p2[2] {
		t.Fatalf("expected different nonces")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	m := newMgr(t)
	blob, err := m.Encrypt("hello")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(blob, ":")
	if len(parts) != 4 {
		t.Fatalf("unexpected format: %v", parts)
	}

	// Tamper with ciphertext: flip one character in base64 segment (safe-ish tweak)
	cBytes, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		t.Fatalf("decode cipher: %v", err)
	}
	if len(cBytes) == 0 {
		t.Fatalf("ciphertext empty after decode")
	}
	cBytes[0] ^= 0xFF // flip a byte
	parts[3] = base64.RawURLEncoding.EncodeToString(cBytes)
	tampered := strings.Join(parts, ":")

	if _, err := m.Decrypt(tampered); err == nil {
		t.Fatalf("expected auth failure after tampering, got nil error")
	}
}

func TestDecrypt_InvalidPrefix(t *testing.T) {
	m := newMgr(t)

	// Build a valid looking blob, then swap the prefix
	blob, err := m.Encrypt("data")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	parts := strings.Split(blob, ":")
	if len(parts) != 4 {
		t.Fatalf("unexpected format: %v", parts)
	}
	parts[0] = "bad" // should be "gcm"
	bad := strings.Join(parts, ":")

	if _, err := m.Decrypt(bad); err == nil {
		t.Fatalf("expected invalid blob format error")
	}
}

func TestDecrypt_InvalidBlobFormat(t *testing.T) {
	m := newMgr(t)

	// Too few parts
	if _, err := m.Decrypt("gcm:v1:onlytwo"); err == nil {
		t.Fatalf("expected error for invalid blob format")
	}

	// Empty
	if _, err := m.Decrypt(""); err == nil {
		t.Fatalf("expected error for empty blob")
	}
}

func TestDecrypt_InvalidNonceEncoding(t *testing.T) {
	m := newMgr(t)

	// Proper 4-part form but nonce not base64
	blob := "gcm:v1:not-base64:thiswillnotmatter"
	if _, err := m.Decrypt(blob); err == nil {
		t.Fatalf("expected nonce encoding error")
	}
}

func TestDecrypt_InvalidCipherEncoding(t *testing.T) {
	m := newMgr(t)

	// Valid nonce, invalid cipher base64
	nonce := make([]byte, 12) // GCM standard nonce size
	_, _ = rand.Read(nonce)
	nb := base64.RawURLEncoding.EncodeToString(nonce)
	blob := "gcm:v1:" + nb + ":" + "!!!notb64!!!"

	if _, err := m.Decrypt(blob); err == nil {
		t.Fatalf("expected ciphertext encoding error")
	}
}

func TestDecrypt_BadNonceSize(t *testing.T) {
	m := newMgr(t)

	// Make a too-short nonce
	shortNonce := []byte{1, 2, 3}
	nb := base64.RawURLEncoding.EncodeToString(shortNonce)
	// Valid base64 for cipher, but we won't reach auth check due to nonce size
	cb := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3, 4})

	blob := "gcm:v1:" + nb + ":" + cb
	if _, err := m.Decrypt(blob); err == nil {
		t.Fatalf("expected bad nonce size error")
	}
}
