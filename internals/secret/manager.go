package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

type Manager struct {
	config *Config
}

func NewManager(cfg *Config) (*Manager, error) {
	return &Manager{
		config: cfg,
	}, nil
}

func (m *Manager) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(m.config.Key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ct := gcm.Seal(nil, nonce, []byte(plaintext), nil)

	nb := base64.RawURLEncoding.EncodeToString(nonce)
	cb := base64.RawURLEncoding.EncodeToString(ct)
	return m.config.Prefix + ":" + nb + ":" + cb, nil
}

func (m *Manager) Decrypt(blob string) (string, error) {
	if blob == "" {
		return "", errors.New("empty blob")
	}

	prefix := m.config.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}

	want := prefix + ":"
	if !strings.HasPrefix(blob, want) {
		return "", errors.New("invalid blob prefix")
	}

	rest := strings.TrimPrefix(blob, want)
	parts := strings.SplitN(rest, ":", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid blob format")
	}

	nonce, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("invalid nonce encoding")
	}

	ct, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("invalid ciphertext encoding")
	}

	block, err := aes.NewCipher(m.config.Key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(nonce) != gcm.NonceSize() {
		return "", errors.New("bad nonce size")
	}

	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}

	return string(pt), nil
}
