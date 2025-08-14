package apple

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	TeamID        string
	ClientID      string
	KeyID         string
	PrivateKey    *ecdsa.PrivateKey
	PrivateKeyPEM []byte
}

func (c *Config) Validate() error {
	if c.TeamID == "" {
		return errors.New("missing required Apple team id env var")
	}

	if c.ClientID == "" {
		return errors.New("missing required Apple client id env var")
	}

	if c.KeyID == "" {
		return errors.New("missing required Apple key id env var")
	}

	if c.PrivateKey == nil {
		return errors.New("missing required Apple private key")
	}

	return nil
}

func Load() (*Config, error) {
	team := os.Getenv("APPLE_TEAM_ID")
	client := os.Getenv("APPLE_CLIENT_ID")
	kid := os.Getenv("APPLE_KEY_ID")
	keyPath := os.Getenv("APPLE_PRIVATE_KEY_PATH")

	pemBytes, err := os.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecdsaKey, ok := privAny.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not ECDSA")
	}

	cfg := &Config{
		TeamID:        team,
		ClientID:      client,
		KeyID:         kid,
		PrivateKey:    ecdsaKey,
		PrivateKeyPEM: pemBytes,
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
