package apple

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type Config struct {
	TeamID        string
	ClientID      string
	KeyID         string
	PrivateKey    *ecdsa.PrivateKey
	PrivateKeyPEM []byte
	HttpTimeout   time.Duration
	JwkCacheTTL   time.Duration
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

	if c.HttpTimeout <= 0 {
		return errors.New("invalid Apple HTTP timeout")
	}

	if c.JwkCacheTTL <= 0 {
		return errors.New("invalid Apple JWK cache TTL")
	}

	return nil
}

func Load() (*Config, error) {
	team := os.Getenv("APPLE_TEAM_ID")
	cli := os.Getenv("APPLE_CLIENT_ID")
	kid := os.Getenv("APPLE_KEY_ID")
	path := os.Getenv("APPLE_PRIVATE_KEY_PATH")

	pemBytes, err := os.ReadFile(filepath.Clean(path))
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
		ClientID:      cli,
		KeyID:         kid,
		PrivateKey:    ecdsaKey,
		PrivateKeyPEM: pemBytes,
	}

	if s := os.Getenv("APPLE_HTTP_TIMEOUT"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.HttpTimeout = d
		}
	}

	if s := os.Getenv("APPLE_JWK_CACHE_TTL"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.JwkCacheTTL = d
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}
