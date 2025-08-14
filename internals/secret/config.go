package secret

import (
	"encoding/base64"
	"errors"
	"os"
)

const DefaultPrefix = "gcm:v1"

type Config struct {
	Key    []byte
	Prefix string
}

func (c *Config) Validate() error {
	if len(c.Key) != 32 {
		return errors.New("key must be 32 bytes")
	}

	if c.Prefix == "" {
		return errors.New("prefix cannot be empty")
	}

	return nil
}

func Load() (*Config, error) {
	b64key := os.Getenv("SECRET_ENC_KEY")

	key, err := decodeAnyBase64(b64key)
	if err != nil {
		return nil, err
	}

	prefix := os.Getenv("SECRET_PREFIX")
	if prefix == "" {
		prefix = DefaultPrefix
	}

	cfg := &Config{Key: key, Prefix: prefix}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func decodeAnyBase64(s string) ([]byte, error) {
	// Try URL-safe (no padding)
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}

	// Try standard w/ padding
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}

	// Try standard no-padding
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, nil
	}

	return nil, errors.New("invalid base64/base64url")
}
