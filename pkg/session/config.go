package session

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type Config struct {
	KeyID           string
	PrivateKey      *rsa.PrivateKey
	PublicKeys      map[string]*rsa.PublicKey
	Issuer          string
	Audience        string
	AccessLifetime  time.Duration
	RefreshLifetime time.Duration
	ClockSkewLeeway time.Duration
}

const (
	DefaultAccessTTL       = 10 * time.Minute
	DefaultRefreshTTL      = 30 * 24 * time.Hour
	DefaultClockSkewLeeway = 30 * time.Second
)

func (c *Config) Validate() error {
	if c.KeyID == "" {
		return errors.New("missing required session key id env var")
	}

	if c.PrivateKey == nil {
		return errors.New("missing required session private key")
	}

	if len(c.PublicKeys) == 0 {
		return errors.New("missing required session public keys")
	}
	if _, ok := c.PublicKeys[c.KeyID]; !ok {
		return errors.New("active key id missing from public keys")
	}

	if c.Issuer == "" {
		return errors.New("missing required session issuer env var")
	}

	if c.Audience == "" {
		return errors.New("missing required session audience env var")
	}

	if c.AccessLifetime <= 0 {
		return errors.New("invalid required session access lifetime env var")
	}

	if c.RefreshLifetime <= 0 {
		return errors.New("invalid required session refresh lifetime env var")
	}

	if c.ClockSkewLeeway < 0 {
		return errors.New("invalid session clock skew leeway env var")
	}

	return nil
}

func Load() (*Config, error) {
	cfg := &Config{
		KeyID:    os.Getenv("APP_JWT_KEY_ID"),
		Issuer:   os.Getenv("APP_JWT_ISSUER"),
		Audience: os.Getenv("APP_JWT_AUDIENCE"),
	}

	privatePath := os.Getenv("APP_JWT_PRIVATE_KEY_PATH")
	if privatePath != "" {
		priv, err := loadRSAPrivateKey(privatePath)
		if err != nil {
			return nil, fmt.Errorf("load private key: %w", err)
		}
		cfg.PrivateKey = priv
	}

	cfg.PublicKeys = make(map[string]*rsa.PublicKey)
	publicKeysEnv := os.Getenv("APP_JWT_PUBLIC_KEYS")
	if publicKeysEnv != "" {
		for pair := range strings.SplitSeq(publicKeysEnv, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, errors.New("invalid APP_JWT_PUBLIC_KEYS entry, expected kid:path")
			}
			pub, err := loadRSAPublicKey(parts[1])
			if err != nil {
				return nil, fmt.Errorf("load public key %q: %w", parts[0], err)
			}
			cfg.PublicKeys[parts[0]] = pub
		}
	}

	if cfg.PrivateKey != nil && cfg.KeyID != "" {
		if _, ok := cfg.PublicKeys[cfg.KeyID]; !ok {
			cfg.PublicKeys[cfg.KeyID] = &cfg.PrivateKey.PublicKey
		}
	}

	cfg.AccessLifetime = DefaultAccessTTL
	if s := os.Getenv("APP_JWT_ACCESS_LIFETIME"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.AccessLifetime = d
		}
	}

	cfg.RefreshLifetime = DefaultRefreshTTL
	if s := os.Getenv("APP_JWT_REFRESH_LIFETIME"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.RefreshLifetime = d
		}
	}

	cfg.ClockSkewLeeway = DefaultClockSkewLeeway
	if s := os.Getenv("APP_JWT_CLOCK_SKEW_LEEWAY"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d >= 0 {
			cfg.ClockSkewLeeway = d
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	if block.Type == "RSA PRIVATE KEY" {
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaKey, nil
}

func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	if block.Type == "RSA PUBLIC KEY" {
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaKey, nil
}
