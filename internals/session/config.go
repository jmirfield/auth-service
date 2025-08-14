package session

import (
	"errors"
	"os"
	"time"
)

type Config struct {
	Secret          string
	Issuer          string
	Audience        string
	AccessLifetime  time.Duration
	RefreshLifetime time.Duration
	ClockSkewLeeway time.Duration
}

// Validate checks that required fields are present.
func (c *Config) Validate() error {
	if c.Secret == "" {
		return errors.New("missing required session secret env var")
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
		Secret:   os.Getenv("APP_JWT_SECRET"),
		Issuer:   os.Getenv("APP_JWT_ISSUER"),
		Audience: os.Getenv("APP_JWT_AUDIENCE"),
	}

	if s := os.Getenv("APP_JWT_ACCESS_LIFETIME"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.AccessLifetime = d
		}
	}

	if s := os.Getenv("APP_JWT_REFRESH_LIFETIME"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 {
			cfg.RefreshLifetime = d
		}
	}

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
