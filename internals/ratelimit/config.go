package ratelimit

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Max    int
	Window time.Duration
}

const (
	defaultMax    = 60
	defaultWindow = time.Minute
)

func Load() *Config {
	cfg := &Config{
		Max:    defaultMax,
		Window: defaultWindow,
	}

	if v := os.Getenv("RATE_LIMIT_MAX"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Max = n
		}
	}
	if v := os.Getenv("RATE_LIMIT_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Window = d
		}
	}

	return cfg
}
