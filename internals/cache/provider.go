package cache

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("not found")
)

type Provider[T any] interface {
	Get(ctx context.Context, key string) (val T, err error)
	Set(ctx context.Context, key string, value T, ttl time.Duration) error
	Del(ctx context.Context, key string) error
}
