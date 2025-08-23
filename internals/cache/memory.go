package cache

import (
	"context"
	"sync"
	"time"
)

type memItem[T any] struct {
	v   T
	exp time.Time
}

type Memory[T any] struct {
	mu   sync.RWMutex
	data map[string]memItem[T]
	stop <-chan struct{}
}

func NewMemory[T any](ctx context.Context) Provider[T] {
	c := &Memory[T]{data: make(map[string]memItem[T]), stop: ctx.Done()}

	go c.janitor(15 * time.Minute)
	return c
}

func (m *Memory[T]) Get(ctx context.Context, key string) (v T, err error) {
	var zero T
	m.mu.Lock()
	it, exists := m.data[key]
	defer m.mu.Unlock()
	if !exists {
		return zero, ErrNotFound
	}
	now := time.Now()
	if !it.exp.IsZero() && it.exp.Before(now) {
		delete(m.data, key)
		return zero, ErrNotFound
	}
	return it.v, nil
}

func (m *Memory[T]) Set(_ context.Context, key string, value T, ttl time.Duration) error {
	var exp time.Time
	if ttl > 0 {
		exp = time.Now().Add(ttl)
	}
	m.mu.Lock()
	m.data[key] = memItem[T]{v: value, exp: exp}
	m.mu.Unlock()
	return nil
}

func (m *Memory[T]) Del(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.data, key)
	m.mu.Unlock()
	return nil
}

func (m *Memory[T]) janitor(every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			now := time.Now()
			m.mu.Lock()
			for k, it := range m.data {
				if !it.exp.IsZero() && now.After(it.exp) {
					delete(m.data, k)
				}
			}
			m.mu.Unlock()
		case <-m.stop:
			return
		}
	}
}
