package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	max         int
	window      time.Duration
	mu          sync.Mutex
	buckets     map[string]*bucket
	lastCleanup time.Time
}

type bucket struct {
	count       int
	windowStart time.Time
	lastSeen    time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{
		max:     max,
		window: window,
		buckets: make(map[string]*bucket),
	}
}

func (l *Limiter) Allow(key string) bool {
	if l == nil || key == "" || l.max <= 0 || l.window <= 0 {
		return true
	}

	now := time.Now()

	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{
			count:       1,
			windowStart: now,
			lastSeen:    now,
		}
		l.cleanup(now)
		return true
	}

	if now.Sub(b.windowStart) >= l.window {
		b.count = 0
		b.windowStart = now
	}

	if b.count >= l.max {
		b.lastSeen = now
		l.cleanup(now)
		return false
	}

	b.count++
	b.lastSeen = now
	l.cleanup(now)
	return true
}

func (l *Limiter) cleanup(now time.Time) {
	if l.window <= 0 {
		return
	}
	if !l.lastCleanup.IsZero() && now.Sub(l.lastCleanup) < l.window {
		return
	}
	for key, b := range l.buckets {
		if now.Sub(b.lastSeen) > l.window*2 {
			delete(l.buckets, key)
		}
	}
	l.lastCleanup = now
}
