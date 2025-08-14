package storage

import (
	"context"
	"maps"
	"sync"
	"time"
)

type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]Record
}

func NewMemoryStore() Store {
	return &MemoryStore{data: make(map[string]Record)}
}

func (s *MemoryStore) Put(_ context.Context, userID string, r Record) error {
	s.mu.Lock()
	r.UserID = userID
	r.EnsureInit()
	s.data[userID] = deepCopyRecord(r)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) Get(_ context.Context, userID string) (Record, error) {
	s.mu.RLock()
	r, ok := s.data[userID]
	s.mu.RUnlock()
	if !ok {
		return Record{}, ErrNotFound
	}

	return deepCopyRecord(r), nil
}

func (s *MemoryStore) Update(_ context.Context, userID string, fn func(Record) Record) (Record, error) {
	s.mu.Lock()

	var curr Record
	if existing, ok := s.data[userID]; ok {
		curr = deepCopyRecord(existing)
	} else {
		curr = Record{UserID: userID}
		curr.EnsureInit()
	}

	next := fn(curr)
	next.UserID = userID
	next.EnsureInit()

	stored := deepCopyRecord(next)
	s.data[userID] = stored
	s.mu.Unlock()

	return deepCopyRecord(stored), nil
}

func (s *MemoryStore) Delete(_ context.Context, userID string) error {
	s.mu.Lock()
	delete(s.data, userID)
	s.mu.Unlock()
	return nil
}

func (s *MemoryStore) Exists(_ context.Context, userID string) (bool, error) {
	s.mu.RLock()
	_, ok := s.data[userID]
	s.mu.RUnlock()
	return ok, nil
}

func (s *MemoryStore) PruneAllExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	total := 0
	for uid, rec := range s.data {
		before := len(rec.RefreshTokens)
		out := rec.RefreshTokens[:0]
		for _, rt := range rec.RefreshTokens {
			if rt.ExpiresAt.After(now) {
				out = append(out, rt)
			}
		}
		rec.RefreshTokens = out
		s.data[uid] = rec
		total += before - len(out)
	}
	return total, nil
}

// internals/storage/memory.go (add slice copy)
func deepCopyRecord(r Record) Record {
	out := r
	out.RefreshTokensByProvider = maps.Clone(r.RefreshTokensByProvider)
	out.Attrs = maps.Clone(r.Attrs)
	if r.RefreshTokens != nil {
		out.RefreshTokens = make([]RefreshTokenRecord, len(r.RefreshTokens))
		copy(out.RefreshTokens, r.RefreshTokens)
	}
	return out
}
