package storage

import (
	"context"
	"maps"
	"sync"
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
	ensureInit(&r)
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
		ensureInit(&curr)
	}

	next := fn(curr)
	next.UserID = userID
	ensureInit(&next)

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

func ensureInit(r *Record) {
	if r.TokensByProvider == nil {
		r.TokensByProvider = make(map[string]Tokens)
	}
	if r.Attrs == nil {
		r.Attrs = make(map[string]string)
	}
}

func deepCopyRecord(r Record) Record {
	out := r
	out.TokensByProvider = maps.Clone(r.TokensByProvider)
	out.Attrs = maps.Clone(r.Attrs)
	return out
}
