package storage

import (
	"context"
	"time"
)

type Store interface {
	// Get returns the user's record or ErrNotFound.
	Get(ctx context.Context, userID string) (Record, error)

	// Put stores r as the user's record. If the record exists it is replaced; if not, it is created.
	Put(ctx context.Context, userID string, r Record) error

	// Update atomically reads, transforms, and writes the record.
	Update(ctx context.Context, userID string, fn func(Record) Record) (Record, error)

	Delete(ctx context.Context, userID string) error
	Exists(ctx context.Context, refreshToken string) (bool, error)

	PruneAllExpired(ctx context.Context, now time.Time) (pruned int, err error)
}
