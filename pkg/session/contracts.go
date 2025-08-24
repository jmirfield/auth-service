package session

import (
	"context"

	"github.com/google/uuid"
)

type SessionManager interface {
	IssueAccess(ctx context.Context, uid uuid.UUID, extra map[string]string) (string, error)
	IssueRefresh(ctx context.Context, uid uuid.UUID) (string, error)
	IssuePair(ctx context.Context, uid uuid.UUID, extra map[string]string) (string, string, error)
	ParseAccess(ctx context.Context, tok string) (*Claims, error)
	ParseRefresh(ctx context.Context, tok string) (*Claims, error)
	RefreshFrom(ctx context.Context, old string, extra map[string]string, rotate bool) (string, string, error)
}
