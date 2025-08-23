package user

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	Uid       uuid.UUID `json:"user_id"`
	Jti       uuid.UUID `json:"jti"`
	Hash      string    `json:"hash"`
	ExpiresAt time.Time `json:"expires_at"`
}
