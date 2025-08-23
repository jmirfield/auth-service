package user

import "github.com/google/uuid"

type User struct {
	ID   uuid.UUID      `json:"id"`
	Attr map[string]any `json:"attributes,omitempty"`
}
