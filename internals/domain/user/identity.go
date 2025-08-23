package user

import "github.com/google/uuid"

type Identity struct {
	Uid      uuid.UUID `json:"user_id"`
	Provider string    `json:"provider"`
	Sub      string    `json:"sub"`
}

const (
	ProviderApple  = "apple"
	ProviderGoogle = "google"
	// add more as needed
)
