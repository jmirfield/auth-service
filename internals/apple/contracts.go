package apple

import (
	"context"
)

type AppleManager interface {
	ExchangeCode(ctx context.Context, code string) (*TokenResponse, error)
	Refresh(ctx context.Context, tok string) (*TokenResponse, error)
	VerifyIDToken(ctx context.Context, tok string, nonce ...string) (*Claims, error)
}
