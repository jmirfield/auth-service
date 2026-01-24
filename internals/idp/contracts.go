package idp

import "context"

type Claims struct {
	Subject       string
	Issuer        string
	Email         string
	EmailVerified bool
}

type Provider interface {
	Name() string
	ProviderID() string
	ExchangeCode(ctx context.Context, code string) (string, error)
	VerifyIDToken(ctx context.Context, idToken string, nonce string) (*Claims, error)
}
