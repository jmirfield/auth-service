package idp

import (
	"context"
	"errors"

	applex "github.com/jmirfield/auth-service/internals/apple"
	"github.com/jmirfield/auth-service/internals/domain/user"
)

type AppleProvider struct {
	mgr applex.AppleManager
}

func NewAppleProvider(mgr applex.AppleManager) (*AppleProvider, error) {
	if mgr == nil {
		return nil, errors.New("missing apple manager")
	}
	return &AppleProvider{mgr: mgr}, nil
}

func (p *AppleProvider) Name() string {
	return "apple"
}

func (p *AppleProvider) ProviderID() string {
	return user.ProviderApple
}

func (p *AppleProvider) ExchangeCode(ctx context.Context, code string) (string, error) {
	tok, err := p.mgr.ExchangeCode(ctx, code)
	if err != nil {
		return "", err
	}
	return tok.IDToken, nil
}

func (p *AppleProvider) VerifyIDToken(ctx context.Context, idToken string, nonce string) (*Claims, error) {
	claims, err := p.mgr.VerifyIDToken(ctx, idToken, nonce)
	if err != nil {
		return nil, err
	}

	return &Claims{
		Subject: claims.Subject,
		Issuer:  claims.Issuer,
	}, nil
}
