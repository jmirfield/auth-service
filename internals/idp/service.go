package idp

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jmirfield/auth-service/internals/domain/user"
	"github.com/jmirfield/auth-service/internals/repository"
	"github.com/jmirfield/auth-service/internals/secret"
	"github.com/jmirfield/auth-service/pkg/session"
)

var (
	ErrUnknownProvider = errors.New("unknown provider")
	ErrBadCode         = errors.New("bad code")
	ErrInvalidToken    = errors.New("invalid token")
)

type Service struct {
	registry *Registry
	session  session.SessionManager
	repo     repository.UserReadWriter
}

func NewService(registry *Registry, sessionMgr session.SessionManager, repo repository.UserReadWriter) (*Service, error) {
	if registry == nil {
		return nil, errors.New("missing provider registry")
	}
	if sessionMgr == nil {
		return nil, errors.New("missing session manager")
	}
	if repo == nil {
		return nil, errors.New("missing user repository")
	}

	return &Service{
		registry: registry,
		session:  sessionMgr,
		repo:     repo,
	}, nil
}

func (s *Service) Auth(ctx context.Context, providerName, code, nonce string) (string, string, error) {
	p, ok := s.registry.Get(providerName)
	if !ok {
		return "", "", ErrUnknownProvider
	}

	idToken, err := p.ExchangeCode(ctx, code)
	if err != nil {
		return "", "", ErrBadCode
	}

	claims, err := p.VerifyIDToken(ctx, idToken, nonce)
	if err != nil || claims == nil || claims.Subject == "" {
		return "", "", ErrInvalidToken
	}

	ident, err := s.repo.GetIdentity(ctx, p.ProviderID(), claims.Subject)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return "", "", err
	}

	var uid uuid.UUID
	if ident == nil {
		err := s.repo.WithTx(ctx, func(tctx context.Context, rw repository.UserTx) error {
			if err := rw.AdvisoryLockIdentity(tctx, p.ProviderID(), claims.Subject); err != nil {
				return err
			}

			if id2, err := rw.GetIdentity(tctx, p.ProviderID(), claims.Subject); err == nil {
				uid = id2.Uid
				return nil
			}

			usr := &user.User{
				ID: uuid.New(),
			}

			if err := rw.UpsertUser(tctx, usr); err != nil {
				return err
			}

			if err := rw.UpsertIdentity(tctx, &user.Identity{
				Uid:      usr.ID,
				Provider: p.ProviderID(),
				Sub:      claims.Subject,
			}); err != nil {
				return err
			}

			uid = usr.ID
			return nil
		})
		if err != nil {
			return "", "", err
		}
	} else {
		uid = ident.Uid
	}

	appAccess, appRefresh, err := s.session.IssuePair(ctx, uid, nil)
	if err != nil {
		return "", "", err
	}

	rClaims, err := s.session.ParseRefresh(ctx, appRefresh)
	if err != nil {
		return "", "", err
	}

	if rClaims.Subject != uid.String() {
		return "", "", ErrInvalidToken
	}

	jti, err := uuid.Parse(rClaims.ID)
	if err != nil {
		return "", "", err
	}

	if err := s.repo.InsertRefreshToken(ctx, &user.RefreshToken{
		Uid:       uid,
		Hash:      secret.Hash(appRefresh),
		Jti:       jti,
		ExpiresAt: rClaims.ExpiresAt.Time,
	}); err != nil {
		return "", "", err
	}

	return appAccess, appRefresh, nil
}
