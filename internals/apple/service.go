package apple

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
	ErrBadCode      = errors.New("bad code")
	ErrInvalidToken = errors.New("invalid token")
)

type Service struct {
	mgr     AppleManager
	session session.SessionManager
	repo    repository.UserReadWriter
}

func NewService(mgr AppleManager, session session.SessionManager, repo repository.UserReadWriter) (*Service, error) {
	if mgr == nil {
		return nil, errors.New("missing apple manager")
	}
	if session == nil {
		return nil, errors.New("missing session manager")
	}
	if repo == nil {
		return nil, errors.New("missing user repository")
	}

	return &Service{
		mgr:     mgr,
		session: session,
		repo:    repo,
	}, nil
}

func (s *Service) Auth(ctx context.Context, code string, nonce string) (string, string, error) {
	tok, err := s.mgr.ExchangeCode(ctx, code)
	if err != nil {
		return "", "", ErrBadCode
	}

	var claims *Claims
	claims, err = s.mgr.VerifyIDToken(ctx, tok.IDToken, nonce)
	if err != nil {
		return "", "", ErrInvalidToken
	}

	ident, err := s.repo.GetIdentity(ctx, user.ProviderApple, claims.Subject)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return "", "", err
	}

	var uid uuid.UUID
	if ident == nil {
		err := s.repo.WithTx(ctx, func(tctx context.Context, rw repository.UserTx) error {
			if err := rw.AdvisoryLockIdentity(tctx, user.ProviderApple, claims.Subject); err != nil {
				return err
			}

			if id2, err := rw.GetIdentity(tctx, user.ProviderApple, claims.Subject); err == nil {
				uid = id2.Uid
				return nil
			}

			usr := &user.User{
				ID: uuid.New(),
			}

			err := rw.UpsertUser(tctx, usr)
			if err != nil {
				return err
			}

			if err := rw.UpsertIdentity(tctx, &user.Identity{
				Uid:      usr.ID,
				Provider: user.ProviderApple,
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
