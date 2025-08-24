package session

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jmirfield/auth-service/internals/domain/user"
	"github.com/jmirfield/auth-service/internals/repository"
	"github.com/jmirfield/auth-service/internals/secret"
	"github.com/jmirfield/auth-service/pkg/session"
)

var ErrInvalidToken = errors.New("invalid token")
var ErrUserNotFound = errors.New("user not found")

type Service struct {
	repo repository.UserReadWriter
	mgr  session.SessionManager
}

func NewService(repo repository.UserReadWriter, mgr session.SessionManager) (*Service, error) {
	if repo == nil {
		return nil, errors.New("missing user repository")
	}
	if mgr == nil {
		return nil, errors.New("missing session manager")
	}
	return &Service{repo: repo, mgr: mgr}, nil
}

func (s *Service) Refresh(ctx context.Context, token string, rotate bool) (string, string, error) {
	claims, err := s.mgr.ParseRefresh(ctx, token)
	if err != nil {
		return "", "", ErrInvalidToken
	}

	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return "", "", err
	}

	_, err = s.repo.GetUser(ctx, uid)
	if err != nil {
		return "", "", ErrInvalidToken
	}

	tok, err := s.repo.FindRefreshTokenByHash(ctx, uid, secret.Hash(token))
	if err != nil {
		return "", "", ErrInvalidToken
	}

	newAccess, newRefresh, err := s.mgr.RefreshFrom(ctx, token, nil, rotate)
	if err != nil {
		return "", "", err
	}

	if newRefresh != "" {
		err := s.repo.WithTx(ctx, func(ctx context.Context, rw repository.UserTx) error {
			_, err := rw.DeleteRefreshToken(ctx, uid, tok.Jti)
			if err != nil {
				return err
			}

			rClaims, err := s.mgr.ParseRefresh(ctx, newRefresh)
			if err != nil {
				return err
			}

			jti, err := uuid.Parse(rClaims.ID)
			if err != nil {
				return err
			}

			err = rw.InsertRefreshToken(ctx, &user.RefreshToken{
				Uid:       uid,
				Jti:       jti,
				Hash:      secret.Hash(newRefresh),
				ExpiresAt: rClaims.ExpiresAt.Time,
			})
			if err != nil {
				return err
			}
			return nil
		})

		if err != nil {
			return "", "", err
		}
	}

	return newAccess, newRefresh, nil
}

func (s *Service) RevokeSingle(ctx context.Context, uid uuid.UUID, token string) error {
	claims, err := s.mgr.ParseRefresh(ctx, token)
	if err != nil {
		return ErrInvalidToken
	}

	if claims.Subject != uid.String() {
		return ErrInvalidToken
	}

	tokenID, err := uuid.Parse(claims.ID)
	if err != nil {
		return err
	}

	_, err = s.repo.DeleteRefreshToken(ctx, uid, tokenID)
	if err != nil {
		return err
	}

	return nil
}

func (s *Service) RevokeAll(ctx context.Context, uid uuid.UUID) error {
	_, err := s.repo.DeleteAllRefreshTokens(ctx, uid)
	if err != nil {
		return err
	}
	return nil
}
