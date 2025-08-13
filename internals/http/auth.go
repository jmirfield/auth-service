package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/jmirfield/auth-service/internals/session"
)

type ctxKey string

const userIDCtxKey ctxKey = "session_user_id"

type Auth struct {
	m *session.Manager
}

func NewAuth(mgr *session.Manager) *Auth {
	return &Auth{m: mgr}
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if raw == "" {
			Error(w, http.StatusUnauthorized, "missing authorization header")
			return
		}

		parts := strings.SplitN(raw, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			Error(w, http.StatusUnauthorized, "invalid authorization header")
			return
		}

		claims, err := a.m.ParseAccess(parts[1])
		if err != nil {
			Error(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		if claims.UserID == "" {
			Error(w, http.StatusUnauthorized, "invalid claims")
			return
		}

		ctx := context.WithValue(r.Context(), userIDCtxKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func UserIDFromContext(ctx context.Context) (string, bool) {
	uid, ok := ctx.Value(userIDCtxKey).(string)
	return uid, ok && uid != ""
}
