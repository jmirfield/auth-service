## Auth Service

Small Go service for third-party sign-in (currently Apple via a provider adapter), session issuance/refresh, and user persistence in Postgres. It issues RS256 JWT access/refresh tokens, publishes JWKS and OpenID discovery metadata, enforces a global in-memory rate limiter across endpoints, and stores hashed refresh tokens plus (provider, sub) identity mappings.

## Change Guidelines

- Update this file whenever functionality is added, changed, or removed.
- Run `go test ./...` after making changes and ensure tests pass before delivering.
- When scaling horizontally, prefer rate limiting at the load balancer or a shared store; the in-service limiter is a best-effort backstop.
