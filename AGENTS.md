## Auth Service

Small Go service for third-party sign-in (currently Apple via a provider adapter), session issuance/refresh, and user persistence in Postgres. It issues RS256 JWT access/refresh tokens, publishes JWKS and OpenID discovery metadata, and stores hashed refresh tokens plus (provider, sub) identity mappings.

## Change Guidelines

- Update this file whenever functionality is added, changed, or removed.
- Run `go test ./...` after making changes and ensure tests pass before delivering.
