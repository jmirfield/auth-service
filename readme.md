# Auth Service

A small Go service that handles Sign in with Apple, session issuance/refresh, and user persistence in Postgres. It uses `pgx` for DB access, a tiny in-memory cache for JWKS, and Goose for SQL migrations.

## Contents

- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Running with Docker Compose](#running-with-docker-compose)
- [Running locally](#running-locally)
- [Migrations](#migrations)
- [API Endpoints](#api-endpoints)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

- Go 1.22+
- Docker & Docker Compose (for containerized runs)
- An Apple Sign In private key (`.p8`) associated with your Team and Key ID

## Configuration

**.env keys (dummy example):**
```dotenv
# App JWT
APP_JWT_SECRET=dev-supersecret-change-me
APP_JWT_ISSUER=auth-service
APP_JWT_AUDIENCE=auth-service-clients
APP_JWT_ACCESS_LIFETIME=15m
APP_JWT_REFRESH_LIFETIME=720h
APP_JWT_CLOCK_SKEW_LEEWAY=60s

# Apple Sign In
APPLE_TEAM_ID=AAAAAAA111
APPLE_CLIENT_ID=com.example.app
APPLE_KEY_ID=KID123ABC
APPLE_PRIVATE_KEY_PATH=./secrets/AuthKey_DEV.p8
APPLE_HTTP_TIMEOUT=5s
APPLE_JWK_CACHE_TTL=24h

# Database (choose one)
DATABASE_URL=postgres://auth_user:auth_pass@localhost:5432/auth_db?sslmode=disable
# DATABASE_URL=postgres://auth_user:auth_pass@db:5432/auth_db?sslmode=disable  # for Docker

# HTTP
PORT=3000
```

## Running with Docker Compose

1. Place your Apple private key at `./secrets/AppleKey_DEV.p8` (or adjust the path in `.env`).  
2. Ensure your `.env` has `DATABASE_URL` pointing to the **Compose host** (`db`):  
   `postgres://auth_user:auth_pass@db:5432/auth_db?sslmode=disable`
3. Start services:
   ```bash
   docker compose up --build
   ```
4. Service will listen on `http://localhost:${PORT}` (default `3000`).  
   If Adminer is included, it will be at `http://localhost:8081` (server `db`, user `auth_user`, pass `auth_pass`, db `auth_db`).

### Mounting the .p8 into the container
Example `docker-compose.yml` snippet:
```yaml
services:
  server:
    env_file: .env
    volumes:
      - ./secrets/AppleKey_DEV.p8:/run/keys/apple.p8:ro
    environment:
      APPLE_PRIVATE_KEY_PATH: /run/keys/apple.p8
```

## Running locally

1. Start Postgres on your machine (or via Docker) and ensure:
   ```
   DATABASE_URL=postgres://auth_user:auth_pass@localhost:5432/auth_db?sslmode=disable
   ```
2. Ensure the `.p8` at `APPLE_PRIVATE_KEY_PATH` exists.
3. Run the server:
   ```bash
   go run ./...
   ```


## API Endpoints

- `POST /idp/apple`  
  Exchange Apple authorization code, verify ID token, upsert user/identity, issue app tokens.  
  **Response:** `{ "access_token": "...", "refresh_token": "..." }`

- `POST /token/refresh`  
  Exchange a valid refresh token for a new pair.

- `POST /token/revoke` *(auth required)*  
  Revoke a single refresh token.

- `POST /token/revoke/all` *(auth required)*  
  Revoke all refresh tokens for the current user.

