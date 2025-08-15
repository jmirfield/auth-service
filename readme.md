# Auth Service (Go)

A small Go service for handling **Sign in with Apple** on the backend, verifying Apple ID tokens, storing minimal provider data, and issuing **your own JWT access & refresh tokens**. Includes endpoints for refreshing and revoking sessions, and an authentication middleware for protecting APIs.

---

## Features

- Exchange Apple authorization code for tokens.
- Store Apple refresh token securely.
- Issue your own **short-lived access** and **long-lived refresh** JWTs.
- Refresh and revoke sessions.
- Middleware for access token validation.

---

## Requirements

- Go 1.21+
- Apple Sign In credentials:
  - **Team ID**
  - **Key ID**
  - **Service ID** or **Bundle ID**
  - **Private key (.p8)**
- 32+ byte JWT signing secret.

---

## Environment Variables

```env
# APPLE CONFIG
APPLE_TEAM_ID=YOUR_TEAM_ID
APPLE_CLIENT_ID=com.example.serviceid.or.bundleid
APPLE_KEY_ID=ABC123DEF
APPLE_PRIVATE_KEY_PATH=./AuthKey_ABC123DEF.p8

# JWT Config
APP_JWT_SECRET=supersecretkey_that_is_32+_bytes
APP_JWT_ISSUER=auth-service
APP_JWT_AUDIENCE=your-mobile-app
APP_JWT_ACCESS_LIFETIME=15m
APP_JWT_REFRESH_LIFETIME=720h
APP_JWT_CLOCK_SKEW_LEEWAY=60s

# SECRETS CONFIG
SECRET_ENC_KEY=akojrJmt29/0yT5RQ3SXihF1q0k0qYqUDg7WusrzBL0= <- Must be 32 bytes b64
SECRET_PREFIX=my-app

# Server
PORT=3000
```

## TODO
- CI/CD Builds 