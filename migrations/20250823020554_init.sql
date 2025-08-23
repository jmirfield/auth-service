-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  attributes   JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS user_identities (
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider          TEXT NOT NULL,            
  sub               TEXT NOT NULL,                                
  PRIMARY KEY (provider, sub)
);

CREATE TABLE IF NOT EXISTS user_refresh_tokens (
  user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  jti        UUID NOT NULL,                     
  hash       TEXT NOT NULL,                     
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,                   
  PRIMARY KEY (user_id, jti)
);

CREATE INDEX IF NOT EXISTS idx_user_identities_user_id
  ON user_identities (user_id);

CREATE INDEX IF NOT EXISTS idx_user_refresh_tokens_hash
  ON user_refresh_tokens (hash);

CREATE INDEX IF NOT EXISTS idx_user_refresh_tokens_expires_at
  ON user_refresh_tokens (expires_at);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
