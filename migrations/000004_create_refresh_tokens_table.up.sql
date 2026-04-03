-- 000004_create_refresh_tokens_table.up.sql
-- Creates the refresh_tokens table for storing token signatures (never full tokens).

CREATE TABLE refresh_tokens (
    signature  TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users (id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens (expires_at) WHERE revoked_at IS NULL;
