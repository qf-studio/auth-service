-- OAuth accounts: links external provider identities to local users.
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id               TEXT        PRIMARY KEY,
    user_id          TEXT        NOT NULL REFERENCES users (id),
    provider         TEXT        NOT NULL,
    provider_user_id TEXT        NOT NULL,
    email            TEXT        NOT NULL DEFAULT '',
    access_token     TEXT        NOT NULL DEFAULT '',
    refresh_token    TEXT        NOT NULL DEFAULT '',
    token_expires_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT oauth_accounts_provider_user_unique UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts (user_id);
CREATE INDEX idx_oauth_accounts_provider ON oauth_accounts (provider);
