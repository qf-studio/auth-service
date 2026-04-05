-- MFA secrets: stores TOTP (and future WebAuthn) enrollment per user.
CREATE TABLE IF NOT EXISTS mfa_secrets (
    id           TEXT        PRIMARY KEY,
    user_id      TEXT        NOT NULL REFERENCES users (id),
    type         TEXT        NOT NULL DEFAULT 'totp',
    secret       TEXT        NOT NULL,
    confirmed    BOOLEAN     NOT NULL DEFAULT FALSE,
    confirmed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_mfa_secrets_user_type_active
    ON mfa_secrets (user_id, type) WHERE deleted_at IS NULL;
CREATE INDEX idx_mfa_secrets_user_id ON mfa_secrets (user_id);

-- MFA backup codes: one row per hashed code, consumed once.
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id         TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users (id),
    code_hash  TEXT        NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_backup_codes_user_id ON mfa_backup_codes (user_id);
