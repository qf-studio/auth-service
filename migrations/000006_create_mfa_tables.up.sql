-- 000006_create_mfa_tables.up.sql
-- MFA secrets and backup codes for multi-factor authentication.

CREATE TABLE IF NOT EXISTS mfa_secrets (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      TEXT        NOT NULL REFERENCES users(id),
    method       TEXT        NOT NULL DEFAULT 'totp',
    secret       TEXT        NOT NULL,
    confirmed    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, method)
);

CREATE INDEX idx_mfa_secrets_user_id ON mfa_secrets (user_id);

CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      TEXT        NOT NULL REFERENCES users(id),
    code_hash    TEXT        NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_mfa_backup_codes_user_id ON mfa_backup_codes (user_id);
