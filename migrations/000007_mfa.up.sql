-- 000007_mfa.up.sql
-- Creates MFA secrets and backup codes tables for multi-factor authentication.

CREATE TABLE mfa_secrets (
    id               TEXT        PRIMARY KEY,
    user_id          TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_secret TEXT        NOT NULL,
    algorithm        TEXT        NOT NULL DEFAULT 'SHA1',
    digits           INTEGER     NOT NULL DEFAULT 6,
    period           INTEGER     NOT NULL DEFAULT 30,
    confirmed        BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT mfa_secrets_user_unique UNIQUE (user_id)
);

CREATE INDEX idx_mfa_secrets_user_id ON mfa_secrets (user_id);

CREATE TABLE backup_codes (
    id         TEXT        PRIMARY KEY,
    user_id    TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT        NOT NULL,
    used       BOOLEAN     NOT NULL DEFAULT FALSE,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_backup_codes_user_id ON backup_codes (user_id);
CREATE INDEX idx_backup_codes_unused ON backup_codes (user_id) WHERE used = FALSE;
