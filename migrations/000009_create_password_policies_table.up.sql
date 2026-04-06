CREATE TABLE password_policies (
    id            TEXT        PRIMARY KEY,
    name          TEXT        NOT NULL,
    min_length    INT         NOT NULL DEFAULT 15,
    max_length    INT         NOT NULL DEFAULT 128,
    max_age_days  INT         NOT NULL DEFAULT 0,
    history_count INT         NOT NULL DEFAULT 0,
    require_mfa   BOOLEAN     NOT NULL DEFAULT FALSE,
    is_default    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ,

    CONSTRAINT password_policies_name_unique UNIQUE (name)
);

CREATE INDEX idx_password_policies_is_default ON password_policies (is_default) WHERE deleted_at IS NULL;
CREATE INDEX idx_password_policies_deleted_at ON password_policies (deleted_at) WHERE deleted_at IS NOT NULL;

-- Add password tracking columns to users table for compliance reporting.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change BOOLEAN NOT NULL DEFAULT FALSE;
