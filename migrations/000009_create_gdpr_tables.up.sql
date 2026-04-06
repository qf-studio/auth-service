-- 000009_create_gdpr_tables.up.sql
-- Adds GDPR consent tracking, deletion requests, and user-level deletion timestamp.

-- Add deletion_requested_at to users table for grace-period tracking.
ALTER TABLE users
    ADD COLUMN deletion_requested_at TIMESTAMPTZ;

CREATE INDEX idx_users_deletion_requested_at ON users (deletion_requested_at)
    WHERE deletion_requested_at IS NOT NULL;

-- Consent records track per-user, per-type consent grants and revocations.
CREATE TABLE consent_records (
    id          TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    consent_type TEXT       NOT NULL,
    granted     BOOLEAN     NOT NULL DEFAULT FALSE,
    granted_at  TIMESTAMPTZ,
    revoked_at  TIMESTAMPTZ,
    ip_address  TEXT        NOT NULL DEFAULT '',
    user_agent  TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_consent_records_user_id ON consent_records (user_id);
CREATE INDEX idx_consent_records_user_type ON consent_records (user_id, consent_type);

-- GDPR deletion requests with grace-period workflow.
CREATE TABLE gdpr_deletion_requests (
    id              TEXT        PRIMARY KEY,
    user_id         TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    status          TEXT        NOT NULL DEFAULT 'pending',
    reason          TEXT        NOT NULL DEFAULT '',
    requested_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    scheduled_at    TIMESTAMPTZ NOT NULL,
    completed_at    TIMESTAMPTZ,
    cancelled_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT gdpr_deletion_requests_user_id_unique UNIQUE (user_id)
);

CREATE INDEX idx_gdpr_deletion_requests_status ON gdpr_deletion_requests (status)
    WHERE status = 'pending';
CREATE INDEX idx_gdpr_deletion_requests_scheduled ON gdpr_deletion_requests (scheduled_at)
    WHERE status = 'pending';
