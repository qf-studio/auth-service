CREATE TABLE IF NOT EXISTS gdpr_deletion_requests (
    id            TEXT PRIMARY KEY,
    user_id       TEXT NOT NULL REFERENCES users(id),
    status        TEXT NOT NULL DEFAULT 'pending',
    reason        TEXT NOT NULL DEFAULT '',
    requested_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    scheduled_at  TIMESTAMPTZ NOT NULL,
    completed_at  TIMESTAMPTZ,
    cancelled_at  TIMESTAMPTZ,
    cancelled_by  TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_gdpr_deletion_requests_user_id ON gdpr_deletion_requests(user_id);
CREATE INDEX idx_gdpr_deletion_requests_status ON gdpr_deletion_requests(status);
CREATE INDEX idx_gdpr_deletion_requests_scheduled_at ON gdpr_deletion_requests(scheduled_at);

-- Ensure only one pending/approved deletion request per user.
CREATE UNIQUE INDEX idx_gdpr_deletion_requests_user_pending
    ON gdpr_deletion_requests(user_id)
    WHERE status IN ('pending', 'approved');
