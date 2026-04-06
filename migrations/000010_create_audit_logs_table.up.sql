-- 000010: Create audit_logs table for persisting security audit events.
-- Supports querying by actor, target, event type, and time range.

CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  TEXT        NOT NULL,
    actor_id    TEXT        NOT NULL DEFAULT '',
    target_id   TEXT        NOT NULL DEFAULT '',
    ip          TEXT        NOT NULL DEFAULT '',
    metadata    JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index for user activity timeline (all events by a given actor).
CREATE INDEX idx_audit_logs_actor_id ON audit_logs (actor_id, created_at DESC)
    WHERE actor_id != '';

-- Index for resource history (all events targeting a given entity).
CREATE INDEX idx_audit_logs_target_id ON audit_logs (target_id, created_at DESC)
    WHERE target_id != '';

-- Index for filtering by event type (e.g. security insights dashboards).
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type, created_at DESC);

-- Index for time-range scans (audit viewer pagination).
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at DESC);
