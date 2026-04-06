CREATE TABLE IF NOT EXISTS audit_logs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type  VARCHAR(100) NOT NULL,
    actor_id    VARCHAR(255) NOT NULL DEFAULT '',
    target_id   VARCHAR(255) NOT NULL DEFAULT '',
    ip          VARCHAR(45)  NOT NULL DEFAULT '',
    severity    VARCHAR(20)  NOT NULL DEFAULT 'info',
    metadata    JSONB        NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_actor_id   ON audit_logs (actor_id) WHERE actor_id != '';
CREATE INDEX idx_audit_logs_target_id  ON audit_logs (target_id) WHERE target_id != '';
CREATE INDEX idx_audit_logs_created_at ON audit_logs (created_at);
CREATE INDEX idx_audit_logs_severity   ON audit_logs (severity);
