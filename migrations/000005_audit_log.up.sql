-- 000005_audit_log.up.sql
-- Creates the append-only audit_logs table for NIST SP 800-53 AU-2/AU-3 compliance.
-- This table is INSERT-only: no UPDATE or DELETE operations are permitted.

CREATE TYPE audit_outcome AS ENUM ('success', 'failure', 'denied');

CREATE TABLE audit_logs (
    id              TEXT            PRIMARY KEY,
    event_type      TEXT            NOT NULL,
    outcome         audit_outcome   NOT NULL,
    occurred_at     TIMESTAMPTZ     NOT NULL,
    subject_id      TEXT            NOT NULL DEFAULT '',
    subject_type    TEXT            NOT NULL DEFAULT '',
    resource_type   TEXT            NOT NULL DEFAULT '',
    resource_id     TEXT            NOT NULL DEFAULT '',
    action          TEXT            NOT NULL DEFAULT '',
    source_ip       TEXT            NOT NULL DEFAULT '',
    user_agent      TEXT            NOT NULL DEFAULT '',
    correlation_id  TEXT            NOT NULL DEFAULT '',
    component       TEXT            NOT NULL DEFAULT '',
    metadata        JSONB           NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
);

-- Primary query patterns: filter by event type, subject, time range.
CREATE INDEX idx_audit_logs_event_type ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_subject_id ON audit_logs (subject_id) WHERE subject_id != '';
CREATE INDEX idx_audit_logs_occurred_at ON audit_logs (occurred_at);
CREATE INDEX idx_audit_logs_correlation_id ON audit_logs (correlation_id) WHERE correlation_id != '';
CREATE INDEX idx_audit_logs_resource ON audit_logs (resource_type, resource_id) WHERE resource_id != '';

-- Revoke UPDATE and DELETE on audit_logs for the application role.
-- This enforces append-only semantics at the database level.
-- NOTE: Adjust 'auth_app' to match the application's PostgreSQL role.
-- REVOKE UPDATE, DELETE ON audit_logs FROM auth_app;
