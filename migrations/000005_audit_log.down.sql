-- 000005_audit_log.down.sql
-- Drops the audit_logs table and audit_outcome enum type.

DROP TABLE IF EXISTS audit_logs;
DROP TYPE IF EXISTS audit_outcome;
