-- 000023_audit_logs_user_agent.up.sql
-- Persisting audit events (GH-527) records the caller's user agent next to the IP.
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT '';
