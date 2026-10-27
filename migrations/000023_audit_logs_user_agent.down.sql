-- 000023_audit_logs_user_agent.down.sql
ALTER TABLE audit_logs DROP COLUMN IF EXISTS user_agent;
