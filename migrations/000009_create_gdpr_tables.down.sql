-- 000009_create_gdpr_tables.down.sql
-- Removes GDPR tables and user-level deletion_requested_at column.

DROP TABLE IF EXISTS gdpr_deletion_requests;
DROP TABLE IF EXISTS consent_records;

DROP INDEX IF EXISTS idx_users_deletion_requested_at;

ALTER TABLE users
    DROP COLUMN IF EXISTS deletion_requested_at;
