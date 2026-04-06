DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS password_policies;
ALTER TABLE users DROP COLUMN IF EXISTS force_password_change;
ALTER TABLE users DROP COLUMN IF EXISTS password_changed_at;
