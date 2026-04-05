-- 000005_create_api_keys.down.sql
-- Drops the api_keys table and related types.

DROP TABLE IF EXISTS api_keys;
DROP TYPE IF EXISTS api_key_status;
