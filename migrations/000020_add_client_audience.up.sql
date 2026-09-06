-- 000020_add_client_audience.up.sql
-- Adds a per-client aud override (GH-506): empty means the client's issued
-- access tokens inherit the service-wide JWT_AUDIENCE, non-empty replaces it.

ALTER TABLE clients ADD COLUMN audience TEXT[] NOT NULL DEFAULT '{}';
