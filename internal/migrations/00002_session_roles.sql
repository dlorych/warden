-- +goose Up
-- Rows already in sessions predate application roles. The nullable phase lets
-- the migration identify and invalidate only those legacy browser sessions.
-- New sessions are created with an explicit roles array, so replaying this
-- migration does not invalidate sessions created after the upgrade.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS roles_json jsonb;
DELETE FROM sessions WHERE roles_json IS NULL;
ALTER TABLE sessions ALTER COLUMN roles_json SET DEFAULT '[]'::jsonb;
ALTER TABLE sessions ALTER COLUMN roles_json SET NOT NULL;
