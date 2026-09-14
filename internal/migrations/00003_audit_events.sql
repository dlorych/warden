-- +goose Up
CREATE TABLE IF NOT EXISTS audit_events (
    id bigserial PRIMARY KEY,
    occurred_at timestamptz NOT NULL,
    schema_version integer NOT NULL CHECK (schema_version > 0),
    operation_id uuid NOT NULL,
    request_id uuid NOT NULL,
    actor_id text NOT NULL DEFAULT '',
    actor_name text NOT NULL DEFAULT '',
    actor_type text NOT NULL CHECK (actor_type IN ('user', 'webhook', 'system', 'service', 'anonymous')),
    actor_roles jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(actor_roles) = 'array'),
    action_code text NOT NULL CHECK (btrim(action_code) <> ''),
    outcome text NOT NULL CHECK (outcome IN ('started', 'success', 'unauthenticated', 'denied', 'invalid', 'failed')),
    auth_method text NOT NULL DEFAULT '',
    permission text NOT NULL DEFAULT '',
    policy_version text NOT NULL DEFAULT '',
    reason text NOT NULL DEFAULT '',
    resource_type text NOT NULL DEFAULT '',
    resource_id text NOT NULL DEFAULT '',
    ip_address text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT '',
    route text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS audit_events_newest_idx ON audit_events(occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_action_idx ON audit_events(action_code, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_outcome_idx ON audit_events(outcome, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON audit_events(actor_id, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_resource_idx ON audit_events(resource_type, resource_id, occurred_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS audit_events_operation_idx ON audit_events(operation_id);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION reject_audit_event_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_event_mutation();
DROP TRIGGER IF EXISTS audit_events_no_truncate ON audit_events;
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_audit_event_mutation();

REVOKE ALL PRIVILEGES ON audit_events, audit_events_id_seq FROM warden_runtime;
GRANT SELECT, INSERT ON audit_events TO warden_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO warden_runtime;

-- This is the sole deployment event. Goose applies this migration once, and
-- the guard also keeps direct/repeated execution from manufacturing activity.
INSERT INTO audit_events
    (occurred_at, schema_version, operation_id, request_id, actor_type,
     action_code, outcome, auth_method, reason, route, metadata)
SELECT
    now(), 1, '00000000-0000-4000-8000-000000000003', '00000000-0000-4000-8000-000000000004', 'system',
    'audit.initialized', 'success', 'migration', 'schema_initialized',
    'migration/00003', jsonb_build_object('schema_version', 3)
WHERE NOT EXISTS (
    SELECT 1 FROM audit_events WHERE action_code = 'audit.' || 'initialized'
);
