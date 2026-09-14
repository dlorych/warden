-- +goose Up
CREATE TABLE IF NOT EXISTS requests (
    id uuid PRIMARY KEY,
    repository text NOT NULL,
    environment text NOT NULL,
    commit_sha text NOT NULL,
    requester text NOT NULL,
    requester_subject text NOT NULL,
    context jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    decision text NOT NULL DEFAULT 'pending' CHECK (decision IN ('pending', 'approved', 'rejected')),
    reason text NOT NULL DEFAULT '',
    log_status text NOT NULL DEFAULT 'pending',
    delivery_status text NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS decisions (
    id uuid PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES requests(id),
    reviewer_subject text NOT NULL,
    reviewer_name text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reason text NOT NULL DEFAULT '',
    statement jsonb NOT NULL,
    signature text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    published_bundle jsonb,
    UNIQUE (request_id, reviewer_subject)
);
ALTER TABLE decisions ADD COLUMN IF NOT EXISTS published_bundle jsonb;

CREATE TABLE IF NOT EXISTS sessions (
    id text PRIMARY KEY,
    subject text NOT NULL,
    name text NOT NULL,
    groups_json jsonb NOT NULL DEFAULT '[]'::jsonb,
    csrf_hash text NOT NULL,
    created_at timestamptz NOT NULL,
    last_seen timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_states (
    id text PRIMARY KEY,
    state_hash text UNIQUE NOT NULL,
    verifier text NOT NULL,
    nonce_hash text NOT NULL,
    redirect_uri text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id uuid PRIMARY KEY,
    kind text NOT NULL,
    request_id uuid NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempts int NOT NULL DEFAULT 0,
    run_after timestamptz NOT NULL,
    last_error text NOT NULL DEFAULT '',
    locked_at timestamptz
);
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS locked_at timestamptz;

CREATE TABLE IF NOT EXISTS challenges (
    nonce_hash text PRIMARY KEY,
    request_id uuid NOT NULL REFERENCES requests(id),
    subject text NOT NULL,
    decision text NOT NULL,
    reason text NOT NULL DEFAULT '',
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE INDEX IF NOT EXISTS requests_created_idx ON requests(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS decisions_created_idx ON decisions(created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS jobs_due_idx ON jobs(status, run_after);

REVOKE ALL PRIVILEGES ON requests, decisions, sessions, oauth_states, jobs, challenges, goose_db_version FROM warden_runtime;
GRANT SELECT, INSERT, UPDATE ON requests TO warden_runtime;
GRANT SELECT, INSERT, UPDATE ON decisions TO warden_runtime;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO warden_runtime;
GRANT SELECT, INSERT, DELETE ON oauth_states TO warden_runtime;
GRANT SELECT, INSERT, UPDATE ON jobs TO warden_runtime;
GRANT SELECT, INSERT, UPDATE ON challenges TO warden_runtime;
GRANT SELECT ON goose_db_version TO warden_runtime;

-- Keep the application role useful for DML while preventing it from changing
-- the schema or acquiring privileges through the public schema.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM warden_runtime;
GRANT USAGE ON SCHEMA public TO warden_runtime;
