-- The admin connection is used only for this bootstrap step. Goose owns
-- schema changes; the application receives a separate, DML-only login.
SELECT format('CREATE ROLE warden_migrator LOGIN PASSWORD %L', :'migrator_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_migrator')\gexec
SELECT format('CREATE ROLE warden_runtime LOGIN PASSWORD %L', :'runtime_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'warden_runtime')\gexec

ALTER ROLE warden_migrator LOGIN PASSWORD :'migrator_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE warden_runtime LOGIN PASSWORD :'runtime_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;

GRANT CONNECT ON DATABASE warden TO warden_migrator, warden_runtime;
-- Existing development databases were created by the original warden login.
-- Transfer only the baseline objects so the migration login can safely adopt
-- them without inheriting the admin login's privileges.
REVOKE warden FROM warden_migrator;
DO $$
DECLARE
    object_name text;
BEGIN
    FOREACH object_name IN ARRAY ARRAY[
        'requests', 'decisions', 'sessions', 'oauth_states', 'jobs',
        'challenges', 'audit_events', 'goose_db_version'
    ] LOOP
        IF to_regclass(format('public.%I', object_name)) IS NOT NULL THEN
            EXECUTE format('ALTER TABLE public.%I OWNER TO warden_migrator', object_name);
        END IF;
    END LOOP;
    IF to_regclass('public.audit_events_id_seq') IS NOT NULL THEN
        ALTER SEQUENCE public.audit_events_id_seq OWNER TO warden_migrator;
    END IF;
END
$$;
GRANT USAGE, CREATE ON SCHEMA public TO warden_migrator;
REVOKE ALL ON DATABASE warden FROM warden_runtime;
GRANT CONNECT ON DATABASE warden TO warden_runtime;
-- TEMPORARY is granted to PUBLIC by default, so revoking only direct
-- privileges from the runtime role would still leave it with database DDL.
-- Neither the application nor Goose needs temporary database objects.
REVOKE TEMPORARY ON DATABASE warden FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM warden_runtime;
GRANT USAGE ON SCHEMA public TO warden_runtime;
