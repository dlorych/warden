# Audit Log operations

The Audit Log is retained indefinitely for the current MVP. Audit Events are
immutable: the `warden_runtime` database login has only `SELECT` and `INSERT`
on `audit_events`, and database triggers reject update, delete, and truncate.
Database administrators are trusted operators. A retention or erasure policy
must be approved separately and must not be implemented as routine cleanup.

## Monitoring queries

Run these queries as a read-only monitoring role or a database administrator.
They inspect metadata and counts only; they do not change Audit Events.

```sql
-- Current row count and oldest/newest retained event.
SELECT count(*) AS audit_event_count,
       min(occurred_at) AS oldest_event,
       max(occurred_at) AS newest_event
FROM audit_events;

-- Table, indexes, and total footprint.
SELECT pg_size_pretty(pg_relation_size('public.audit_events')) AS table_size,
       pg_size_pretty(pg_indexes_size('public.audit_events')) AS index_size,
       pg_size_pretty(pg_total_relation_size('public.audit_events')) AS total_size;

-- Daily volume for growth and external-lifecycle retry review.
SELECT date_trunc('day', occurred_at AT TIME ZONE 'UTC') AS utc_day,
       count(*) AS events,
       count(*) FILTER (WHERE outcome = 'started') AS started_events,
       count(*) FILTER (WHERE outcome = 'failed') AS failed_events
FROM audit_events
GROUP BY 1
ORDER BY 1 DESC
LIMIT 90;

-- Started external attempts without a terminal event. operation_id is the
-- stable logical operation across retries, so attempt and phase metadata are
-- part of the correlation key; a later successful retry must not hide an
-- earlier started-only attempt.
SELECT started.operation_id,
       started.resource_id,
       started.metadata->>'logical_operation_id' AS logical_operation_id,
       started.metadata->>'job_id' AS job_id,
       started.metadata->>'attempt' AS attempt,
       started.metadata->>'phase' AS phase,
       started.occurred_at AS started_at
FROM audit_events started
WHERE started.outcome = 'started'
  AND NOT EXISTS (
      SELECT 1 FROM audit_events terminal
      WHERE terminal.operation_id = started.operation_id
        AND terminal.outcome IN ('success', 'failed')
        AND terminal.metadata->>'job_id' = started.metadata->>'job_id'
        AND terminal.metadata->>'attempt' = started.metadata->>'attempt'
        AND terminal.metadata->>'phase' = started.metadata->>'phase'
  )
ORDER BY started.occurred_at;
```

Review partitioning before the table reaches **10 million Audit Events or
50 GiB total size**, whichever comes first, and review sooner if the daily
volume query or index maintenance becomes operationally expensive. A future
partitioning migration must preserve the append-only trigger/privilege
contract, retain all existing partitions indefinitely, and keep the bounded
keyset query behavior. Threshold review is not permission to delete or
truncate old partitions.

## Migration and startup workflow

Schema changes are owned by `warden_migrator`, never by the long-running
`warden_runtime` login. Add a forward-only Goose migration under
`internal/migrations`, update `CurrentVersion`, extend migration tests, and
run the one-shot migrator before starting Warden:

```sh
./devinit
docker compose --env-file .dev/compose.env -f compose.yaml run --rm migrate
docker compose --env-file .dev/compose.env -f compose.yaml up -d warden
```

Compose already expresses this as a prerequisite, and a future Kubernetes
deployment should use an init container. Re-running `migrate` is safe and
must leave the sole `audit.initialized` deployment event unchanged. Warden
checks `goose_db_version` at startup and refuses to serve when it is below the
embedded migration version. `make final-check` verifies a fresh isolated
upgrade, repeat execution, exactly one initialization event, refusal below
version 3, and successful schema-gated restart without resetting local data;
the disposable verification database is dropped by name and the main Audit
Log is never used as a migration fixture.
