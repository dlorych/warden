# Operate indefinite Audit Log retention for the MVP

Warden retains Audit Events indefinitely for the current MVP and provides
count, age, daily-volume, footprint, and indeterminate-external-operation
queries for operators. Partitioning is not introduced pre-emptively; the
documented review threshold is 10 million events or 50 GiB total table and
index size. Any later partitioning or retention decision must preserve the
append-only contract and be recorded as a new architectural decision.

The final acceptance gate is executable and additive. It reuses the real
Keycloak, signed GitHub mock webhook, Reviewer certificate, Rekor inclusion
proof, and separate database roles. It never drops volumes or removes Audit
Events from the main retained Audit Log to make a run repeatable; it drops
only the explicitly generated isolated migration-verification database.
