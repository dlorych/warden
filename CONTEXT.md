# Warden

Warden governs deployment approval requests, signed decisions, and the evidence needed to verify them. It also records access to and changes within that approval process.

## Language

**Protected Resource**:
A deployment request, decision, evidence bundle, or Audit Log whose access is controlled by Warden.

**Audit Event**:
An immutable record of one attempted semantic action, its actor when known, and its outcome.
_Avoid_: Audit entry, activity record

**Audit Log**:
The ordered, append-only collection of Audit Events retained by Warden.
_Avoid_: Activity log

**Auditor**:
An identity authorized to inspect the Audit Log, without thereby receiving access to the protected resources described by its events.

**Reader**:
An identity authorized to inspect deployment requests, decisions, and protected evidence.

**Reviewer**:
An identity authorized to prepare and add deployment decisions. A Reviewer is also a Reader.

**Action Code**:
A stable name identifying the semantic action represented by an Audit Event.
_Avoid_: Event type, operation name

**Audit Event outcome**:
The observed result of an attempted semantic action: `started`, `success`,
`unauthenticated`, `denied`, `invalid`, or `failed`. A `started` event without
a terminal event is an indeterminate external operation and remains queryable.

**External lifecycle**:
The worker phases that cross a Warden boundary: transparency publication,
source recheck, and source delivery. Each phase has linked `started` and
terminal Audit Events under its stable Action Code.
