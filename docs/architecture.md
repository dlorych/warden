# Warden architecture

Warden is a small deployment approval service. A source adapter turns a
source webhook into a durable, source-neutral request; a reviewer sees that
request through the browser BFF and signs a decision with the CLI; a worker
publishes the decision to Rekor before delivering it back to the source.

## Request and decision paths

The browser BFF is a cookie session boundary. `/bff/login` and
`/bff/callback` perform the Keycloak/OIDC code flow, and `/bff/session`
returns the current user and CSRF token. Browser reads such as
`/bff/requests`, `/bff/requests/{id}`, `/bff/requests/{id}/evidence`, and
`/bff/decisions` use the HttpOnly same-origin session cookie. The BFF does not
give the browser an OIDC access token. Browser writes, including
`/bff/logout`, require the session CSRF token and origin checks.

Browser authentication and protected reads are audited at the BFF boundary.
`/bff/login` records the redirect start and operational discovery or state
failures; `/bff/callback` records the invalid, operational-failure, and success
outcomes Warden observes; and `/bff/logout` records unauthenticated, denied,
invalid, failed, and successful outcomes. Credential failures that occur
entirely inside the IdP remain the IdP's responsibility. The protected browser
list and detail reads for requests, the decision list, and protected evidence
all append immutable Audit Events under their stable Action Codes, including
missing or invalid sessions and authorization denials. Audit appends happen
before a protected payload is returned; an append failure returns `503` and no
protected payload (fail closed).

The auditor-only `/bff/audit` endpoint uses the stable `audit.read` Action
Code, bounded keyset pagination, and finite action, outcome, actor, resource,
operation, and UTC time filters. Its own successful and unsuccessful reads are
appended after selecting the result snapshot, so the event for a query appears
only on the next query. The public `GET /evidence/{request-id}` path remains
permission-free and unaudited; it exposes only an immutable bundle after
publication.

The browser polls only the active request list or request-detail view. Polling
stops when that view is inactive or the document is hidden; the Audit Log is
refreshed explicitly and never polls automatically.

`GET /evidence/{request-id}` is a public, immutable read path for the
published evidence bundle referenced by source callbacks. It is deliberately
separate from the authenticated BFF and bearer CLI APIs.

Logout has two coordinated parts. The BFF deletes its server-side session and
expires the session cookie first. It then constructs an RP-initiated logout
URL from the `end_session_endpoint` in the issuer's discovery document, using
the configured BFF client ID and fixed post-logout URL. The React client
navigates to that URL so Keycloak can clear its SSO cookie before redirecting
back to Warden. Warden does not retain an ID token merely to use as an
`id_token_hint`; Keycloak accepts the client-ID form of the request. If
discovery does not provide an end-session endpoint, local logout remains
successful and the client returns to the sign-in screen. An IdP may show a
logout confirmation page for a client-ID-only request; that is provider UI,
and the browser can complete it before returning to Warden. The redirect is
an operator-configured value and must also be allowlisted by the IdP client.

The CLI uses a separate bearer boundary. `warden decide` and `warden evidence
download` use the OIDC public `warden-cli` client, authorization-code PKCE,
the fixed loopback callback `127.0.0.1:18765`, audience `warden-cli`, and the
`warden:decide` scope. The CLI API is under `/api/v1`: it reads
`GET /requests/{id}`, obtains a one-time challenge with
`POST /requests/{id}/challenges`, submits a certificate-backed decision with
`POST /requests/{id}/decisions`, and reads evidence with
`GET /requests/{id}/evidence`. Cookies are rejected on this boundary. An
explicit `--access-token` is available for headless tests and automation; it
does not bypass bearer-token validation or application-role authorization.

The challenge statement is bound to the displayed request, request ID,
decision, reason, authenticated subject, nonce, and expiry. The CLI displays
the context, requests the exact decision/reason challenge, asks for explicit
confirmation, and signs the returned statement. The service consumes the
request-bound nonce transactionally and accepts only one winning decision.

```mermaid
sequenceDiagram
    participant GH as Source/GitHub
    participant W as Warden API
    participant DB as PostgreSQL
    participant C as Reviewer CLI
    participant R as Rekor v2
    GH->>W: signed webhook
    W->>GH: source lookup and context enrichment
    W->>DB: durable request
    C->>W: bearer GET request
    C->>W: bearer POST challenge(decision, reason)
    C->>C: display context, confirm, sign statement
    C->>W: bearer POST certificate-backed bundle
    W->>DB: consume nonce, record decision, enqueue publish job
    W->>DB: worker claims publish job
    W->>R: submit hashedrekord and verify proof/checkpoint
    W->>GH: recheck source, then deliver callback with evidence link
```

## Source boundary

The `source.Adapter` interface is the service's source boundary. Its webhook
method validates and normalizes an event, `Recheck` confirms that the source
state is still eligible before delivery, and `Deliver` sends the final
decision. The GitHub implementation performs the current webhook signature,
repository/callback, SHA, and workflow checks. The normalized event stores
source context as opaque bytes. Warden persists those bytes and passes them
back to the adapter; it does not interpret provider-specific fields in the
approval path.

Webhook ingestion audits every observed outcome under `request.add`. Before
signature verification, the actor is anonymous; after a valid HMAC, the
adapter is represented by a fixed internal `source` principal and the
default-deny authorizer records the `request.add` permission decision. Request
creation and its successful Audit Event commit in one transaction. Deterministic
request IDs make retries idempotent for the request row, while each delivery
still appends a distinct event with only bounded correlation and request-state
metadata. Payloads, signatures, provider identity fields, and source context
are never copied into audit metadata or logs.

## Identity, signing, and transparency

Keycloak is the OIDC boundary for this MVP. Enterprise SAML or Active
Directory integration belongs behind an IdP broker, so Warden continues to
consume the same issuer, audience, groups, and stable subject claims. Warden
does not contain a separate SAML or AD protocol implementation.

Decision statements use versioned canonical JSON and are signed through the
standard Go `crypto.Signer` interface. Development uses local PEM ECDSA
P-256 keys and certificates from `cmd/devinit`; the certificate URI carries
the stable OIDC subject. The seam permits an ADCS-issued certificate and a
PKCS#11/HSM-backed signer later without changing the evidence wire format.

The worker submits the canonical statement digest, signature, and certificate
as a Rekor v2 `hashedRekordRequestV002`. It persists Rekor's exact
`canonicalized_body`, inclusion path, and signed checkpoint in the evidence
bundle. Offline verification uses the independently configured checkpoint
public key and trusted checkpoint origin, verifies the signed note and
RFC6962 inclusion proof, and checks that the logged digest, signature, and
certificate are the bundle's values. Historical validity against an RFC 3161
timestamp is deliberately deferred; Rekor integrated time is not treated as
that timestamp.

The worker stores the published bundle and marks the request published before
calling the source adapter's delivery callback. A delivery retry reuses that
durable publication marker and does not submit another Rekor entry.

Worker external lifecycles are audited under the fixed internal
`warden-worker` service principal with the `worker` role. The worker sends
each authorization request through the core default-deny Authorizer and
retains its permission, policy version, and reason on the corresponding Audit
Events. Rekor publication uses `transparency.publish`; source rechecks and
delivery use `source.deliver`; request and evidence mutations are authorized
with `request.update` and `evidence.update` respectively. A denied decision,
or an unavailable Audit Log while recording that decision, prevents work.

Before every Rekor Submit, source Recheck, and source Deliver invocation, a
`started` Audit Event is committed. An observed terminal result appends a
linked `success` or `failed` event. Started and terminal events for an attempt
share a stable operation ID; retry attempts remain distinct events through
their bounded metadata (logical operation ID plus job ID, attempt, and phase).
A started-only operation is therefore queryable as indeterminate
after a process interruption. Metadata never contains evidence, source
context, tokens, callbacks, Rekor response data, or raw errors.

When Warden controls the database mutation, verified publication plus its
request/evidence state and the publication success event commit atomically.
Delivery, cancellation, and expiry status changes commit atomically with
their terminal events. Failure events are appended only after rolled-back
mutations. If a terminal Audit Event cannot be appended, the mutation rolls
back and the job remains retryable; if Rekor or a source has already accepted
the request, the external-success/DB-failure window is represented by the
started-only attempt and may cause a repeated external call on retry.

The GitHub callback comment includes a stable public URL such as
`https://warden.example/evidence/{request-id}`. The endpoint returns the exact
immutable bundle only after Rekor inclusion has been verified; pending or
missing requests return 404. The bundle contains the signed decision,
certificate chain, Rekor entry data, and inclusion proof, so an auditor can
verify it offline. The callback links to Warden's complete evidence bundle
rather than a raw Rekor URL because Rekor is the transparency anchor while
Warden's bundle binds that log entry to the request and decision in one
portable artifact. The source adapter receives the same deterministic comment
on retries.

## Durability and failure handling

PostgreSQL stores requests, decisions, challenges, sessions, and publish jobs.
Jobs are claimed under row locks with `SKIP LOCKED`; failed work is returned
to pending with bounded backoff. Before delivery, the worker rechecks the
source. A cancelled or no-longer-eligible source run is recorded as
cancelled, and a request that expires is recorded as expired. The current
worker loop is single-process; the database locking is the foundation for
adding workers later.

## Security invariants

- Source webhooks require the configured HMAC signature and source-specific
  validation before a request is stored.
- OIDC tokens are checked at the API boundary for issuer, signature, audience,
  expiry, and `warden:decide`; application roles from the `warden_roles` claim
  authorize each action with a default-deny policy.
- Browser sessions are HttpOnly and same-origin. Mutating BFF requests require
  origin validation and the session CSRF token.
- A challenge is bound to request ID, reviewer subject, decision, reason, and
  expiry; its nonce is consumed once under a transaction lock.
- A decision must match the request context digest, request ID, service,
  subject, challenge, and canonical statement signature. The certificate chain
  must terminate at configured development trust and contain the exact OIDC
  subject URI.
- Rekor verification is fail-closed without the independently configured
  checkpoint key. The logged canonicalized body is checked against the
  decision before inclusion is accepted.
- Development user private keys remain local to the CLI. Warden mounts only
  the app key, CA trust, and Rekor checkpoint public key; only the Rekor
  container mounts the Rekor signer.

## Production backlog

The following items are intentionally outside this tracer bullet:

- replace development CA material with managed certificate issuance (for
  example ADCS or Fulcio) and move signing keys to PKCS#11/HSM custody;
- configure enterprise IdP-broker federation, production group mapping, key
  rotation, and operational access controls;
- distribute Rekor trust roots through the organization's trust mechanism,
  add checkpoint witnessing/consistency monitoring, and validate trusted
  RFC 3161 timestamps historically;
- make workers and source delivery highly available, with metrics, alerting,
  durable backups, retention policy, and recovery drills;
- add production adapter registration and routing for multiple source types,
  with per-source credentials and policy configuration;
- replace the in-memory local GitHub mock with production source credentials
  and deployment policy configuration, and harden or remove its unauthenticated
  development admin routes.
