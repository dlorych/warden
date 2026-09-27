package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/authz"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

type decisionTx interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Commit(context.Context) error
	Rollback(context.Context) error
}

// AuditAppendError marks an error from an audit append attempted inside a
// business transaction. Unwrap preserves the underlying database or
// validation error for callers that need to inspect its cause.
type AuditAppendError struct{ Err error }

func (e *AuditAppendError) Error() string {
	if e == nil || e.Err == nil {
		return "audit append failed"
	}
	return fmt.Sprintf("audit append failed: %v", e.Err)
}

func (e *AuditAppendError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (*AuditAppendError) AuditAppendFailure() bool { return true }

type Store struct {
	db              *pgxpool.Pool
	beginDecisionTx func(context.Context) (decisionTx, error)
}

func New(db *pgxpool.Pool) *Store {
	return &Store{
		db: db,
		beginDecisionTx: func(ctx context.Context) (decisionTx, error) {
			return db.Begin(ctx)
		},
	}
}

// beginAuthTx is kept as a seam for authentication lifecycle tests. The same
// transaction shape is used by decision/challenge mutations.
func (s *Store) beginAuthTx(ctx context.Context) (decisionTx, error) {
	if s.beginDecisionTx != nil {
		return s.beginDecisionTx(ctx)
	}
	return s.db.Begin(ctx)
}

// AppendAuditEvent is the only write operation exposed for Audit Events. The
// database role and trigger enforce the same append-only guarantee below the
// application boundary.
func (s *Store) AppendAuditEvent(ctx context.Context, event audit.Event) error {
	return appendAuditEvent(ctx, s.db, event)
}

type execer interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func appendAuditEvent(ctx context.Context, db execer, event audit.Event) error {
	if event.SchemaVersion == 0 {
		event.SchemaVersion = audit.EventSchemaVersion
	}
	if event.OperationID == "" {
		event.OperationID = uuid.NewString()
	}
	if event.RequestID == "" {
		event.RequestID = uuid.NewString()
	}
	if event.OccurredAt.IsZero() {
		event.OccurredAt = time.Now().UTC()
	}
	if event.Metadata == nil {
		event.Metadata = json.RawMessage(`{}`)
	}
	if !json.Valid(event.Metadata) || len(event.Metadata) > 16<<10 {
		return fmt.Errorf("audit metadata must be valid JSON no larger than 16 KiB")
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(event.Metadata, &metadata); err != nil || metadata == nil {
		return fmt.Errorf("audit metadata must be a JSON object")
	}
	if len(event.UserAgent) > 512 {
		event.UserAgent = truncateUTF8(event.UserAgent, 512)
	}
	if _, err := uuid.Parse(event.OperationID); err != nil {
		return fmt.Errorf("audit operation ID: %w", err)
	}
	if _, err := uuid.Parse(event.RequestID); err != nil {
		return fmt.Errorf("audit request ID: %w", err)
	}
	rolesValue := event.ActorRoles
	if rolesValue == nil {
		rolesValue = []string{}
	}
	roles, err := json.Marshal(rolesValue)
	if err != nil {
		return fmt.Errorf("audit actor roles: %w", err)
	}
	_, err = db.Exec(ctx, `INSERT INTO audit_events
		(occurred_at,schema_version,operation_id,request_id,actor_id,actor_name,actor_type,actor_roles,
		 action_code,outcome,auth_method,permission,policy_version,reason,resource_type,resource_id,
		 ip_address,user_agent,route,metadata)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		event.OccurredAt.UTC(), event.SchemaVersion, event.OperationID, event.RequestID,
		event.ActorID, event.ActorName, event.ActorType, roles, event.ActionCode, event.Outcome,
		event.AuthMethod, event.Permission, event.PolicyVersion, event.Reason, event.ResourceType,
		event.ResourceID, event.IPAddress, event.UserAgent, event.Route, event.Metadata)
	return err
}

func truncateUTF8(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

type auditCursor struct {
	OccurredAt time.Time `json:"t"`
	ID         int64     `json:"i"`
}

func decodeAuditCursor(raw string) (auditCursor, error) {
	if raw == "" {
		return auditCursor{}, nil
	}
	if len(raw) > 512 {
		return auditCursor{}, fmt.Errorf("audit cursor is too long")
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return auditCursor{}, fmt.Errorf("invalid audit cursor")
	}
	var c auditCursor
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&c); err != nil || decoder.Decode(&struct{}{}) != io.EOF || c.ID < 1 || c.OccurredAt.IsZero() {
		return auditCursor{}, fmt.Errorf("invalid audit cursor")
	}
	return c, nil
}

// ValidateAuditCursor checks a client-provided keyset cursor without querying
// the database. HTTP handlers use this to classify malformed cursors as bad
// requests rather than database/read failures.
func ValidateAuditCursor(raw string) error {
	_, err := decodeAuditCursor(raw)
	return err
}

func encodeAuditCursor(c auditCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ListAuditEvents uses a deterministic newest-first keyset. It deliberately
// accepts only the finite filter set in audit.Query; arbitrary JSON metadata
// predicates are not part of the read API.
func (s *Store) ListAuditEvents(ctx context.Context, q audit.Query) (audit.Page, error) {
	if q.Limit < 1 {
		q.Limit = 50
	}
	if q.Limit > 100 {
		return audit.Page{}, fmt.Errorf("audit page size exceeds maximum")
	}
	cursor, err := decodeAuditCursor(q.Cursor)
	if err != nil {
		return audit.Page{}, err
	}
	var operation any
	if strings.TrimSpace(q.OperationID) != "" {
		if _, err = uuid.Parse(q.OperationID); err != nil {
			return audit.Page{}, fmt.Errorf("invalid operation ID")
		}
		operation = q.OperationID
	} else {
		// Keep the absent value NULL: casting an empty string to uuid would
		// fail before PostgreSQL can evaluate the OR predicate.
		operation = nil
	}
	var cursorTime any = nil
	var cursorID any = nil
	if !cursor.OccurredAt.IsZero() {
		cursorTime, cursorID = cursor.OccurredAt, cursor.ID
	}
	rows, err := s.db.Query(ctx, `SELECT id,occurred_at,schema_version,operation_id,request_id,
		actor_id,actor_name,actor_type,actor_roles,action_code,outcome,auth_method,permission,
		policy_version,reason,resource_type,resource_id,ip_address,user_agent,route,metadata
		FROM audit_events
		WHERE ($1::timestamptz IS NULL OR (occurred_at,id) < ($1,$2))
		  AND ($3='' OR action_code=$3) AND ($4='' OR outcome=$4)
		  AND ($5='' OR actor_id=$5) AND ($6='' OR resource_type=$6)
		  AND ($7='' OR resource_id=$7) AND ($8::uuid IS NULL OR operation_id=$8::uuid)
		  AND ($9::timestamptz IS NULL OR occurred_at >= $9)
		  AND ($10::timestamptz IS NULL OR occurred_at <= $10)
		ORDER BY occurred_at DESC,id DESC LIMIT $11`, cursorTime, cursorID, q.Action,
		string(q.Outcome), q.ActorID, q.ResourceType, q.ResourceID, operation, q.From, q.To, q.Limit+1)
	if err != nil {
		return audit.Page{}, err
	}
	defer rows.Close()
	items := make([]audit.Event, 0, q.Limit)
	for rows.Next() {
		var e audit.Event
		var roles []byte
		if err = rows.Scan(&e.ID, &e.OccurredAt, &e.SchemaVersion, &e.OperationID, &e.RequestID,
			&e.ActorID, &e.ActorName, &e.ActorType, &roles, &e.ActionCode, &e.Outcome,
			&e.AuthMethod, &e.Permission, &e.PolicyVersion, &e.Reason, &e.ResourceType,
			&e.ResourceID, &e.IPAddress, &e.UserAgent, &e.Route, &e.Metadata); err != nil {
			return audit.Page{}, err
		}
		if err = json.Unmarshal(roles, &e.ActorRoles); err != nil {
			return audit.Page{}, fmt.Errorf("audit actor roles are malformed: %w", err)
		}
		items = append(items, e)
	}
	if err = rows.Err(); err != nil {
		return audit.Page{}, err
	}
	next := ""
	if len(items) > q.Limit {
		last := items[q.Limit-1]
		next = encodeAuditCursor(auditCursor{OccurredAt: last.OccurredAt, ID: last.ID})
		items = items[:q.Limit]
	}
	return audit.Page{Items: items, NextCursor: next}, nil
}

// CheckSchemaVersion verifies that the standalone migration step has made the
// minimum schema available. It deliberately performs no DDL: a server started
// before migration, or against an uninitialized database, must fail closed.
func (s *Store) CheckSchemaVersion(ctx context.Context, minimum int64) error {
	var version int64
	err := s.db.QueryRow(ctx, `SELECT COALESCE(max(version_id) FILTER (WHERE is_applied), 0) FROM goose_db_version`).Scan(&version)
	if err != nil {
		return fmt.Errorf("schema version unavailable: %w", err)
	}
	if version < minimum {
		return fmt.Errorf("schema version %d is below required version %d", version, minimum)
	}
	return nil
}

type Session struct {
	ID, Subject, Name, CSRFHash    string
	Roles                          []string
	CreatedAt, LastSeen, ExpiresAt time.Time
}

func hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func (s *Store) CreateSession(ctx context.Context, subject, name, csrf string, roles []string, now time.Time, idle, absolute time.Duration) (Session, error) {
	normalized := authz.NormalizeRoles(roles)
	roleStrings := make([]string, len(normalized))
	for i, role := range normalized {
		roleStrings[i] = string(role)
	}
	x := Session{ID: uuid.NewString(), Subject: subject, Name: name, Roles: roleStrings, CSRFHash: hash(csrf), CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(absolute)}
	rolesJSON, e := json.Marshal(x.Roles)
	if e != nil {
		return x, e
	}
	_, e = s.db.Exec(ctx, `INSERT INTO sessions(id,subject,name,roles_json,csrf_hash,created_at,last_seen,expires_at) VALUES($1,$2,$3,$4,$5,$6,$6,$7)`, x.ID, x.Subject, x.Name, rolesJSON, x.CSRFHash, x.CreatedAt, x.ExpiresAt)
	return x, e
}

// CreateSessionWithAudit commits a browser session and its authentication
// event in one transaction. A session is never made usable when the event
// cannot be appended.
func (s *Store) CreateSessionWithAudit(ctx context.Context, subject, name, csrf string, roles []string, now time.Time, idle, absolute time.Duration, successEvent audit.Event) (Session, error) {
	normalized := authz.NormalizeRoles(roles)
	roleStrings := make([]string, len(normalized))
	for i, role := range normalized {
		roleStrings[i] = string(role)
	}
	x := Session{ID: uuid.NewString(), Subject: subject, Name: name, Roles: roleStrings, CSRFHash: hash(csrf), CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(absolute)}
	rolesJSON, err := json.Marshal(x.Roles)
	if err != nil {
		return x, err
	}
	tx, err := s.beginAuthTx(ctx)
	if err != nil {
		return x, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO sessions(id,subject,name,roles_json,csrf_hash,created_at,last_seen,expires_at) VALUES($1,$2,$3,$4,$5,$6,$6,$7)`, x.ID, x.Subject, x.Name, rolesJSON, x.CSRFHash, x.CreatedAt, x.ExpiresAt); err != nil {
		return x, err
	}
	if err = appendAuditEvent(ctx, tx, successEvent); err != nil {
		return x, &AuditAppendError{Err: err}
	}
	return x, tx.Commit(ctx)
}

// DeleteSessionWithAudit commits local logout and its event together. The
// caller must not expire the browser cookie until this method succeeds.
func (s *Store) DeleteSessionWithAudit(ctx context.Context, id string, successEvent audit.Event) error {
	tx, err := s.beginAuthTx(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if err = appendAuditEvent(ctx, tx, successEvent); err != nil {
		return &AuditAppendError{Err: err}
	}
	return tx.Commit(ctx)
}
func (s *Store) GetSession(ctx context.Context, id string, now time.Time, idle time.Duration) (Session, error) {
	var x Session
	var rolesJSON []byte
	err := s.db.QueryRow(ctx, `SELECT id,subject,name,roles_json,csrf_hash,created_at,last_seen,expires_at FROM sessions WHERE id=$1`, id).Scan(&x.ID, &x.Subject, &x.Name, &rolesJSON, &x.CSRFHash, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt)
	if err != nil {
		return x, err
	}
	if err = json.Unmarshal(rolesJSON, &x.Roles); err != nil {
		return x, fmt.Errorf("session roles are malformed: %w", err)
	}
	if now.Sub(x.LastSeen) > idle || now.After(x.ExpiresAt) {
		_, _ = s.db.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, id)
		return x, fmt.Errorf("session expired")
	}
	_, _ = s.db.Exec(ctx, `UPDATE sessions SET last_seen=$2 WHERE id=$1`, id, now)
	return x, nil
}
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, e := s.db.Exec(ctx, `DELETE FROM sessions WHERE id=$1`, id)
	return e
}

type OAuthState struct {
	ID, StateHash, Verifier, Nonce, NonceHash, RedirectURI string
	CreatedAt, ExpiresAt                                   time.Time
}

func (s *Store) CreateOAuthState(ctx context.Context, state, verifier, nonce, redirect string, now time.Time) (OAuthState, error) {
	x := OAuthState{ID: uuid.NewString(), StateHash: hash(state), Verifier: verifier, Nonce: nonce, NonceHash: hash(nonce), RedirectURI: redirect, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	_, e := s.db.Exec(ctx, `INSERT INTO oauth_states(id,state_hash,verifier,nonce_hash,redirect_uri,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, x.ID, x.StateHash, x.Verifier, x.NonceHash, x.RedirectURI, x.CreatedAt, x.ExpiresAt)
	return x, e
}

// CreateOAuthStateWithAudit commits login state and the initiation event in one
// transaction, so a redirect is never issued without a durable audit event.
func (s *Store) CreateOAuthStateWithAudit(ctx context.Context, state, verifier, nonce, redirect string, now time.Time, startedEvent audit.Event) (OAuthState, error) {
	x := OAuthState{ID: uuid.NewString(), StateHash: hash(state), Verifier: verifier, Nonce: nonce, NonceHash: hash(nonce), RedirectURI: redirect, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute)}
	tx, err := s.beginAuthTx(ctx)
	if err != nil {
		return x, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO oauth_states(id,state_hash,verifier,nonce_hash,redirect_uri,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, x.ID, x.StateHash, x.Verifier, x.NonceHash, x.RedirectURI, x.CreatedAt, x.ExpiresAt); err != nil {
		return x, err
	}
	if err = appendAuditEvent(ctx, tx, startedEvent); err != nil {
		return x, &AuditAppendError{Err: err}
	}
	return x, tx.Commit(ctx)
}
func (s *Store) ConsumeOAuthState(ctx context.Context, state string, now time.Time) (OAuthState, error) {
	var x OAuthState
	// DELETE ... RETURNING atomically consumes the state and requires only the
	// runtime role's existing SELECT/DELETE grants. SELECT ... FOR UPDATE would
	// additionally require UPDATE on oauth_states.
	err := s.db.QueryRow(ctx, `DELETE FROM oauth_states WHERE state_hash=$1 AND expires_at >= $2 RETURNING id,state_hash,verifier,nonce_hash,redirect_uri,created_at,expires_at`, hash(state), now).Scan(&x.ID, &x.StateHash, &x.Verifier, &x.NonceHash, &x.RedirectURI, &x.CreatedAt, &x.ExpiresAt)
	if err != nil {
		return x, fmt.Errorf("oauth state consume: %w", err)
	}
	return x, nil
}

type Request struct {
	ID, Repository, Environment, CommitSHA, Requester, RequesterSubject, Decision, LogStatus, DeliveryStatus, Reason string
	CreatedAt, ExpiresAt                                                                                             time.Time
	Context                                                                                                          []byte
}
type Decision struct {
	ID, RequestID, ReviewerSubject, ReviewerName, Decision, Reason, Signature string
	Statement                                                                 []byte
	CreatedAt                                                                 time.Time
}
type Challenge struct {
	NonceHash, RequestID, Subject, Decision, Reason string
	ExpiresAt                                       time.Time
	ConsumedAt                                      *time.Time
}
type Job struct {
	ID, Kind, RequestID string
	Payload             []byte
	Status              string
	Attempts            int
	RunAfter            time.Time
	LastError           string
}

func (s *Store) ClaimJob(ctx context.Context) (Job, error) {
	tx, e := s.db.Begin(ctx)
	if e != nil {
		return Job{}, e
	}
	defer tx.Rollback(ctx)
	var j Job
	e = tx.QueryRow(ctx, `SELECT id,kind,request_id,payload,status,attempts,run_after,last_error FROM jobs WHERE (status='pending' AND run_after<=now()) OR (status='running' AND locked_at<now()-interval '5 minutes') ORDER BY run_after,id LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&j.ID, &j.Kind, &j.RequestID, &j.Payload, &j.Status, &j.Attempts, &j.RunAfter, &j.LastError)
	if e != nil {
		return j, e
	}
	_, e = tx.Exec(ctx, `UPDATE jobs SET status='running',locked_at=now(),attempts=attempts+1 WHERE id=$1`, j.ID)
	if e != nil {
		return j, e
	}
	return j, tx.Commit(ctx)
}
func (s *Store) FinishJob(ctx context.Context, id string, ok bool, errText string) error {
	if ok {
		_, e := s.db.Exec(ctx, `UPDATE jobs SET status='done',locked_at=NULL,last_error='' WHERE id=$1`, id)
		return e
	}
	_, e := s.db.Exec(ctx, `UPDATE jobs SET status='pending',locked_at=NULL,run_after=now()+LEAST((2 ^ LEAST(attempts,8))*interval '1 minute',interval '1 hour'),last_error=$2 WHERE id=$1`, id, errText)
	return e
}
func (s *Store) SetStatuses(ctx context.Context, id, logStatus, deliveryStatus string) error {
	_, e := s.db.Exec(ctx, `UPDATE requests SET log_status=COALESCE(NULLIF($2,''),log_status),delivery_status=COALESCE(NULLIF($3,''),delivery_status) WHERE id=$1`, id, logStatus, deliveryStatus)
	return e
}
func (s *Store) SavePublishedBundle(ctx context.Context, requestID string, bundle []byte) error {
	_, e := s.db.Exec(ctx, `UPDATE decisions SET published_bundle=$2 WHERE request_id=$1`, requestID, bundle)
	return e
}
func (s *Store) SavePublishedAndMark(ctx context.Context, requestID string, bundle []byte) error {
	tx, e := s.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `UPDATE decisions SET published_bundle=$2 WHERE request_id=$1`, requestID, bundle); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE requests SET log_status='published' WHERE id=$1`, requestID); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// PublishedEvidence returns the complete immutable evidence bundle only after
// publication has been committed. Pending decisions deliberately have no
// public representation here.
func (s *Store) PublishedEvidence(ctx context.Context, requestID string) ([]byte, bool, error) {
	var bundle []byte
	err := s.db.QueryRow(ctx, `SELECT d.published_bundle FROM decisions d JOIN requests r ON r.id=d.request_id WHERE d.request_id=$1 AND r.log_status='published' AND d.published_bundle IS NOT NULL`, requestID).Scan(&bundle)
	if err == pgx.ErrNoRows || len(bundle) == 0 {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return bundle, true, nil
}
func (s *Store) CreateChallenge(ctx context.Context, requestID, subject, decision, reason, nonceHash string, expires time.Time) error {
	_, e := s.db.Exec(ctx, `INSERT INTO challenges(nonce_hash,request_id,subject,decision,reason,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, nonceHash, requestID, subject, decision, reason, expires)
	return e
}

// CreateChallengeWithAudit atomically creates a challenge and appends its
// supplied success event. Failure events must be appended separately after an
// error is returned; they never participate in this transaction.
func (s *Store) CreateChallengeWithAudit(ctx context.Context, requestID, subject, decision, reason, nonceHash string, expires time.Time, successEvent audit.Event) error {
	begin := s.beginDecisionTx
	if begin == nil {
		begin = func(ctx context.Context) (decisionTx, error) { return s.db.Begin(ctx) }
	}
	tx, err := begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `INSERT INTO challenges(nonce_hash,request_id,subject,decision,reason,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, nonceHash, requestID, subject, decision, reason, expires); err != nil {
		return err
	}
	if err = appendAuditEvent(ctx, tx, successEvent); err != nil {
		return &AuditAppendError{Err: err}
	}
	return tx.Commit(ctx)
}
func (s *Store) ConsumeChallenge(ctx context.Context, requestID, subject, nonceHash, decision, reason string, now time.Time) error {
	tx, e := s.db.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	var c Challenge
	// Bind the row lock to the target request as well as the nonce. The
	// request-ID check below remains a defense in depth invariant.
	e = tx.QueryRow(ctx, `SELECT nonce_hash,request_id,subject,decision,reason,expires_at,consumed_at FROM challenges WHERE nonce_hash=$1 AND request_id=$2 FOR UPDATE`, nonceHash, requestID).Scan(&c.NonceHash, &c.RequestID, &c.Subject, &c.Decision, &c.Reason, &c.ExpiresAt, &c.ConsumedAt)
	if e != nil {
		return fmt.Errorf("challenge not found")
	}
	if !challengeMatches(c, requestID, subject, decision, reason, now) {
		return fmt.Errorf("challenge is invalid or expired")
	}
	var tag pgconn.CommandTag
	tag, e = tx.Exec(ctx, `UPDATE challenges SET consumed_at=$2 WHERE nonce_hash=$1 AND request_id=$3 AND consumed_at IS NULL`, nonceHash, now, requestID)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("challenge is invalid or already consumed")
	}
	return tx.Commit(ctx)
}

func challengeMatches(c Challenge, requestID, subject, decision, reason string, now time.Time) bool {
	return c.RequestID == requestID && c.Subject == subject && c.Decision == decision && c.Reason == reason && c.ConsumedAt == nil && !now.After(c.ExpiresAt)
}

func scanRequest(row pgx.Row) (Request, error) {
	var x Request
	e := row.Scan(&x.ID, &x.Repository, &x.Environment, &x.CommitSHA, &x.Requester, &x.RequesterSubject, &x.Context, &x.CreatedAt, &x.ExpiresAt, &x.Decision, &x.LogStatus, &x.DeliveryStatus, &x.Reason)
	return x, e
}
func (s *Store) GetRequest(ctx context.Context, id string) (Request, error) {
	return scanRequest(s.db.QueryRow(ctx, `SELECT id,repository,environment,commit_sha,requester,requester_subject,context,created_at,expires_at,decision,log_status,delivery_status,reason FROM requests WHERE id=$1`, id))
}
func (s *Store) ListRequests(ctx context.Context, cursor string, limit int) ([]Request, string, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, e := s.db.Query(ctx, `SELECT id,repository,environment,commit_sha,requester,requester_subject,context,created_at,expires_at,decision,log_status,delivery_status,reason FROM requests WHERE ($1='' OR (created_at,id) < (SELECT created_at,id FROM requests WHERE id=NULLIF($1,'')::uuid)) ORDER BY created_at DESC,id DESC LIMIT $2`, cursor, limit+1)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var x Request
		if e = rows.Scan(&x.ID, &x.Repository, &x.Environment, &x.CommitSHA, &x.Requester, &x.RequesterSubject, &x.Context, &x.CreatedAt, &x.ExpiresAt, &x.Decision, &x.LogStatus, &x.DeliveryStatus, &x.Reason); e != nil {
			return nil, "", e
		}
		out = append(out, x)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	next := ""
	if len(out) > limit {
		next = out[limit-1].ID
		out = out[:limit]
	}
	return out, next, nil
}
func (s *Store) ListDecisions(ctx context.Context, cursor string, limit int) ([]Decision, string, error) {
	if limit < 1 || limit > 100 {
		limit = 50
	}
	rows, e := s.db.Query(ctx, `SELECT id,request_id,reviewer_subject,reviewer_name,decision,reason,statement,signature,created_at FROM decisions WHERE ($1='' OR (created_at,id) < (SELECT created_at,id FROM decisions WHERE id=NULLIF($1,'')::uuid)) ORDER BY created_at DESC,id DESC LIMIT $2`, cursor, limit+1)
	if e != nil {
		return nil, "", e
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var x Decision
		if e = rows.Scan(&x.ID, &x.RequestID, &x.ReviewerSubject, &x.ReviewerName, &x.Decision, &x.Reason, &x.Statement, &x.Signature, &x.CreatedAt); e != nil {
			return nil, "", e
		}
		out = append(out, x)
	}
	if e = rows.Err(); e != nil {
		return nil, "", e
	}
	next := ""
	if len(out) > limit {
		next = out[limit-1].ID
		out = out[:limit]
	}
	return out, next, nil
}
func (s *Store) RequestEvidence(ctx context.Context, id string) ([]Decision, error) {
	rows, e := s.db.Query(ctx, `SELECT id,request_id,reviewer_subject,reviewer_name,decision,reason,COALESCE(published_bundle,statement),signature,created_at FROM decisions WHERE request_id=$1 ORDER BY created_at`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []Decision
	for rows.Next() {
		var x Decision
		if e = rows.Scan(&x.ID, &x.RequestID, &x.ReviewerSubject, &x.ReviewerName, &x.Decision, &x.Reason, &x.Statement, &x.Signature, &x.CreatedAt); e != nil {
			return nil, e
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// AcceptDecision atomically enforces first valid reviewer, no self approval, and a single winning decision.
func (s *Store) AcceptDecision(ctx context.Context, requestID, reviewerSubject, reviewerName, decision, reason, nonceHash string, statement []byte, signature string) (Decision, error) {
	return s.acceptDecision(ctx, requestID, reviewerSubject, reviewerName, decision, reason, nonceHash, statement, signature, nil)
}

// AcceptDecisionWithAudit atomically accepts a decision and appends the supplied
// success event. The event is inserted through the same transaction as every
// business mutation, so either the complete decision lifecycle commits or all
// of it rolls back. Failure events must be appended separately after this
// method returns an error.
func (s *Store) AcceptDecisionWithAudit(ctx context.Context, requestID, reviewerSubject, reviewerName, decision, reason, nonceHash string, statement []byte, signature string, successEvent audit.Event) (Decision, error) {
	return s.acceptDecision(ctx, requestID, reviewerSubject, reviewerName, decision, reason, nonceHash, statement, signature, &successEvent)
}

func (s *Store) acceptDecision(ctx context.Context, requestID, reviewerSubject, reviewerName, decision, reason, nonceHash string, statement []byte, signature string, successEvent *audit.Event) (Decision, error) {
	begin := s.beginDecisionTx
	if begin == nil {
		begin = func(ctx context.Context) (decisionTx, error) { return s.db.Begin(ctx) }
	}
	tx, e := begin(ctx)
	if e != nil {
		return Decision{}, e
	}
	defer tx.Rollback(ctx)
	var requester, existing string
	var expires time.Time
	e = tx.QueryRow(ctx, `SELECT requester_subject,decision,expires_at FROM requests WHERE id=$1 FOR UPDATE`, requestID).Scan(&requester, &existing, &expires)
	if e != nil {
		return Decision{}, e
	}
	if requester == reviewerSubject {
		return Decision{}, fmt.Errorf("reviewer cannot approve own request")
	}
	if time.Now().After(expires) {
		return Decision{}, fmt.Errorf("request expired")
	}
	if existing != "pending" {
		return Decision{}, fmt.Errorf("request already decided")
	}
	var challenge Challenge
	if e = tx.QueryRow(ctx, `SELECT nonce_hash,request_id,subject,decision,reason,expires_at,consumed_at FROM challenges WHERE nonce_hash=$1 AND request_id=$2 AND consumed_at IS NULL FOR UPDATE`, nonceHash, requestID).Scan(&challenge.NonceHash, &challenge.RequestID, &challenge.Subject, &challenge.Decision, &challenge.Reason, &challenge.ExpiresAt, &challenge.ConsumedAt); e != nil || !challengeMatches(challenge, requestID, reviewerSubject, mapDecision(decision), reason, time.Now()) {
		return Decision{}, fmt.Errorf("challenge is invalid or expired")
	}
	var d Decision
	d.ID = uuid.NewString()
	d.RequestID = requestID
	d.ReviewerSubject = reviewerSubject
	d.ReviewerName = reviewerName
	d.Decision = decision
	d.Reason = reason
	d.Statement = statement
	d.Signature = signature
	d.CreatedAt = time.Now()
	if _, e = tx.Exec(ctx, `INSERT INTO decisions(id,request_id,reviewer_subject,reviewer_name,decision,reason,statement,signature,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, d.ID, d.RequestID, d.ReviewerSubject, d.ReviewerName, d.Decision, d.Reason, d.Statement, d.Signature, d.CreatedAt); e != nil {
		return d, e
	}
	if _, e = tx.Exec(ctx, `UPDATE requests SET decision=$2,reason=$3 WHERE id=$1`, requestID, decision, reason); e != nil {
		return d, e
	}
	var tag pgconn.CommandTag
	tag, e = tx.Exec(ctx, `UPDATE challenges SET consumed_at=$2 WHERE nonce_hash=$1 AND request_id=$3 AND consumed_at IS NULL`, nonceHash, time.Now(), requestID)
	if e != nil {
		return d, e
	}
	if tag.RowsAffected() != 1 {
		return d, fmt.Errorf("challenge is invalid or already consumed")
	}
	if _, e = tx.Exec(ctx, `INSERT INTO jobs(id,kind,request_id,payload,run_after) VALUES($1,'publish', $2, $3, now())`, uuid.New(), requestID, statement); e != nil {
		return d, e
	}
	if successEvent != nil {
		if e = appendAuditEvent(ctx, tx, *successEvent); e != nil {
			return d, &AuditAppendError{Err: e}
		}
	}
	return d, tx.Commit(ctx)
}
func mapDecision(v string) string { return v }
func (s *Store) EnqueueWebhook(ctx context.Context, r Request) error {
	_, e := s.db.Exec(ctx, `INSERT INTO requests(id,repository,environment,commit_sha,requester,requester_subject,context,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO NOTHING`, r.ID, r.Repository, r.Environment, r.CommitSHA, r.Requester, r.RequesterSubject, r.Context, r.CreatedAt, r.ExpiresAt)
	return e
}
