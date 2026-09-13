package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Store struct{ db *pgxpool.Pool }

func New(db *pgxpool.Pool) *Store                  { return &Store{db: db} }
func (s *Store) Migrate(ctx context.Context) error { _, err := s.db.Exec(ctx, schema); return err }

const schema = `CREATE TABLE IF NOT EXISTS requests (id uuid PRIMARY KEY, repository text NOT NULL, environment text NOT NULL, commit_sha text NOT NULL, requester text NOT NULL, requester_subject text NOT NULL, context jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL, decision text NOT NULL DEFAULT 'pending' CHECK(decision IN ('pending','approved','rejected')), reason text NOT NULL DEFAULT '', log_status text NOT NULL DEFAULT 'pending', delivery_status text NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS decisions (id uuid PRIMARY KEY, request_id uuid NOT NULL REFERENCES requests(id), reviewer_subject text NOT NULL, reviewer_name text NOT NULL, decision text NOT NULL CHECK(decision IN ('approved','rejected')), reason text NOT NULL DEFAULT '', statement jsonb NOT NULL, signature text NOT NULL DEFAULT '', created_at timestamptz NOT NULL, UNIQUE(request_id,reviewer_subject));
ALTER TABLE decisions ADD COLUMN IF NOT EXISTS published_bundle jsonb;
CREATE TABLE IF NOT EXISTS sessions (id text PRIMARY KEY, subject text NOT NULL, name text NOT NULL, groups_json jsonb NOT NULL DEFAULT '[]', csrf_hash text NOT NULL, created_at timestamptz NOT NULL, last_seen timestamptz NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS oauth_states (id text PRIMARY KEY, state_hash text UNIQUE NOT NULL, verifier text NOT NULL, nonce_hash text NOT NULL, redirect_uri text NOT NULL, created_at timestamptz NOT NULL, expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS jobs (id uuid PRIMARY KEY, kind text NOT NULL, request_id uuid NOT NULL, payload jsonb NOT NULL, status text NOT NULL DEFAULT 'pending', attempts int NOT NULL DEFAULT 0, run_after timestamptz NOT NULL, last_error text NOT NULL DEFAULT '');
ALTER TABLE jobs ADD COLUMN IF NOT EXISTS locked_at timestamptz;
CREATE TABLE IF NOT EXISTS challenges (nonce_hash text PRIMARY KEY, request_id uuid NOT NULL REFERENCES requests(id), subject text NOT NULL, decision text NOT NULL, reason text NOT NULL DEFAULT '', expires_at timestamptz NOT NULL, consumed_at timestamptz);
CREATE INDEX IF NOT EXISTS requests_created_idx ON requests(created_at DESC,id DESC); CREATE INDEX IF NOT EXISTS decisions_created_idx ON decisions(created_at DESC,id DESC); CREATE INDEX IF NOT EXISTS jobs_due_idx ON jobs(status,run_after);`

type Session struct {
	ID, Subject, Name, CSRFHash    string
	CreatedAt, LastSeen, ExpiresAt time.Time
}

func hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
func (s *Store) CreateSession(ctx context.Context, subject, name, csrf string, now time.Time, idle, absolute time.Duration) (Session, error) {
	x := Session{ID: uuid.NewString(), Subject: subject, Name: name, CSRFHash: hash(csrf), CreatedAt: now, LastSeen: now, ExpiresAt: now.Add(absolute)}
	_, e := s.db.Exec(ctx, `INSERT INTO sessions(id,subject,name,csrf_hash,created_at,last_seen,expires_at) VALUES($1,$2,$3,$4,$5,$5,$6)`, x.ID, x.Subject, x.Name, x.CSRFHash, x.CreatedAt, x.ExpiresAt)
	return x, e
}
func (s *Store) GetSession(ctx context.Context, id string, now time.Time, idle time.Duration) (Session, error) {
	var x Session
	err := s.db.QueryRow(ctx, `SELECT id,subject,name,csrf_hash,created_at,last_seen,expires_at FROM sessions WHERE id=$1`, id).Scan(&x.ID, &x.Subject, &x.Name, &x.CSRFHash, &x.CreatedAt, &x.LastSeen, &x.ExpiresAt)
	if err != nil {
		return x, err
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
func (s *Store) ConsumeOAuthState(ctx context.Context, state string, now time.Time) (OAuthState, error) {
	var x OAuthState
	tx, e := s.db.Begin(ctx)
	if e != nil {
		return x, e
	}
	defer tx.Rollback(ctx)
	e = tx.QueryRow(ctx, `SELECT id,state_hash,verifier,nonce_hash,redirect_uri,created_at,expires_at FROM oauth_states WHERE state_hash=$1 FOR UPDATE`, hash(state)).Scan(&x.ID, &x.StateHash, &x.Verifier, &x.NonceHash, &x.RedirectURI, &x.CreatedAt, &x.ExpiresAt)
	if e != nil {
		return x, e
	}
	if now.After(x.ExpiresAt) {
		return x, fmt.Errorf("oauth state expired")
	}
	if _, e = tx.Exec(ctx, `DELETE FROM oauth_states WHERE id=$1`, x.ID); e != nil {
		return x, e
	}
	return x, tx.Commit(ctx)
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
func (s *Store) CreateChallenge(ctx context.Context, requestID, subject, decision, reason, nonceHash string, expires time.Time) error {
	_, e := s.db.Exec(ctx, `INSERT INTO challenges(nonce_hash,request_id,subject,decision,reason,expires_at) VALUES($1,$2,$3,$4,$5,$6)`, nonceHash, requestID, subject, decision, reason, expires)
	return e
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
	tx, e := s.db.Begin(ctx)
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
	return d, tx.Commit(ctx)
}
func mapDecision(v string) string { return v }
func (s *Store) EnqueueWebhook(ctx context.Context, r Request) error {
	_, e := s.db.Exec(ctx, `INSERT INTO requests(id,repository,environment,commit_sha,requester,requester_subject,context,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(id) DO NOTHING`, r.ID, r.Repository, r.Environment, r.CommitSHA, r.Requester, r.RequesterSubject, r.Context, r.CreatedAt, r.ExpiresAt)
	return e
}
