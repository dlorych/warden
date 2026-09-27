package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/authz"
)

type decisionTxStub struct {
	requestSubject  string
	requestState    string
	requestExpiry   time.Time
	challenge       Challenge
	execQueries     []string
	auditAction     string
	auditOutcome    audit.Outcome
	auditPermission string
	auditMetadata   json.RawMessage
	auditInserts    int
	requestRows     int64
	requestRowsSet  bool
	auditErr        error
	challengeErr    error
	jobErr          error
	commitErr       error
	committed       bool
	rolledBack      bool
}

func (s *decisionTxStub) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	s.execQueries = append(s.execQueries, query)
	if strings.Contains(query, "INSERT INTO audit_events") {
		s.auditInserts++
		if len(args) > 8 {
			s.auditAction, _ = args[8].(string)
		}
		if len(args) > 9 {
			s.auditOutcome, _ = args[9].(audit.Outcome)
		}
		if len(args) > 11 {
			s.auditPermission, _ = args[11].(string)
		}
		if len(args) > 19 {
			s.auditMetadata, _ = args[19].(json.RawMessage)
		}
		if s.auditErr != nil {
			return pgconn.CommandTag{}, s.auditErr
		}
	}
	if strings.Contains(query, "INSERT INTO requests") && s.requestRowsSet {
		return pgconn.NewCommandTag(fmt.Sprintf("INSERT %d", s.requestRows)), nil
	}
	if strings.Contains(query, "INSERT INTO challenges") && s.challengeErr != nil {
		return pgconn.CommandTag{}, s.challengeErr
	}
	if strings.Contains(query, "INSERT INTO jobs") && s.jobErr != nil {
		return pgconn.CommandTag{}, s.jobErr
	}
	if strings.Contains(query, "UPDATE challenges") {
		return pgconn.NewCommandTag("UPDATE 1"), nil
	}
	return pgconn.NewCommandTag("INSERT 1"), nil
}

func (s *decisionTxStub) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	if strings.Contains(query, "requester_subject") {
		return decisionRow{scan: func(dest ...any) error {
			*(dest[0].(*string)) = s.requestSubject
			*(dest[1].(*string)) = s.requestState
			*(dest[2].(*time.Time)) = s.requestExpiry
			return nil
		}}
	}
	return decisionRow{scan: func(dest ...any) error {
		*(dest[0].(*string)) = s.challenge.NonceHash
		*(dest[1].(*string)) = s.challenge.RequestID
		*(dest[2].(*string)) = s.challenge.Subject
		*(dest[3].(*string)) = s.challenge.Decision
		*(dest[4].(*string)) = s.challenge.Reason
		*(dest[5].(*time.Time)) = s.challenge.ExpiresAt
		*(dest[6].(**time.Time)) = s.challenge.ConsumedAt
		return nil
	}}
}

func (s *decisionTxStub) Commit(context.Context) error {
	if s.commitErr != nil {
		return s.commitErr
	}
	s.committed = true
	return nil
}

func (s *decisionTxStub) Rollback(context.Context) error {
	s.rolledBack = true
	return nil
}

type decisionRow struct {
	scan func(...any) error
}

func (r decisionRow) Scan(dest ...any) error { return r.scan(dest...) }

func validDecisionTestEvent() audit.Event {
	return audit.Event{
		OperationID: "00000000-0000-4000-8000-000000000101",
		RequestID:   "00000000-0000-4000-8000-000000000102",
		ActorType:   audit.ActorUser,
		ActionCode:  audit.ActionDecisionAdd,
		Outcome:     audit.OutcomeSuccess,
		Permission:  string(authz.DecisionAdd),
		Metadata:    []byte(`{"returned":1}`),
	}
}

func newDecisionTestStore(tx *decisionTxStub) *Store {
	return &Store{beginDecisionTx: func(context.Context) (decisionTx, error) { return tx, nil }}
}

func TestAcceptDecisionWithAuditCommitsBusinessStateAndSuccessEventTogether(t *testing.T) {
	now := time.Now().UTC()
	tx := &decisionTxStub{
		requestSubject: "requester",
		requestState:   "pending",
		requestExpiry:  now.Add(time.Hour),
		challenge: Challenge{
			NonceHash: "nonce-hash",
			RequestID: "request-id",
			Subject:   "reviewer",
			Decision:  "approved",
			Reason:    "ship it",
			ExpiresAt: now.Add(time.Minute),
		},
	}

	got, err := newDecisionTestStore(tx).AcceptDecisionWithAudit(context.Background(), "request-id", "reviewer", "Reviewer", "approved", "ship it", "nonce-hash", []byte(`{"statement":true}`), "signature", validDecisionTestEvent())
	if err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "request-id" || got.Decision != "approved" {
		t.Fatalf("decision = %#v", got)
	}
	if !tx.committed {
		t.Fatal("successful decision did not commit")
	}
	if !tx.rolledBack {
		t.Fatal("transaction cleanup did not call rollback after commit")
	}
	if len(tx.execQueries) != 5 || !strings.Contains(tx.execQueries[len(tx.execQueries)-1], "INSERT INTO audit_events") {
		t.Fatalf("transaction writes = %q, want business writes followed by audit insert", tx.execQueries)
	}
	if tx.auditAction != audit.ActionDecisionAdd || tx.auditOutcome != audit.OutcomeSuccess || tx.auditPermission != audit.ActionDecisionAdd {
		t.Fatalf("audit insert action=%q outcome=%q permission=%q, want decision.add/success/decision.add", tx.auditAction, tx.auditOutcome, tx.auditPermission)
	}
}

func TestAcceptDecisionWithAuditRollsBackWhenAuditAppendFails(t *testing.T) {
	now := time.Now().UTC()
	auditErr := errors.New("audit unavailable")
	tx := &decisionTxStub{
		requestSubject: "requester",
		requestState:   "pending",
		requestExpiry:  now.Add(time.Hour),
		auditErr:       auditErr,
		challenge: Challenge{
			NonceHash: "nonce-hash",
			RequestID: "request-id",
			Subject:   "reviewer",
			Decision:  "approved",
			Reason:    "ship it",
			ExpiresAt: now.Add(time.Minute),
		},
	}

	_, err := newDecisionTestStore(tx).AcceptDecisionWithAudit(context.Background(), "request-id", "reviewer", "Reviewer", "approved", "ship it", "nonce-hash", []byte(`{"statement":true}`), "signature", validDecisionTestEvent())
	if !errors.Is(err, auditErr) {
		t.Fatalf("error = %v, want audit error", err)
	}
	var marker *AuditAppendError
	if !errors.As(err, &marker) || !marker.AuditAppendFailure() {
		t.Fatalf("error = %v, want AuditAppendError marker", err)
	}
	if tx.committed {
		t.Fatal("audit failure committed business state")
	}
	if !tx.rolledBack {
		t.Fatal("audit failure did not roll back transaction")
	}
}

func TestAcceptDecisionWithAuditDoesNotAppendFailureEventWhenMutationFails(t *testing.T) {
	now := time.Now().UTC()
	jobErr := errors.New("job enqueue failed")
	tx := &decisionTxStub{
		requestSubject: "requester",
		requestState:   "pending",
		requestExpiry:  now.Add(time.Hour),
		jobErr:         jobErr,
		challenge: Challenge{
			NonceHash: "nonce-hash",
			RequestID: "request-id",
			Subject:   "reviewer",
			Decision:  "approved",
			Reason:    "ship it",
			ExpiresAt: now.Add(time.Minute),
		},
	}

	_, err := newDecisionTestStore(tx).AcceptDecisionWithAudit(context.Background(), "request-id", "reviewer", "Reviewer", "approved", "ship it", "nonce-hash", []byte(`{"statement":true}`), "signature", validDecisionTestEvent())
	if !errors.Is(err, jobErr) {
		t.Fatalf("error = %v, want mutation error", err)
	}
	var marker *AuditAppendError
	if errors.As(err, &marker) {
		t.Fatalf("mutation error = %v, must not carry AuditAppendError", err)
	}
	if tx.committed {
		t.Fatal("mutation failure committed business state")
	}
	if !tx.rolledBack {
		t.Fatal("mutation failure did not roll back transaction")
	}
	for _, query := range tx.execQueries {
		if strings.Contains(query, "INSERT INTO audit_events") {
			t.Fatal("mutation failure appended an audit event inside the failed transaction")
		}
	}
}
