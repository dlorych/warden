package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/authz"
)

func validWebhookTestEvent() audit.Event {
	return audit.Event{
		OperationID:   "00000000-0000-4000-8000-000000000201",
		RequestID:     "00000000-0000-4000-8000-000000000202",
		ActorID:       "source:github",
		ActorType:     audit.ActorWebhook,
		ActorRoles:    []string{string(authz.RoleSource)},
		ActionCode:    audit.ActionRequestAdd,
		Outcome:       audit.OutcomeSuccess,
		Permission:    string(authz.RequestAdd),
		PolicyVersion: authz.PolicyVersion,
		Metadata:      []byte(`{"delivery_id":"11111111-1111-4111-8111-111111111111"}`),
	}
}

func webhookTestRequest() Request {
	return Request{ID: "11111111-1111-4111-8111-111111111111", Repository: "acme/app", Environment: "production", CommitSHA: "abc", Requester: "actor", RequesterSubject: "actor-subject", Context: []byte(`{"workflow_run_id":1}`)}
}

func TestEnqueueWebhookWithAuditCommitsRequestAndEventTogether(t *testing.T) {
	tx := &decisionTxStub{}
	err := newDecisionTestStore(tx).EnqueueWebhookWithAudit(context.Background(), webhookTestRequest(), validWebhookTestEvent())
	if err != nil {
		t.Fatal(err)
	}
	if !tx.committed || !tx.rolledBack {
		t.Fatalf("commit=%v rollback=%v, want true/true", tx.committed, tx.rolledBack)
	}
	if len(tx.execQueries) != 2 || !strings.Contains(tx.execQueries[0], "INSERT INTO requests") || !strings.Contains(tx.execQueries[0], "ON CONFLICT(id) DO NOTHING") || !strings.Contains(tx.execQueries[1], "INSERT INTO audit_events") {
		t.Fatalf("transaction writes=%q", tx.execQueries)
	}
	if tx.auditAction != audit.ActionRequestAdd || tx.auditOutcome != audit.OutcomeSuccess || tx.auditPermission != string(authz.RequestAdd) {
		t.Fatalf("audit action=%q outcome=%q permission=%q", tx.auditAction, tx.auditOutcome, tx.auditPermission)
	}
}

func TestEnqueueWebhookWithAuditRollsBackWhenAuditAppendFails(t *testing.T) {
	auditErr := errors.New("audit unavailable")
	tx := &decisionTxStub{auditErr: auditErr}
	err := newDecisionTestStore(tx).EnqueueWebhookWithAudit(context.Background(), webhookTestRequest(), validWebhookTestEvent())
	if !errors.Is(err, auditErr) {
		t.Fatalf("error=%v, want audit error", err)
	}
	var marker *AuditAppendError
	if !errors.As(err, &marker) || !marker.AuditAppendFailure() {
		t.Fatalf("error=%v, want AuditAppendError marker", err)
	}
	if tx.committed || !tx.rolledBack {
		t.Fatalf("commit=%v rollback=%v, want false/true", tx.committed, tx.rolledBack)
	}
}

func TestEnqueueWebhookWithAuditMarksExistingAndStillAppendsEveryEvent(t *testing.T) {
	tx := &decisionTxStub{requestRowsSet: true, requestRows: 0}
	store := newDecisionTestStore(tx)
	for range 2 {
		if err := store.EnqueueWebhookWithAudit(context.Background(), webhookTestRequest(), validWebhookTestEvent()); err != nil {
			t.Fatal(err)
		}
	}
	if tx.auditInserts != 2 {
		t.Fatalf("audit inserts=%d, want one per retry", tx.auditInserts)
	}
	if !strings.Contains(string(tx.auditMetadata), `"request_state":"existing"`) {
		t.Fatalf("metadata=%s, want existing request state", tx.auditMetadata)
	}
}
