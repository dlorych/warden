package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCreateChallengeWithAuditCommitsChallengeAndSuccessEventTogether(t *testing.T) {
	tx := &decisionTxStub{}
	err := newDecisionTestStore(tx).CreateChallengeWithAudit(
		context.Background(), "request-id", "reviewer", "approved", "ship it", "nonce-hash",
		time.Unix(100, 0).UTC(), validDecisionTestEvent(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !tx.committed {
		t.Fatal("successful challenge did not commit")
	}
	if !tx.rolledBack {
		t.Fatal("transaction cleanup did not call rollback after commit")
	}
	if len(tx.execQueries) != 2 || !strings.Contains(tx.execQueries[0], "INSERT INTO challenges") || !strings.Contains(tx.execQueries[1], "INSERT INTO audit_events") {
		t.Fatalf("transaction writes = %q, want challenge insert followed by audit insert", tx.execQueries)
	}
}

func TestCreateChallengeWithAuditMarksAndUnwrapsAuditFailure(t *testing.T) {
	auditErr := errors.New("audit unavailable")
	tx := &decisionTxStub{auditErr: auditErr}
	err := newDecisionTestStore(tx).CreateChallengeWithAudit(
		context.Background(), "request-id", "reviewer", "approved", "ship it", "nonce-hash",
		time.Unix(100, 0).UTC(), validDecisionTestEvent(),
	)
	if !errors.Is(err, auditErr) {
		t.Fatalf("error = %v, want underlying audit error", err)
	}
	var marker *AuditAppendError
	if !errors.As(err, &marker) || !marker.AuditAppendFailure() {
		t.Fatalf("error = %v, want AuditAppendError marker", err)
	}
	if tx.committed || !tx.rolledBack {
		t.Fatalf("audit failure commit=%v rollback=%v, want false/true", tx.committed, tx.rolledBack)
	}
}

func TestCreateChallengeWithAuditDoesNotMarkMutationOrCommitFailures(t *testing.T) {
	challengeErr := errors.New("challenge insert failed")
	commitErr := errors.New("commit failed")
	tests := []struct {
		name string
		tx   *decisionTxStub
		want error
	}{
		{name: "challenge insert", tx: &decisionTxStub{challengeErr: challengeErr}, want: challengeErr},
		{name: "commit", tx: &decisionTxStub{commitErr: commitErr}, want: commitErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := newDecisionTestStore(tt.tx).CreateChallengeWithAudit(
				context.Background(), "request-id", "reviewer", "approved", "ship it", "nonce-hash",
				time.Unix(100, 0).UTC(), validDecisionTestEvent(),
			)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			var marker *AuditAppendError
			if errors.As(err, &marker) {
				t.Fatalf("error = %v, must not carry AuditAppendError", err)
			}
			if tt.tx.committed || !tt.tx.rolledBack {
				t.Fatalf("commit=%v rollback=%v, want false/true", tt.tx.committed, tt.tx.rolledBack)
			}
		})
	}
}
