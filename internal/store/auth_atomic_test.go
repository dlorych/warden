package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCreateOAuthStateWithAuditRollsBackOnAuditFailure(t *testing.T) {
	tx := &decisionTxStub{auditErr: errors.New("audit unavailable")}
	_, err := newDecisionTestStore(tx).CreateOAuthStateWithAudit(context.Background(), "state", "verifier", "nonce", "https://example/callback", time.Now(), validDecisionTestEvent())
	var marker *AuditAppendError
	if !errors.As(err, &marker) || tx.committed || !tx.rolledBack {
		t.Fatalf("err=%v committed=%v rolledBack=%v", err, tx.committed, tx.rolledBack)
	}
}

func TestCreateSessionWithAuditCommitsSessionAndEventTogether(t *testing.T) {
	tx := &decisionTxStub{}
	_, err := newDecisionTestStore(tx).CreateSessionWithAudit(context.Background(), "subject", "name", "csrf", []string{"reader"}, time.Now(), time.Minute, time.Hour, validDecisionTestEvent())
	if err != nil || !tx.committed || !tx.rolledBack {
		t.Fatalf("err=%v committed=%v rolledBack=%v", err, tx.committed, tx.rolledBack)
	}
}

func TestDeleteSessionWithAuditRollsBackOnAuditFailure(t *testing.T) {
	tx := &decisionTxStub{auditErr: errors.New("audit unavailable")}
	err := newDecisionTestStore(tx).DeleteSessionWithAudit(context.Background(), "session", validDecisionTestEvent())
	var marker *AuditAppendError
	if !errors.As(err, &marker) || tx.committed || !tx.rolledBack {
		t.Fatalf("err=%v committed=%v rolledBack=%v", err, tx.committed, tx.rolledBack)
	}
}
