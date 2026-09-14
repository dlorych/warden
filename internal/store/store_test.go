package store

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/wardenv/service/internal/audit"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type auditExecStub struct {
	query string
	args  []any
	err   error
}

func (s *auditExecStub) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	s.query, s.args = query, args
	return pgconn.CommandTag{}, s.err
}

func TestAppendAuditEventOnlyUsesInsertAndNormalizesEnvelopeJSON(t *testing.T) {
	db := &auditExecStub{}
	event := audit.Event{ActorType: audit.ActorAnonymous, ActionCode: audit.ActionRequestRead, Outcome: audit.OutcomeSuccess, Metadata: []byte(`{"safe":true}`)}
	if err := appendAuditEvent(context.Background(), db, event); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ToUpper(db.query), "INSERT INTO AUDIT_EVENTS") || strings.Contains(strings.ToUpper(db.query), "UPDATE") || strings.Contains(strings.ToUpper(db.query), "DELETE") || strings.Contains(strings.ToUpper(db.query), "TRUNCATE") {
		t.Fatalf("audit append query was not insert-only: %q", db.query)
	}
	if got, ok := db.args[7].([]byte); !ok || string(got) != "[]" {
		t.Fatalf("nil actor roles were not normalized to an array: %#v", db.args[7])
	}
}

func TestAppendAuditEventRejectsNonObjectMetadataBeforeSQL(t *testing.T) {
	db := &auditExecStub{}
	event := audit.Event{ActorType: audit.ActorAnonymous, ActionCode: audit.ActionRequestRead, Outcome: audit.OutcomeSuccess, Metadata: []byte(`[]`)}
	if err := appendAuditEvent(context.Background(), db, event); err == nil {
		t.Fatal("array metadata was accepted")
	}
	if db.query != "" {
		t.Fatalf("invalid metadata reached SQL: %q", db.query)
	}
}

func TestDecodeAuditCursorRejectsUnknownFieldsAndTrailingJSON(t *testing.T) {
	valid := encodeAuditCursor(auditCursor{OccurredAt: time.Unix(100, 0).UTC(), ID: 4})
	if _, err := decodeAuditCursor(valid); err != nil {
		t.Fatal(err)
	}
	if err := ValidateAuditCursor(valid); err != nil {
		t.Fatalf("valid cursor rejected: %v", err)
	}
	for _, raw := range []string{"eyJ0IjoiMTk3MC0wMS0wMVQwMDowMDowMFoiLCJpIjo0LCJ4IjoxfQ", "eyJ0IjoiMTk3MC0wMS0wMVQwMDowMDowMFoiLCJpIjo0fXsicCI6MX0"} {
		if _, err := decodeAuditCursor(raw); err == nil {
			t.Fatalf("accepted malformed cursor %q", raw)
		}
		if err := ValidateAuditCursor(raw); err == nil {
			t.Fatalf("accepted malformed cursor %q through validation boundary", raw)
		}
	}
}

func TestAppendAuditEventPropagatesDatabaseFailure(t *testing.T) {
	db := &auditExecStub{err: errors.New("database unavailable")}
	event := audit.Event{ActorType: audit.ActorAnonymous, ActionCode: audit.ActionRequestRead, Outcome: audit.OutcomeFailed}
	if err := appendAuditEvent(context.Background(), db, event); !errors.Is(err, db.err) {
		t.Fatalf("error=%v, want database error", err)
	}
}

func TestChallengeMatchesBindsRequestAndIsSingleUse(t *testing.T) {
	now := time.Unix(100, 0)
	c := Challenge{NonceHash: "nonce", RequestID: "request-a", Subject: "reviewer", Decision: "approved", Reason: "ship", ExpiresAt: now.Add(time.Minute)}
	if challengeMatches(c, "request-b", "reviewer", "approved", "ship", now) {
		t.Fatal("challenge for request A authorized request B")
	}
	if !challengeMatches(c, "request-a", "reviewer", "approved", "ship", now) {
		t.Fatal("matching challenge was rejected")
	}
	consumed := now
	c.ConsumedAt = &consumed
	if challengeMatches(c, "request-a", "reviewer", "approved", "ship", now) {
		t.Fatal("consumed challenge was reusable")
	}
}

func TestTruncateUTF8PreservesValidUserAgent(t *testing.T) {
	got := truncateUTF8(strings.Repeat("a", 510)+"€", 512)
	if len(got) > 512 || !utf8.ValidString(got) {
		t.Fatalf("truncated user-agent is not bounded UTF-8: bytes=%d valid=%v", len(got), utf8.ValidString(got))
	}
}
