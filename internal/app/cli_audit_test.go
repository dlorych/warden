package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/authz"
)

func cliRequest(method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	ctx := chi.NewRouteContext()
	ctx.URLParams.Add("id", "request-id")
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, ctx))
}

func TestRequireCLIRecordsIntendedActionForUnauthenticatedRequests(t *testing.T) {
	for _, test := range []struct {
		name, path, reason string
	}{
		{name: "missing bearer", path: "/requests/request-id", reason: "bearer_missing"},
		{name: "malformed bearer", path: "/requests/request-id", reason: "bearer_malformed"},
		{name: "empty bearer", path: "/requests/request-id", reason: "bearer_malformed"},
		{name: "cookie", path: "/requests/request-id/challenges", reason: "cookie_not_allowed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &fakeAuditRepository{}
			a := &App{Audit: repo}
			r := cliRequest(http.MethodGet, test.path)
			if test.name == "malformed bearer" {
				r.Header.Set("Authorization", "Basic abc")
			}
			if test.name == "empty bearer" {
				r.Header.Set("Authorization", "Bearer   ")
			}
			if test.name == "cookie" {
				r.AddCookie(&http.Cookie{Name: "warden_session", Value: "session"})
			}
			called := false
			next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
			rr := httptest.NewRecorder()
			a.requireCLI(next).ServeHTTP(rr, r)
			if called || rr.Code != http.StatusUnauthorized {
				t.Fatalf("next=%v status=%d, want no next/401", called, rr.Code)
			}
			if len(repo.events) != 1 {
				t.Fatalf("events=%d, want 1", len(repo.events))
			}
			event := repo.events[0]
			wantAction := audit.ActionRequestRead
			if test.name == "cookie" {
				wantAction = audit.ActionDecisionPrepare
			}
			if event.ActionCode != wantAction || event.Permission != string(cliPermissionForTest(wantAction)) || event.Outcome != audit.OutcomeUnauthenticated || event.Reason != test.reason {
				t.Fatalf("event=%#v", event)
			}
			if event.AuthMethod != "bearer" || event.ActorType != audit.ActorAnonymous {
				t.Fatalf("authentication fields=%#v", event)
			}
		})
	}
}

func cliPermissionForTest(action string) authz.Permission {
	switch action {
	case audit.ActionDecisionPrepare:
		return authz.DecisionPrepare
	default:
		return authz.RequestRead
	}
}

func TestCLIAuditActionMappingAndAllowlistedDecisionMetadata(t *testing.T) {
	for permission, action := range map[authz.Permission]string{
		authz.RequestRead:     audit.ActionRequestRead,
		authz.EvidenceRead:    audit.ActionEvidenceRead,
		authz.DecisionPrepare: audit.ActionDecisionPrepare,
		authz.DecisionAdd:     audit.ActionDecisionAdd,
	} {
		if got := cliAction(permission); got != action {
			t.Fatalf("cliAction(%q)=%q, want %q", permission, got, action)
		}
	}
	for _, decision := range []string{"approved", "rejected"} {
		var fields map[string]any
		if err := json.Unmarshal(decisionAuditMetadata(decision), &fields); err != nil {
			t.Fatal(err)
		}
		if len(fields) != 1 || fields["decision"] != decision {
			t.Fatalf("metadata=%#v", fields)
		}
		for _, forbidden := range []string{"token", "certificate", "signature", "nonce", "statement", "reason", "payload"} {
			if _, ok := fields[forbidden]; ok {
				t.Fatalf("metadata contains forbidden field %q: %#v", forbidden, fields)
			}
		}
	}
}

type markedAuditError struct{ error }

func (markedAuditError) AuditAppendFailure() bool { return true }

func TestDecisionMutationFailureUsesStableReasonsAndFailClosedAuditMarker(t *testing.T) {
	tests := []struct {
		name, message, reason string
		outcome               audit.Outcome
		status                int
	}{
		{name: "self approval", message: "reviewer cannot approve own request", reason: authz.ReasonSelfApproval, outcome: audit.OutcomeDenied, status: http.StatusNotFound},
		{name: "expired", message: "request expired", reason: "request_expired", outcome: audit.OutcomeInvalid, status: http.StatusConflict},
		{name: "already decided", message: "request already decided", reason: "request_already_decided", outcome: audit.OutcomeInvalid, status: http.StatusConflict},
		{name: "challenge", message: "challenge is invalid or expired", reason: "challenge_invalid", outcome: audit.OutcomeInvalid, status: http.StatusConflict},
		{name: "audit append", message: "audit unavailable", reason: "audit_append_failed", outcome: audit.OutcomeFailed, status: http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var err error = errors.New(test.message)
			if test.name == "audit append" {
				err = markedAuditError{error: err}
			}
			outcome, reason, status, _ := decisionMutationFailure(err)
			if outcome != test.outcome || reason != test.reason || status != test.status {
				t.Fatalf("outcome=%q reason=%q status=%d", outcome, reason, status)
			}
		})
	}
}

func TestCLIProblemDoesNotReturnPayloadWhenAuditAppendFails(t *testing.T) {
	a := &App{Audit: &fakeAuditRepository{err: errors.New("audit unavailable")}}
	r := cliRequest(http.MethodGet, "/requests/request-id")
	rr := httptest.NewRecorder()
	a.cliProblem(rr, r, cliAuditEvent(nil, authz.RequestRead, audit.OutcomeSuccess, "read", "request-id"), http.StatusOK, "protected payload")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "protected payload") {
		t.Fatalf("response exposed protected payload: %q", rr.Body.String())
	}
}
