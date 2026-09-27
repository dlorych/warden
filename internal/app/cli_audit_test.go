package app

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/auth"
	"github.com/wardenv/service/internal/authz"
)

func cliRequest(method, path string) *http.Request {
	return httptest.NewRequest(method, path, nil)
}

func TestRequireCLIRecordsIntendedActionForUnauthenticatedRequests(t *testing.T) {
	for _, test := range []struct {
		name, path, reason, resourceType, action string
		method, header                           string
		cookie                                   bool
	}{
		{name: "missing request bearer", method: http.MethodGet, path: "/api/v1/requests/11111111-1111-4111-8111-111111111111", reason: "bearer_missing", resourceType: "deployment_request", action: audit.ActionRequestRead},
		{name: "malformed request bearer", method: http.MethodGet, header: "Basic abc", path: "/api/v1/requests/11111111-1111-4111-8111-111111111111", reason: "bearer_malformed", resourceType: "deployment_request", action: audit.ActionRequestRead},
		{name: "empty request bearer", method: http.MethodGet, header: "Bearer   ", path: "/api/v1/requests/11111111-1111-4111-8111-111111111111", reason: "bearer_malformed", resourceType: "deployment_request", action: audit.ActionRequestRead},
		{name: "missing challenge bearer", method: http.MethodPost, path: "/api/v1/requests/11111111-1111-4111-8111-111111111111/challenges", reason: "bearer_missing", resourceType: "deployment_decision", action: audit.ActionDecisionPrepare},
		{name: "missing decision bearer", method: http.MethodPost, path: "/api/v1/requests/11111111-1111-4111-8111-111111111111/decisions", reason: "bearer_missing", resourceType: "deployment_decision", action: audit.ActionDecisionAdd},
		{name: "missing evidence bearer", method: http.MethodGet, path: "/api/v1/requests/11111111-1111-4111-8111-111111111111/evidence", reason: "bearer_missing", resourceType: "protected_evidence", action: audit.ActionEvidenceRead},
		{name: "cookie challenge", method: http.MethodPost, path: "/api/v1/requests/11111111-1111-4111-8111-111111111111/challenges", reason: "cookie_not_allowed", resourceType: "deployment_decision", action: audit.ActionDecisionPrepare, cookie: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &fakeAuditRepository{}
			a := &App{Audit: repo}
			r := cliRequest(test.method, test.path)
			if test.header != "" {
				r.Header.Set("Authorization", test.header)
			}
			if test.cookie {
				r.AddCookie(&http.Cookie{Name: "warden_session", Value: "session"})
			}
			rr := httptest.NewRecorder()
			// Exercise the mounted router and route-scoped middleware.
			a.Router().ServeHTTP(rr, r)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401", rr.Code)
			}
			if len(repo.events) != 1 {
				t.Fatalf("events=%d, want 1", len(repo.events))
			}
			event := repo.events[0]
			if event.ActionCode != test.action || event.Permission != string(permissionForAction(test.action)) || event.Outcome != audit.OutcomeUnauthenticated || event.Reason != test.reason {
				t.Fatalf("event=%#v", event)
			}
			if event.AuthMethod != "bearer" || event.ActorType != audit.ActorAnonymous || event.ResourceID != "11111111-1111-4111-8111-111111111111" || event.ResourceType != test.resourceType {
				t.Fatalf("authentication fields=%#v", event)
			}
		})
	}
}

func TestCLIRouterLeavesUnknownPathsAndMethodsUnaudited(t *testing.T) {
	for _, test := range []struct {
		name, method, path string
		status             int
	}{
		{name: "unknown path", method: http.MethodGet, path: "/api/v1/not-a-route", status: http.StatusNotFound},
		{name: "method mismatch", method: http.MethodPost, path: "/api/v1/requests/11111111-1111-4111-8111-111111111111", status: http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			repo := &fakeAuditRepository{}
			a := &App{Audit: repo}
			rr := httptest.NewRecorder()
			a.Router().ServeHTTP(rr, cliRequest(test.method, test.path))
			if rr.Code != test.status {
				t.Fatalf("status=%d, want %d", rr.Code, test.status)
			}
			if len(repo.events) != 0 {
				t.Fatalf("events=%d, want no audit event", len(repo.events))
			}
		})
	}
}

func TestCLIAuditOmitsInvalidAttemptedRequestID(t *testing.T) {
	for _, path := range []string{
		"/api/v1/requests/not-a-uuid",
		"/api/v1/requests/" + strings.Repeat("a", 5000),
	} {
		t.Run(path, func(t *testing.T) {
			repo := &fakeAuditRepository{}
			a := &App{Audit: repo}
			r := cliRequest(http.MethodGet, path)
			rr := httptest.NewRecorder()
			a.Router().ServeHTTP(rr, r)
			if rr.Code != http.StatusUnauthorized || len(repo.events) != 1 {
				t.Fatalf("status=%d events=%d", rr.Code, len(repo.events))
			}
			if got := repo.events[0].ResourceID; got != "" {
				t.Fatalf("resource ID=%q, want omitted", got)
			}
		})
	}
}

func TestRequireCLIRecordsJWKSOutageAsOperationalFailure(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   "http://" + r.Host,
				"jwks_uri": "http://" + r.Host + "/keys",
			})
		case "/keys":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	service := auth.New(auth.Config{OIDCIssuer: provider.URL, OIDCAudience: "warden-cli"})
	if err := service.Discovery(t.Context()); err != nil {
		t.Fatal(err)
	}
	repo := &fakeAuditRepository{}
	a := &App{Auth: service, Audit: repo}
	r := cliRequest(http.MethodGet, "/api/v1/requests/11111111-1111-4111-8111-111111111111")
	r.Header.Set("Authorization", "Bearer "+testAccessToken())
	rr := httptest.NewRecorder()
	a.Router().ServeHTTP(rr, r)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
	if len(repo.events) != 1 {
		t.Fatalf("events=%d, want 1", len(repo.events))
	}
	event := repo.events[0]
	if event.Outcome != audit.OutcomeFailed || event.Reason != "authentication_unavailable" || event.ResourceID != "11111111-1111-4111-8111-111111111111" {
		t.Fatalf("event=%#v", event)
	}
}

func testAccessToken() string {
	encode := base64.RawURLEncoding.EncodeToString
	header := encode([]byte(`{"alg":"RS256","kid":"missing"}`))
	payload := encode([]byte(`{"iss":"https://issuer.example","sub":"reviewer","aud":"warden-cli","exp":4102444800,"scope":"warden:decide"}`))
	signature := encode([]byte("signature"))
	return header + "." + payload + "." + signature
}

func permissionForAction(action string) authz.Permission {
	switch action {
	case audit.ActionEvidenceRead:
		return authz.EvidenceRead
	case audit.ActionDecisionPrepare:
		return authz.DecisionPrepare
	case audit.ActionDecisionAdd:
		return authz.DecisionAdd
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
