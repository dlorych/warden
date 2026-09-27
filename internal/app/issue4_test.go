package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/store"
)

func TestOIDCCallbackUnavailableIsOperationalFailure(t *testing.T) {
	outcome, reason, status, title := classifyOIDCCallbackFailure(nil, nil)
	if outcome != audit.OutcomeFailed || reason != "oidc_unavailable" || status != http.StatusServiceUnavailable || title != "OIDC unavailable" {
		t.Fatalf("nil OIDC callback failure = %q, %q, %d, %q", outcome, reason, status, title)
	}
}

func TestOperationForStateIsStableUUIDWithoutPersistingState(t *testing.T) {
	first := operationForState("state-value")
	if first != operationForState("state-value") {
		t.Fatal("state operation was not stable")
	}
	if first == operationForState("other-state") || !strings.Contains(first, "-") {
		t.Fatalf("operation correlation = %q", first)
	}
	if strings.Contains(first, "state-value") {
		t.Fatal("raw state appeared in operation correlation")
	}
}

func TestSafeAuditMetadataAddsStatusAndExcludesSensitiveValues(t *testing.T) {
	raw := json.RawMessage(`{"returned":2,"password":"secret","token":"bearer"}`)
	got := string(safeAuditMetadata(raw, 200))
	if !strings.Contains(got, `"http_status":200`) || !strings.Contains(got, `"returned":2`) {
		t.Fatalf("metadata = %s", got)
	}
	if strings.Contains(got, "secret") || strings.Contains(got, "bearer") {
		t.Fatalf("sensitive metadata survived sanitization: %s", got)
	}
}

func TestBrowserAuditActionCodesAndPermissions(t *testing.T) {
	actor := auditActor("subject", "name", []string{"reader"}, audit.ActorUser)
	if event := requestListAuditEvent(actor, audit.OutcomeSuccess, "list"); event.ActionCode != audit.ActionRequestList || event.Permission != "request.read" {
		t.Fatalf("request list event = %#v", event)
	}
	if event := decisionListAuditEvent(actor, audit.OutcomeSuccess, "list"); event.ActionCode != audit.ActionDecisionList || event.Permission != "decision.read" || event.ResourceType != "deployment_decision" {
		t.Fatalf("decision list event = %#v", event)
	}
	if event := evidenceAuditEvent(actor, audit.OutcomeSuccess, "read", "id"); event.ActionCode != audit.ActionEvidenceRead || event.Permission != "evidence.read" || event.ResourceType != "protected_evidence" {
		t.Fatalf("evidence event = %#v", event)
	}
}

func TestAuthAuditActionsCarryNoAuthorizationPolicyEvidence(t *testing.T) {
	actor := auditActor("subject", "name", []string{"reader"}, audit.ActorUser)
	for _, action := range []string{audit.ActionAuthLogin, audit.ActionAuthLogout} {
		event := authAuditEvent(actor, action, audit.OutcomeInvalid, "csrf_invalid")
		if event.Permission != "" || event.PolicyVersion != "" {
			t.Fatalf("%s carried authorization evidence: %#v", action, event)
		}
	}
	if event := authAuditEvent(actor, audit.ActionAuthLogout, audit.OutcomeInvalid, "csrf_invalid"); event.Outcome != audit.OutcomeInvalid {
		t.Fatalf("CSRF validation outcome = %q", event.Outcome)
	}
}

func TestAtomicAuditFailureUsesEmergencyMarkerWithoutSecrets(t *testing.T) {
	var output bytes.Buffer
	a := &App{logger: slog.New(slog.NewJSONHandler(&output, nil))}
	event := audit.Event{ActionCode: audit.ActionAuthLogin, Outcome: audit.OutcomeSuccess, Route: "/bff/callback"}
	err := &store.AuditAppendError{Err: errors.New("database unavailable")}
	a.logAuditFailure(event, err)
	if !strings.Contains(output.String(), `"emergency":true`) {
		t.Fatalf("audit failure lacked emergency marker: %s", output.String())
	}
	if strings.Contains(output.String(), "token") || strings.Contains(output.String(), "secret") {
		t.Fatalf("audit failure leaked sensitive values: %s", output.String())
	}
}
