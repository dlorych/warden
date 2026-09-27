package app

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/authz"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/internal/store"
	"github.com/wardenv/service/pkg/evidence"
)

type workerTraceSource struct {
	trace      *[]string
	recheckOK  bool
	recheckErr error
	deliverErr error
}

func (s workerTraceSource) Webhook(context.Context, []byte, string) (source.Event, error) {
	return source.Event{}, nil
}
func (s workerTraceSource) Recheck(context.Context, source.Event) (bool, error) {
	*s.trace = append(*s.trace, "recheck")
	return s.recheckOK, s.recheckErr
}
func (s workerTraceSource) Deliver(context.Context, source.Event, string, string) error {
	*s.trace = append(*s.trace, "deliver")
	return s.deliverErr
}

type workerAuditSink struct {
	events []audit.Event
	err    error
	trace  *[]string
}

func (s *workerAuditSink) AppendAuditEvent(_ context.Context, event audit.Event) error {
	if s.err != nil {
		return s.err
	}
	s.events = append(s.events, event)
	if s.trace != nil {
		*s.trace = append(*s.trace, "audit:"+string(event.Outcome)+":"+event.ActionCode)
	}
	return nil
}
func (*workerAuditSink) ListAuditEvents(context.Context, audit.Query) (audit.Page, error) {
	return audit.Page{}, nil
}

func workerTestRequest() store.Request {
	return store.Request{ID: "11111111-1111-4111-8111-111111111111", Decision: "approved", ExpiresAt: time.Now().Add(time.Hour)}
}

func publicationTestApp(t *testing.T, sink *workerAuditSink, trace *[]string) (*App, evidence.Bundle) {
	t.Helper()
	now := time.Now().UTC()
	caKey, ca, caPEM, _, err := evidence.NewDevCA(now)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _, leafPEM, _, err := evidence.NewDevCertificate(now, ca, caKey, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	signed, err := evidence.SignStatement(evidence.Statement{
		Service: "wardenv", RequestID: workerTestRequest().ID, ContextDigest: strings.Repeat("1", 64),
		Decision: "approved", Subject: "reviewer", Nonce: "nonce", Expiry: now.Add(time.Hour).Unix(),
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	bundle := evidence.Bundle{Version: evidence.StatementVersion, Signed: signed, CertificateChain: []string{string(leafPEM), string(caPEM)}}
	a := &App{
		Audit: sink, Policy: authz.Policy{}, Config: Config{
			EvidenceTrustPEM:   string(caPEM),
			RekorCheckpointKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		},
	}
	a.workerGetRequest = func(context.Context, string) (store.Request, error) { return workerTestRequest(), nil }
	a.workerRekorSubmit = func(context.Context, evidence.SignedDecision, *x509.Certificate) (*evidence.RekorProof, error) {
		if trace != nil {
			*trace = append(*trace, "rekor")
		}
		return &evidence.RekorProof{}, nil
	}
	a.workerVerifyPublicationFn = func(evidence.Bundle, *x509.CertPool, ed25519.PublicKey, string) error { return nil }
	a.workerSavePublishedAndMarkFn = func(_ context.Context, _ string, _ []byte, event audit.Event) error {
		if trace != nil {
			*trace = append(*trace, "save")
		}
		sink.events = append(sink.events, event)
		return nil
	}
	a.workerSetStatusesFn = func(_ context.Context, _ string, _, _ string, event audit.Event) error {
		sink.events = append(sink.events, event)
		return nil
	}
	a.Source = workerTraceSource{trace: trace, recheckOK: false}
	return a, bundle
}

func TestWorkerPublicationStartedPrecedesRekorAndAtomicTerminalSave(t *testing.T) {
	trace := []string{}
	sink := &workerAuditSink{trace: &trace}
	a, bundle := publicationTestApp(t, sink, &trace)
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.publish(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", RequestID: workerTestRequest().ID, Attempts: 1, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	started, terminal := -1, -1
	for i, event := range sink.events {
		if event.ActionCode == audit.ActionTransparencyPublish && event.Outcome == audit.OutcomeStarted {
			started = i
		}
		if event.ActionCode == audit.ActionTransparencyPublish && event.Outcome == audit.OutcomeSuccess {
			terminal = i
		}
	}
	if started < 0 || terminal < 0 || sink.events[started].OperationID != sink.events[terminal].OperationID {
		t.Fatalf("publication events=%#v", sink.events)
	}
	startedTrace, rekorTrace, saveTrace := indexOf(trace, "audit:started:transparency.publish"), indexOf(trace, "rekor"), indexOf(trace, "save")
	if !(startedTrace >= 0 && startedTrace < rekorTrace && rekorTrace < saveTrace) {
		t.Fatalf("publication ordering=%v", trace)
	}
}

func TestWorkerPublicationStartedAuditFailureSuppressesRekor(t *testing.T) {
	trace := []string{}
	sink := &workerAuditSink{err: errors.New("audit unavailable"), trace: &trace}
	a, bundle := publicationTestApp(t, sink, &trace)
	payload, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.publish(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", RequestID: workerTestRequest().ID, Attempts: 1, Payload: payload}); err == nil {
		t.Fatal("started audit failure was ignored")
	}
	if indexOf(trace, "rekor") >= 0 {
		t.Fatalf("Rekor invoked after started audit failure: %v", trace)
	}
}

func TestWorkerPublicationValidationFailuresAreAuditedWithoutStarted(t *testing.T) {
	for _, test := range []struct {
		name, payload, reason string
	}{
		{name: "malformed", payload: "{", reason: "evidence_bundle_invalid"},
		{name: "statement", payload: `{}`, reason: "statement_missing"},
		{name: "certificate", payload: `{"signed":{"statement":{"request_id":"11111111-1111-4111-8111-111111111111"}}}`, reason: "certificate_chain_missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			sink := &workerAuditSink{}
			a, _ := publicationTestApp(t, sink, nil)
			err := a.publish(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", RequestID: workerTestRequest().ID, Attempts: 1, Payload: []byte(test.payload)})
			if err == nil {
				t.Fatal("invalid publication was accepted")
			}
			if len(sink.events) != 1 || sink.events[0].Outcome != audit.OutcomeInvalid || sink.events[0].Reason != test.reason {
				t.Fatalf("events=%#v", sink.events)
			}
		})
	}
}

func TestWorkerPublishedRequestSkipsRekor(t *testing.T) {
	trace := []string{}
	sink := &workerAuditSink{}
	a, _ := publicationTestApp(t, sink, &trace)
	a.workerGetRequest = func(context.Context, string) (store.Request, error) {
		req := workerTestRequest()
		req.LogStatus = "published"
		return req, nil
	}
	if err := a.publish(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", RequestID: workerTestRequest().ID, Attempts: 1}); err != nil {
		t.Fatal(err)
	}
	if indexOf(trace, "rekor") >= 0 {
		t.Fatalf("published request invoked Rekor: %v", trace)
	}
}

func TestWorkerRetryAttemptsShareOperationAndExposeDistinctAttemptMetadata(t *testing.T) {
	one := newWorkerOperation(store.Job{ID: "22222222-2222-4222-8222-222222222222", Attempts: 1}, workerTestRequest().ID, audit.ActionTransparencyPublish)
	two := newWorkerOperation(store.Job{ID: "22222222-2222-4222-8222-222222222222", Attempts: 2}, workerTestRequest().ID, audit.ActionTransparencyPublish)
	if one.operationID != two.operationID || one.logicalOperationID != two.logicalOperationID {
		t.Fatalf("retry operation IDs=%q/%q logical=%q/%q", one.operationID, two.operationID, one.logicalOperationID, two.logicalOperationID)
	}
	var first, second map[string]any
	if err := json.Unmarshal(one.metadata(), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(two.metadata(), &second); err != nil {
		t.Fatal(err)
	}
	if first["attempt"] == second["attempt"] {
		t.Fatalf("retry attempt metadata did not differ: %v/%v", first, second)
	}
}

func indexOf(values []string, want string) int {
	for i, value := range values {
		if value == want {
			return i
		}
	}
	return -1
}

func TestWorkerExternalCallsFollowStartedEventsAndCorrelateAttempts(t *testing.T) {
	trace := []string{}
	sink := &workerAuditSink{trace: &trace}
	statuses := []string{}
	a := &App{Audit: sink, Policy: authz.Policy{}, Source: workerTraceSource{trace: &trace, recheckOK: true}}
	a.workerSetStatusesFn = func(_ context.Context, _ string, _, delivery string, event audit.Event) error {
		statuses = append(statuses, delivery)
		sink.events = append(sink.events, event)
		if event.Outcome != audit.OutcomeSuccess {
			t.Fatalf("status event outcome=%q", event.Outcome)
		}
		return nil
	}
	req := workerTestRequest()
	if err := a.deliverJob(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", Attempts: 1}, req); err != nil {
		t.Fatal(err)
	}
	if strings.Index(trace[0], "started") < 0 || trace[1] != "recheck" || strings.Index(trace[3], "started") < 0 || trace[len(trace)-1] != "deliver" {
		t.Fatalf("call ordering=%v", trace)
	}
	if len(sink.events) != 4 || sink.events[0].OperationID != sink.events[1].OperationID || sink.events[2].OperationID != sink.events[3].OperationID || sink.events[0].OperationID == sink.events[2].OperationID {
		t.Fatalf("operation correlation=%#v", sink.events)
	}
	var firstMeta, secondMeta map[string]any
	if err := json.Unmarshal(sink.events[0].Metadata, &firstMeta); err != nil {
		t.Fatal(err)
	}
	if firstMeta["phase"] != audit.ActionSourceRecheck || firstMeta["attempt"].(float64) != 1 {
		t.Fatalf("unsafe or incorrect metadata=%v", firstMeta)
	}
	if err := json.Unmarshal(sink.events[2].Metadata, &secondMeta); err != nil {
		t.Fatal(err)
	}
	if secondMeta["phase"] != audit.ActionSourceDeliver || secondMeta["logical_operation_id"] == firstMeta["logical_operation_id"] {
		t.Fatalf("phases were not independently correlated=%v/%v", firstMeta, secondMeta)
	}
	if len(statuses) != 1 || statuses[0] != "delivered" {
		t.Fatalf("statuses=%v", statuses)
	}
}

func TestWorkerIneligibleRecheckCancelsAtomicallyAndDoesNotDeliver(t *testing.T) {
	trace := []string{}
	sink := &workerAuditSink{}
	var status string
	a := &App{Audit: sink, Policy: authz.Policy{}, Source: workerTraceSource{trace: &trace, recheckOK: false}}
	a.workerSetStatusesFn = func(_ context.Context, _ string, _, delivery string, event audit.Event) error {
		status = delivery
		sink.events = append(sink.events, event)
		return nil
	}
	if err := a.deliverJob(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", Attempts: 1}, workerTestRequest()); err != nil {
		t.Fatal(err)
	}
	if len(trace) != 1 || trace[0] != "recheck" {
		t.Fatalf("source calls=%v, wanted recheck only", trace)
	}
	if status != "cancelled" || len(sink.events) != 2 || sink.events[0].Outcome != audit.OutcomeStarted || sink.events[1].Reason != "not_eligible" {
		t.Fatalf("status=%q events=%#v", status, sink.events)
	}
}

func TestWorkerDoesNotInvokeSourceBeforeStartedAudit(t *testing.T) {
	trace := []string{}
	a := &App{Audit: &workerAuditSink{err: errors.New("audit unavailable")}, Policy: authz.Policy{}, Source: workerTraceSource{trace: &trace, recheckOK: true}}
	a.workerSetStatusesFn = func(context.Context, string, string, string, audit.Event) error { return nil }
	if err := a.deliverJob(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", Attempts: 1}, workerTestRequest()); err == nil {
		t.Fatal("audit failure was ignored")
	}
	if len(trace) != 0 {
		t.Fatalf("source invoked after started audit failure: %v", trace)
	}
}

type denyWorkerAuthorizer struct{}

func (denyWorkerAuthorizer) Authorize(req authz.Request) authz.Decision {
	return authz.Decision{Permission: req.Permission, PolicyVersion: "test-policy", Reason: authz.ReasonRoleMissing}
}

func TestWorkerAuthorizationDenialIsAuditedAndPreventsExternalCall(t *testing.T) {
	trace := []string{}
	sink := &workerAuditSink{trace: &trace}
	a := &App{Audit: sink, Policy: denyWorkerAuthorizer{}, Source: workerTraceSource{trace: &trace, recheckOK: true}}
	a.workerSetStatusesFn = func(context.Context, string, string, string, audit.Event) error { return nil }
	if err := a.deliverJob(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", Attempts: 1}, workerTestRequest()); err == nil {
		t.Fatal("authorization denial was ignored")
	}
	if len(trace) != 1 || trace[0] != "audit:denied:source.recheck" {
		t.Fatalf("denial trace=%v", trace)
	}
	if len(sink.events) != 1 || sink.events[0].Permission != string(authz.SourceDeliver) || sink.events[0].PolicyVersion != "test-policy" {
		t.Fatalf("denial event=%#v", sink.events)
	}
}

func TestWorkerTerminalStatusAuditFailureLeavesStartedOnly(t *testing.T) {
	sink := &workerAuditSink{}
	trace := []string{}
	a := &App{Audit: sink, Policy: authz.Policy{}, Source: workerTraceSource{trace: &trace, recheckOK: true}}
	a.workerSetStatusesFn = func(context.Context, string, string, string, audit.Event) error {
		return &store.AuditAppendError{Err: errors.New("audit unavailable")}
	}
	if err := a.deliverJob(context.Background(), store.Job{ID: "22222222-2222-4222-8222-222222222222", Attempts: 1}, workerTestRequest()); err == nil {
		t.Fatal("terminal audit failure was ignored")
	}
	if len(trace) != 2 || trace[0] != "recheck" || trace[1] != "deliver" {
		t.Fatalf("source calls=%v", trace)
	}
	if len(sink.events) != 3 || sink.events[0].Outcome != audit.OutcomeStarted || sink.events[1].Outcome != audit.OutcomeSuccess || sink.events[2].Outcome != audit.OutcomeStarted {
		t.Fatalf("events=%#v", sink.events)
	}
}
