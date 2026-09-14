package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/auth"
	"github.com/wardenv/service/internal/authz"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/pkg/evidence"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type fakeAuditRepository struct {
	events []audit.Event
	err    error
	page   audit.Page
	order  []string
}

func (f *fakeAuditRepository) AppendAuditEvent(_ context.Context, event audit.Event) error {
	if f.err != nil {
		return f.err
	}
	f.order = append(f.order, "append")
	f.events = append(f.events, event)
	return nil
}
func (f *fakeAuditRepository) ListAuditEvents(context.Context, audit.Query) (audit.Page, error) {
	f.order = append(f.order, "select")
	return f.page, nil
}

func TestRecordAuditPreservesCorrelationAuthMethodAndUTF8UserAgent(t *testing.T) {
	repo := &fakeAuditRepository{}
	a := &App{Audit: repo}
	r := httptest.NewRequest(http.MethodGet, "/api/v1/requests/id", nil)
	r.Header.Set("User-Agent", strings.Repeat("a", 510)+"€")
	wantOperation, wantRequest := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	event := readAuditEvent(auditActor("subject", "name", []string{"reader"}, audit.ActorUser), audit.OutcomeSuccess, "read", "id")
	event.AuthMethod, event.OperationID, event.RequestID = "cookie", wantOperation, wantRequest
	if err := a.recordAudit(r, event, http.StatusOK); err != nil {
		t.Fatal(err)
	}
	if len(repo.events) != 1 {
		t.Fatalf("events=%d, want 1", len(repo.events))
	}
	got := repo.events[0]
	if got.AuthMethod != "cookie" || got.OperationID != wantOperation || got.RequestID != wantRequest {
		t.Fatalf("event correlation/auth = %#v", got)
	}
	if len(got.UserAgent) > 512 || !utf8.ValidString(got.UserAgent) {
		t.Fatalf("user-agent was not safely bounded: bytes=%d valid=%v", len(got.UserAgent), utf8.ValidString(got.UserAgent))
	}
}

func TestFailAuditReturns503WithoutProtectedPayload(t *testing.T) {
	a := &App{Audit: &fakeAuditRepository{err: errors.New("database unavailable")}}
	rr := httptest.NewRecorder()
	ok := a.failAudit(rr, httptest.NewRequest(http.MethodGet, "/bff/requests/id", nil), readAuditEvent(auditActor("subject", "", nil, audit.ActorUser), audit.OutcomeSuccess, "read", "id"), http.StatusOK)
	if ok || rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ok=%v status=%d, want false/503", ok, rr.Code)
	}
	if strings.Contains(rr.Body.String(), "protected") {
		t.Fatalf("failure response contained protected payload: %q", rr.Body.String())
	}
}

func TestParseAuditQueryValidatesFiniteFiltersAndRanges(t *testing.T) {
	q, err := parseAuditQuery(url.Values{
		"action": {"request.read"}, "outcome": {"success"}, "actor_id": {"subject"},
		"resource_id": {"request"}, "operation_id": {"11111111-1111-4111-8111-111111111111"},
		"from": {"2026-01-01T00:00:00Z"}, "to": {"2026-01-02T00:00:00Z"}, "limit": {"25"},
	})
	if err != nil || q.Limit != 25 || q.Action != "request.read" || q.From == nil || q.To == nil {
		t.Fatalf("query=%#v err=%v", q, err)
	}
	for _, values := range []url.Values{
		{"limit": {"101"}}, {"outcome": {"nope"}}, {"operation_id": {"bad"}},
		{"metadata": {"secret"}}, {"from": {"2026-02-01T00:00:00Z"}, "to": {"2026-01-01T00:00:00Z"}},
		{"cursor": {"not-a-cursor"}},
	} {
		if _, err := parseAuditQuery(values); err == nil {
			t.Fatalf("accepted invalid query %#v", values)
		}
	}
}

func TestParseAuditQueryValidatesKeysetCursor(t *testing.T) {
	valid := "eyJ0IjoiMTk3MC0wMS0wMVQwMDowMTo0MFoiLCJpIjo0fQ"
	if q, err := parseAuditQuery(url.Values{"cursor": {valid}}); err != nil || q.Cursor != valid {
		t.Fatalf("valid cursor rejected: q=%#v err=%v", q, err)
	}
	for _, raw := range []string{
		"not-a-cursor",
		"eyJ0IjoiMTk3MC0wMS0wMVQwMDAwMDAwMFoiLCJpIjo0fQ",
	} {
		if _, err := parseAuditQuery(url.Values{"cursor": {raw}}); err == nil {
			t.Fatalf("accepted malformed cursor %q", raw)
		}
	}
}

func TestSelectAndAuditReadSelectsSnapshotBeforeAppendingEvent(t *testing.T) {
	repo := &fakeAuditRepository{page: audit.Page{Items: []audit.Event{{ID: 7}}}}
	a := &App{Audit: repo}
	page, queryErr, appendErr := a.selectAndAuditRead(httptest.NewRequest(http.MethodGet, "/bff/audit", nil), audit.Query{Limit: 10}, auditActor("auditor", "", []string{"auditor"}, audit.ActorUser))
	if queryErr != nil || appendErr != nil || len(page.Items) != 1 {
		t.Fatalf("page=%#v queryErr=%v appendErr=%v", page, queryErr, appendErr)
	}
	if strings.Join(repo.order, ",") != "select,append" {
		t.Fatalf("operation order=%v, want select,append", repo.order)
	}
}

func TestHandlerAuthorizationUsesRolePrecheckAndResourceDenial(t *testing.T) {
	a := &App{Policy: authz.Policy{}}
	// Once the request is loaded, the handler supplies its requester subject.
	if a.allows([]string{"reviewer"}, "requester-subject", authz.DecisionAdd, authz.Resource{RequestID: "request", RequesterSubject: "requester-subject"}) {
		t.Fatal("self-review was allowed")
	}
	if a.allows([]string{"auditor"}, "auditor-subject", authz.RequestRead, authz.Resource{RequestID: "request"}) {
		t.Fatal("auditor-only principal was allowed to read an approval request")
	}
}

func TestCLIHandlersDeferTerminalDecisionAuthorizationUntilResourceLookup(t *testing.T) {
	a := &App{Policy: authz.Policy{}}
	action, resourceAware := cliPermission("/requests/request/challenges")
	if action != authz.DecisionPrepare || !resourceAware {
		t.Fatalf("challenge dispatch = %s, resourceAware=%v", action, resourceAware)
	}
	reviewer := authz.Principal{Subject: "reviewer-subject", Roles: []authz.Role{authz.RoleReviewer}}
	if !authz.HasRole(reviewer, authz.RoleReviewer) {
		t.Fatal("reviewer was rejected by coarse route gate")
	}
	if decision := a.authorize([]string{"reviewer"}, reviewer.Subject, action, authz.Resource{RequestID: "request"}); decision.Allowed || decision.Reason != authz.ReasonResourceContext {
		t.Fatalf("terminal authorization did not require resource owner: %#v", decision)
	}
	if decision := a.authorize([]string{"reviewer"}, reviewer.Subject, action, authz.Resource{RequestID: "request", RequesterSubject: "requester-subject"}); !decision.Allowed {
		t.Fatalf("valid reviewer was denied after resource lookup: %#v", decision)
	}
	if action, resourceAware := cliPermission("/requests/request"); action != authz.RequestRead || resourceAware {
		t.Fatalf("request dispatch = %s, resourceAware=%v", action, resourceAware)
	}
}

type fakeSource struct{ err error }

func (f fakeSource) Webhook(context.Context, []byte, string) (source.Event, error) {
	return source.Event{}, f.err
}
func (f fakeSource) Recheck(context.Context, source.Event) (bool, error)         { return true, nil }
func (f fakeSource) Deliver(context.Context, source.Event, string, string) error { return nil }
func TestWebhookAdapterErrorMapping(t *testing.T) {
	for _, tc := range []struct {
		err    error
		status int
	}{{source.ErrInvalidSignature, 401}, {source.ErrIgnored, 204}, {source.ErrMalformed, 400}, {source.ErrUpstream, 502}} {
		a := &App{Source: fakeSource{tc.err}}
		rr := httptest.NewRecorder()
		a.githubWebhook(rr, httptest.NewRequest(http.MethodPost, "/webhooks/github", nil))
		if rr.Code != tc.status {
			t.Fatalf("error %v status %d want %d", tc.err, rr.Code, tc.status)
		}
	}
}

func TestNoStoreMiddleware(t *testing.T) {
	rr := httptest.NewRecorder()
	noStore(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/bff/session", nil))
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache header=%q", rr.Header().Get("Cache-Control"))
	}
}

func TestDecisionCommentUsesStablePublicEvidenceURL(t *testing.T) {
	a := &App{Config: Config{PublicURL: "https://warden.example/"}}
	want := "Warden decision recorded. Evidence: https://warden.example/evidence/11111111-1111-4111-8111-111111111111"
	if got := a.decisionComment("11111111-1111-4111-8111-111111111111"); got != want {
		t.Fatalf("comment = %q, want %q", got, want)
	}
}

func TestOIDCLogoutURLRefreshesDiscoveryOnDemand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":               "http://" + r.Host,
			"end_session_endpoint": "http://" + r.Host + "/logout",
		})
	}))
	defer server.Close()

	a := &App{
		Auth:   auth.New(auth.Config{OIDCIssuer: server.URL, OIDCClientID: "warden-bff"}),
		Config: Config{OIDCPostLogoutRedirectURL: "http://localhost:8080/"},
	}
	got := a.oidcLogoutURL(t.Context())
	want := fmt.Sprintf("%s/logout?client_id=warden-bff&post_logout_redirect_uri=http%%3A%%2F%%2Flocalhost%%3A8080%%2F", server.URL)
	if got != want {
		t.Fatalf("logout URL=%q want %q", got, want)
	}
}

func TestEvidenceCertificateRequiresConfiguredTrustAndSubject(t *testing.T) {
	now := time.Now()
	cak, cac, capem, _, err := evidence.NewDevCA(now)
	if err != nil {
		t.Fatal(err)
	}
	_, cert, certpem, _, err := evidence.NewDevCertificate(now, cac, cak, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Config: Config{EvidenceTrustPEM: string(capem)}}
	chain, e := parseCerts([]string{string(certpem), string(capem)})
	if e != nil {
		t.Fatal(e)
	}
	if e = a.verifyEvidenceCertificate(chain, "reviewer"); e != nil {
		t.Fatalf("trusted cert rejected: %v", e)
	}
	_ = cert
}
