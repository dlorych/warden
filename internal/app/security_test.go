package app

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wardenv/service/internal/auth"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/pkg/evidence"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

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
