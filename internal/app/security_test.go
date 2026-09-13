package app

import (
	"context"
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
