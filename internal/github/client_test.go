package github

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClientRefreshesRevokedInstallationToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var issued atomic.Int32
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/7/access_tokens" {
			n := issued.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"token": "tok" + string(rune('0'+n)), "expires_at": "2099-01-01T00:00:00Z"})
			return
		}
		if r.URL.Path != "/repos/o/r/actions/runs/1" {
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer tok1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 1, "head_sha": "abc"})
	}))
	defer srv.Close()
	c := New(srv.URL, 1, "bad")
	c.PrivateKey = key
	got, e := c.GetWorkflowRun(t.Context(), "o", "r", 1, 7)
	if e != nil {
		t.Fatal(e)
	}
	if got.HeadSHA != "abc" || issued.Load() != 2 || calls.Load() != 2 {
		t.Fatalf("refresh failed: run=%+v issued=%d calls=%d", got, issued.Load(), calls.Load())
	}
}
func TestCallbackURLValidation(t *testing.T) {
	var got bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = true
		if r.Method != http.MethodPost || r.URL.Path != "/repos/o/r/actions/runs/7/deployment_protection_rule" {
			t.Errorf("unexpected callback: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := New(srv.URL, 0, "")
	valid := srv.URL + "/repos/o/r/actions/runs/7/deployment_protection_rule"
	if e := c.Callback(t.Context(), valid, 0, "approved", "prod", "ok"); e != nil {
		t.Fatal(e)
	}
	if !got {
		t.Fatal("callback was not sent")
	}
	if e := c.Callback(t.Context(), valid+"?x=1", 0, "approved", "prod", "ok"); e == nil {
		t.Fatal("query callback accepted")
	}
	if e := c.Callback(t.Context(), "http://other.test/repos/o/r/actions/runs/7/deployment_protection_rule", 0, "approved", "prod", "ok"); e == nil {
		t.Fatal("outside host accepted")
	}
	if e := c.Callback(t.Context(), srv.URL+"/repos/o/r/actions/runs/7/deployment", 0, "approved", "prod", "ok"); e == nil {
		t.Fatal("wrong callback path accepted")
	}
}
func TestAdapterContextRoundTrip(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var runCalls atomic.Int32
	var callbackCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/9/access_tokens" {
			json.NewEncoder(w).Encode(map[string]any{"token": "tok", "expires_at": "2099-01-01T00:00:00Z"})
			return
		}
		if r.URL.Path == "/repos/o/r/actions/runs/77" {
			runCalls.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"id": 77, "head_sha": "abc", "status": "in_progress", "actor": map[string]any{"id": 42, "login": "requester"}})
			return
		}
		if r.URL.Path == "/repos/o/r/actions/runs/77/deployment_protection_rule" {
			callbackCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	c := New(srv.URL, 1, "bad")
	c.PrivateKey = key
	c.AsAdapter("secret", map[string]string{"42": "subject"})
	payload := []byte(`{"action":"requested","sha":"abc","deployment_callback_url":"` + srv.URL + `/repos/o/r/actions/runs/77/deployment_protection_rule","deployment":{"id":5,"environment":"prod","sha":"abc"},"environment":"prod","repository":{"full_name":"o/r"},"installation":{"id":9}}`)
	h := hmac.New(sha256.New, []byte("secret"))
	h.Write(payload)
	ev, e := c.Webhook(t.Context(), payload, "sha256="+hex.EncodeToString(h.Sum(nil)))
	if e != nil {
		t.Fatal(e)
	}
	if ev.RequesterSubject != "subject" {
		t.Fatalf("subject %q", ev.RequesterSubject)
	}
	ok, e := c.Recheck(t.Context(), ev)
	if e != nil || !ok {
		t.Fatalf("recheck: %v %v", ok, e)
	}
	if e = c.Deliver(t.Context(), ev, "approved", "ok"); e != nil {
		t.Fatal(e)
	}
	if runCalls.Load() != 2 || callbackCalls.Load() != 1 {
		t.Fatalf("calls run=%d callback=%d", runCalls.Load(), callbackCalls.Load())
	}
}
