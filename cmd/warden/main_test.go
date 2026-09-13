package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wardenv/service/pkg/evidence"
)

func TestDecideChallengeBindsDisplayedContext(t *testing.T) {
	now := time.Now().UTC()
	cak, cac, _, _, _ := evidence.NewDevCA(now)
	_, _, certPEM, keyPEM, _ := evidence.NewDevCertificate(now, cac, cak, "22222222-2222-4222-8222-222222222222")
	dir := t.TempDir()
	certPath := filepath.Join(dir, "reviewer.pem")
	keyPath := filepath.Join(dir, "reviewer-key.pem")
	if os.WriteFile(certPath, certPEM, 0600) != nil || os.WriteFile(keyPath, keyPEM, 0600) != nil {
		t.Fatal("write dev credentials")
	}
	digest := "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{7}, 32))
	var challengeSeen bool
	var submit evidence.Bundle
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]any{"service": "wardenv", "request_id": "req1", "context_digest": digest, "context": map[string]any{"ref": "abc"}})
		case r.URL.Path == "/api/v1/requests/req1/challenges":
			var in map[string]string
			json.NewDecoder(r.Body).Decode(&in)
			if in["decision"] != "approved" || in["reason"] != "because many words" {
				http.Error(w, "bad challenge", 400)
				return
			}
			challengeSeen = true
			json.NewEncoder(w).Encode(map[string]any{"statement": evidence.Statement{Version: evidence.StatementVersion, Service: "wardenv", RequestID: "req1", ContextDigest: digest, Decision: "approved", Reason: in["reason"], Subject: "22222222-2222-4222-8222-222222222222", Nonce: "nonce", Expiry: time.Now().Add(time.Minute).Unix()}})
		case r.URL.Path == "/api/v1/requests/req1/decisions":
			json.NewDecoder(r.Body).Decode(&submit)
			w.WriteHeader(202)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	old := os.Stdin
	inR, inW, _ := os.Pipe()
	os.Stdin = inR
	defer func() { os.Stdin = old }()
	go func() { io.WriteString(inW, "approved\nbecause many words\ny\n"); inW.Close() }()
	if err := decideCmd([]string{"req1", "--api", srv.URL, "--access-token", "tok", "--key", keyPath, "--cert", certPath}); err != nil {
		t.Fatal(err)
	}
	if !challengeSeen || submit.Signed.Statement.RequestID != "req1" || submit.Signed.Statement.Reason != "because many words" || strings.TrimSpace(submit.Signed.Signature) == "" {
		t.Fatal("decision flow did not submit exact challenged statement")
	}
}

func TestEvidenceDownloadAcceptsIDBeforeFlags(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/requests/req1/evidence" || r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("unexpected request: %s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"signed":"bundle"}`))
	}))
	defer srv.Close()
	out := filepath.Join(t.TempDir(), "bundle.json")
	if err := downloadCmd([]string{"req1", "--api", srv.URL, "--access-token", "tok", "--output", out}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"signed":"bundle"}` {
		t.Fatalf("unexpected bundle: %s", got)
	}
	out2 := filepath.Join(t.TempDir(), "bundle.json")
	if err := downloadCmd([]string{"--api", srv.URL, "--access-token", "tok", "--output", out2, "req1"}); err != nil {
		t.Fatal(err)
	}
}
