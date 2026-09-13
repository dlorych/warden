package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func testServer() *server {
	return &server{requests: map[string]*Request{}, failures: map[string]int{}, tokens: map[string]time.Time{}}
}

func TestInstallationTokenRequiresSignedAppJWTAndTracksToken(t *testing.T) {
	s := testServer()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	file := t.TempDir() + "/app-public.pem"
	if err := os.WriteFile(file, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_APP_PUBLIC_KEY_FILE", file)
	t.Setenv("GITHUB_APP_ID", "12345")

	claims := jwt.RegisteredClaims{Issuer: "12345", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute))}
	appJWT, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/app/installations/123/access_tokens", nil)
	req.Header.Set("Authorization", "Bearer "+appJWT)
	rec := httptest.NewRecorder()
	s.installationToken(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Token == "" {
		t.Fatalf("token response = %s", rec.Body.String())
	}
	valid := httptest.NewRequest(http.MethodGet, "/repos/acme/example/actions/runs/1", nil)
	valid.Header.Set("Authorization", "Bearer "+got.Token)
	if err := s.verifyInstallationToken(valid); err != nil {
		t.Fatalf("issued token rejected: %v", err)
	}
	invalid := httptest.NewRequest(http.MethodGet, "/repos/acme/example/actions/runs/1", nil)
	invalid.Header.Set("Authorization", "Bearer ghs_invalid")
	if err := s.verifyInstallationToken(invalid); err == nil {
		t.Fatal("invalid token accepted")
	}
}

func TestInstallationTokenFailsClosedWithoutPublicKeyFile(t *testing.T) {
	t.Setenv("GITHUB_APP_PUBLIC_KEY_FILE", t.TempDir()+"/missing.pem")
	req := httptest.NewRequest(http.MethodPost, "/app/installations/123/access_tokens", nil)
	req.Header.Set("Authorization", "Bearer anything")
	rec := httptest.NewRecorder()
	testServer().installationToken(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestWorkflowRunTargetsRunAndReportsCancellation(t *testing.T) {
	s := testServer()
	one := s.newRequest(createInput{Repository: "acme/example", CommitSHA: "one"})
	two := s.newRequest(createInput{Repository: "acme/example", CommitSHA: "two"})
	two.RunID = one.RunID + 1
	wantID := uuid.NewSHA1(uuid.NameSpaceURL, []byte(two.Repository+":"+strconv.FormatInt(two.DeploymentID, 10))).String()
	if two.ID != wantID {
		t.Fatalf("request ID = %s, want deterministic ID %s", two.ID, wantID)
	}
	s.requests[one.ID], s.requests[two.ID] = one, two
	s.tokens["ghs_test"] = time.Now().Add(time.Hour)

	path := "/repos/acme/example/actions/runs/" + strconv.FormatInt(two.RunID, 10)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer ghs_test")
	rec := httptest.NewRecorder()
	s.githubAPI(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var run map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run["id"] != float64(two.RunID) || run["head_sha"] != "two" {
		t.Fatalf("wrong run selected: %#v", run)
	}
	if run["status"] != "in_progress" || run["conclusion"] != nil {
		t.Fatalf("pending state = %#v", run)
	}

	two.Outcome = "cancelled"
	rec = httptest.NewRecorder()
	s.githubAPI(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if run["status"] != "completed" || run["conclusion"] != "cancelled" {
		t.Fatalf("cancelled state = %#v", run)
	}
	if run["head_sha"] == "one" {
		t.Fatal("run lookup fell back to another request")
	}
}

func TestCallbackStoresEvidenceComment(t *testing.T) {
	s := testServer()
	x := s.newRequest(createInput{Repository: "acme/example"})
	s.requests[x.ID] = x
	s.tokens["ghs_test"] = time.Now().Add(time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/repos/acme/example/actions/runs/"+strconv.FormatInt(x.RunID, 10)+"/deployment_protection_rule", strings.NewReader(`{"state":"approved","environment_name":"production","comment":"Warden decision recorded. Evidence: http://localhost:8080/evidence/abc"}`))
	req.Header.Set("Authorization", "Bearer ghs_test")
	rec := httptest.NewRecorder()
	s.githubAPI(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if x.CallbackComment == "" || !strings.Contains(x.CallbackComment, "/evidence/abc") {
		t.Fatalf("callback comment = %q", x.CallbackComment)
	}
}
