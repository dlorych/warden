// githubmock is a small, stateful GitHub App/API emulator for local development.
// It exercises the real webhook signature and App JWT exchange paths in Warden.
package main

import (
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Request struct {
	ID             string    `json:"id"`
	Repository     string    `json:"repository"`
	Environment    string    `json:"environment"`
	CommitSHA      string    `json:"commit_sha"`
	Requester      string    `json:"requester"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Decision       string    `json:"decision"`
	Outcome        string    `json:"outcome"`
	DeliveryStatus string    `json:"delivery_status"`
	LogStatus      string    `json:"log_status"`
	Reason         string    `json:"reason,omitempty"`
	Owner          string    `json:"owner"`
	Repo           string    `json:"repo"`
	DeploymentID   int64     `json:"deployment_id"`
	RunID          int64     `json:"run_id"`
	InstallationID int64     `json:"installation_id"`
}
type createInput struct {
	Repository  string `json:"repository"`
	Environment string `json:"environment"`
	CommitSHA   string `json:"commit_sha"`
	Requester   string `json:"requester"`
	Reason      string `json:"reason"`
	ExpiresIn   int    `json:"expires_in"`
}
type server struct {
	mu         sync.RWMutex
	requests   map[string]*Request
	failures   map[string]int
	tokens     map[string]time.Time
	privateLog *slog.Logger
}

func main() {
	s := &server{requests: map[string]*Request{}, failures: map[string]int{}, tokens: map[string]time.Time{}, privateLog: slog.Default()}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/mock/requests", s.mockRequests)
	mux.HandleFunc("/mock/requests/", s.mockRequest)
	mux.HandleFunc("/mock/failures", s.mockFailures)
	mux.HandleFunc("/app/installations/", s.installationToken)
	mux.HandleFunc("/repos/", s.githubAPI)
	mux.HandleFunc("/webhooks/github", s.webhookPassthrough)
	addr := env("ADDR", ":8090")
	s.privateLog.Info("github mock listening", "addr", addr)
	if err := http.ListenAndServe(addr, logging(mux)); err != nil {
		s.privateLog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
func env(k, d string) string {
	if x := os.Getenv(k); x != "" {
		return x
	}
	return d
}
func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	jsonOut(w, 200, map[string]string{"status": "ok"})
}
func jsonOut(w http.ResponseWriter, status int, x any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(x)
}
func jsonErr(w http.ResponseWriter, status int, e string) {
	jsonOut(w, status, map[string]string{"message": e})
}
func body(w http.ResponseWriter, r *http.Request, dst any) bool {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil || json.Unmarshal(b, dst) != nil {
		jsonErr(w, 400, "invalid JSON")
		return false
	}
	return true
}

func (s *server) mockRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.mu.RLock()
		out := make([]*Request, 0, len(s.requests))
		for _, x := range s.requests {
			copy := *x
			out = append(out, &copy)
		}
		s.mu.RUnlock()
		jsonOut(w, 200, map[string]any{"items": out})
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "method not allowed")
		return
	}
	var in createInput
	if !body(w, r, &in) {
		return
	}
	x := s.newRequest(in)
	s.mu.Lock()
	s.requests[x.ID] = x
	s.mu.Unlock()
	if err := s.emitRule(x); err != nil {
		s.privateLog.Warn("webhook delivery failed", "error", err)
		s.mu.Lock()
		x.DeliveryStatus = "failed"
		s.mu.Unlock()
	}
	jsonOut(w, 201, x)
}
func (s *server) newRequest(in createInput) *Request {
	repo := in.Repository
	if repo == "" {
		repo = "acme/example"
	}
	p := strings.SplitN(repo, "/", 2)
	if len(p) != 2 {
		p = []string{"acme", repo}
		repo = strings.Join(p, "/")
	}
	now := time.Now().UTC()
	ttl := in.ExpiresIn
	if ttl <= 0 {
		ttl = 45
	}
	id := uuid.NewString()
	dep := time.Now().UnixNano() % 100000000
	run := dep + 1000
	id = uuid.NewSHA1(uuid.NameSpaceURL, []byte(repo+":"+strconv.FormatInt(dep, 10))).String()
	return &Request{ID: id, Repository: repo, Owner: p[0], Repo: p[1], Environment: or(in.Environment, "production"), CommitSHA: or(in.CommitSHA, "0123456789abcdef0123456789abcdef01234567"), Requester: or(in.Requester, "demo@example.com"), CreatedAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Minute), Decision: "pending", Outcome: "pending", DeliveryStatus: "sent", LogStatus: "pending", Reason: in.Reason, DeploymentID: dep, RunID: run, InstallationID: 12345}
}
func or(x, d string) string {
	if x == "" {
		return d
	}
	return x
}
func (s *server) mockRequest(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/mock/requests/")
	if strings.Contains(id, "/") {
		id = strings.Split(id, "/")[0]
	}
	s.mu.RLock()
	x := s.requests[id]
	s.mu.RUnlock()
	if x == nil {
		jsonErr(w, 404, "request not found")
		return
	}
	if r.Method == "GET" {
		s.mu.RLock()
		copy := *x
		s.mu.RUnlock()
		jsonOut(w, 200, &copy)
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "method not allowed")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/trigger") {
		if err := s.emitRule(x); err != nil {
			jsonErr(w, 502, err.Error())
			return
		}
		s.mu.Lock()
		x.DeliveryStatus = "sent"
		s.mu.Unlock()
		jsonOut(w, 202, x)
		return
	}
	var in map[string]string
	if !body(w, r, &in) {
		return
	}
	s.mu.Lock()
	if v := in["outcome"]; v != "" {
		x.Outcome = v
	}
	if strings.HasSuffix(r.URL.Path, "/cancel") {
		x.Outcome, x.Decision = "cancelled", "cancelled"
	}
	if v := in["decision"]; v != "" {
		x.Decision = v
	}
	s.mu.Unlock()
	s.mu.RLock()
	copy := *x
	s.mu.RUnlock()
	jsonOut(w, 200, &copy)
}
func (s *server) mockFailures(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.mu.RLock()
		jsonOut(w, 200, map[string]any{"failures": s.failures})
		s.mu.RUnlock()
		return
	}
	if r.Method != "POST" {
		jsonErr(w, 405, "method not allowed")
		return
	}
	var in struct {
		Endpoint string `json:"endpoint"`
		Status   int    `json:"status"`
		Clear    bool   `json:"clear"`
	}
	if !body(w, r, &in) {
		return
	}
	if in.Endpoint == "" {
		jsonErr(w, 400, "endpoint required")
		return
	}
	s.mu.Lock()
	if in.Clear {
		delete(s.failures, in.Endpoint)
	} else {
		if in.Status == 0 {
			in.Status = 500
		}
		s.failures[in.Endpoint] = in.Status
	}
	s.mu.Unlock()
	jsonOut(w, 200, map[string]any{"endpoint": in.Endpoint, "status": in.Status, "clear": in.Clear})
}

func (s *server) emitRule(x *Request) error {
	target := env("BACKEND_WEBHOOK_URL", "http://warden:8080/webhooks/github")
	payload := map[string]any{"action": "requested", "deployment_callback_url": strings.TrimRight(env("GITHUB_PUBLIC_URL", "http://githubmock:8090"), "/") + "/repos/" + x.Owner + "/" + x.Repo + "/actions/runs/" + strconv.FormatInt(x.RunID, 10) + "/deployment_protection_rule", "deployment": map[string]any{"id": x.DeploymentID, "sha": x.CommitSHA, "ref": "main", "environment": x.Environment, "creator": map[string]any{"login": x.Requester}}, "environment": x.Environment, "repository": map[string]any{"full_name": x.Repository, "name": x.Repo, "owner": map[string]string{"login": x.Owner}}, "installation": map[string]int64{"id": x.InstallationID}, "sender": map[string]string{"login": x.Requester}}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(string(b)))
	if err != nil {
		return err
	}
	secret := env("GITHUB_WEBHOOK_SECRET", "local-webhook-secret")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "deployment_protection_rule")
	req.Header.Set("X-GitHub-Delivery", uuid.NewString())
	req.Header.Set("X-Hub-Signature-256", "sha256="+hmacHex([]byte(secret), b))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("webhook status %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}
func hmacHex(key, data []byte) string {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(data)
	return fmt.Sprintf("%x", m.Sum(nil))
}

func (s *server) webhookPassthrough(w http.ResponseWriter, r *http.Request) { // useful for inspecting manually posted events
	if r.Method != http.MethodPost {
		jsonErr(w, 405, "method not allowed")
		return
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if len(b) == 0 {
		jsonErr(w, 400, "empty webhook")
		return
	}
	jsonOut(w, 202, map[string]string{"status": "accepted"})
}

func (s *server) installationToken(w http.ResponseWriter, r *http.Request) {
	if !strings.HasSuffix(r.URL.Path, "/access_tokens") || r.Method != http.MethodPost {
		jsonErr(w, 404, "not found")
		return
	}
	if err := s.verifyAppJWT(r); err != nil {
		jsonErr(w, 401, "invalid app JWT: "+err.Error())
		return
	}
	token := "ghs_local_mock_" + uuid.NewString()
	exp := time.Now().UTC().Add(1 * time.Hour)
	s.mu.Lock()
	s.tokens[token] = exp
	s.mu.Unlock()
	jsonOut(w, 201, map[string]any{"token": token, "expires_at": exp, "permissions": map[string]string{"actions": "read", "deployments": "write", "contents": "read"}})
}
func (s *server) verifyAppJWT(r *http.Request) error {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		return errors.New("bearer token required")
	}
	raw := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	pubPath := strings.TrimSpace(os.Getenv("GITHUB_APP_PUBLIC_KEY_FILE"))
	if pubPath == "" {
		return errors.New("GITHUB_APP_PUBLIC_KEY_FILE is required")
	}
	publicBytes, err := os.ReadFile(pubPath)
	if err != nil {
		return fmt.Errorf("read app public key: %w", err)
	}
	pub := string(publicBytes)
	if pub == "" {
		return errors.New("GITHUB_APP_PUBLIC_KEY_FILE is empty")
	}
	block, _ := pem.Decode([]byte(pub))
	if block == nil {
		return errors.New("bad public key")
	}
	var key *rsa.PublicKey
	if k, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		key, _ = k.(*rsa.PublicKey)
	} else if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		key = k
	}
	if key == nil {
		return errors.New("unsupported public key")
	}
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodRS256 {
			return nil, errors.New("unexpected signing algorithm")
		}
		return key, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil || !tok.Valid {
		return errors.New("invalid signature")
	}
	if expected := os.Getenv("GITHUB_APP_ID"); expected != "" {
		iss, _ := tok.Claims.GetIssuer()
		if iss != expected {
			return errors.New("unexpected app issuer")
		}
	}
	if exp, err := tok.Claims.GetExpirationTime(); err != nil || exp == nil || exp.Time.Before(time.Now()) {
		return errors.New("expired token")
	}
	return nil
}

func (s *server) githubAPI(w http.ResponseWriter, r *http.Request) {
	if err := s.verifyInstallationToken(r); err != nil {
		jsonErr(w, 401, err.Error())
		return
	}
	if status := s.failureFor(r.URL.Path); status > 0 {
		jsonErr(w, status, "injected GitHub failure")
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 {
		jsonErr(w, 404, "not found")
		return
	}
	owner, repo := parts[1], parts[2]
	var target *Request
	s.mu.RLock()
	for _, x := range s.requests {
		if len(parts) >= 6 && parts[3] == "actions" && parts[4] == "runs" {
			run, _ := strconv.ParseInt(parts[5], 10, 64)
			if x.RunID == run {
				target = x
				break
			}
		} else if x.Owner == owner && x.Repo == repo {
			target = x
		}
	}
	s.mu.RUnlock()
	if target == nil {
		jsonErr(w, 404, "resource not found")
		return
	}
	// Actions run details, queried by webhook callback verification.
	if len(parts) >= 5 && parts[3] == "actions" && parts[4] == "runs" {
		if len(parts) >= 7 && parts[6] == "deployment_protection_rule" {
			if r.Method != http.MethodPost {
				jsonErr(w, 405, "method not allowed")
				return
			}
			var in struct {
				State           string `json:"state"`
				Environment     string `json:"environment"`
				EnvironmentName string `json:"environment_name"`
				Comment         string `json:"comment"`
			}
			if !body(w, r, &in) {
				return
			}
			if in.Environment == "" {
				in.Environment = in.EnvironmentName
			}
			s.mu.Lock()
			target.Decision = in.State
			target.Outcome = in.State
			target.DeliveryStatus = "delivered"
			s.mu.Unlock()
			jsonOut(w, 202, map[string]any{"id": target.RunID, "state": in.State, "environment": in.Environment, "comment": in.Comment})
			return
		}
		status, conclusion := workflowState(target)
		jsonOut(w, 200, map[string]any{"id": target.RunID, "run_number": 1, "head_sha": target.CommitSHA, "status": status, "conclusion": conclusion, "actor": map[string]any{"id": 42, "login": target.Requester}, "repository": map[string]string{"full_name": target.Repository}})
		return
	}
	if len(parts) >= 5 && parts[3] == "deployments" {
		depID, _ := strconv.ParseInt(parts[4], 10, 64)
		if depID == 0 {
			depID = target.DeploymentID
		}
		if len(parts) >= 6 && parts[5] == "statuses" {
			if r.Method == "POST" {
				var in map[string]any
				_ = body(w, r, &in)
				jsonOut(w, 201, map[string]any{"id": uuid.NewString(), "state": in["state"], "deployment_id": depID})
				return
			}
			jsonOut(w, 200, []any{})
			return
		}
		if len(parts) >= 6 && (parts[5] == "reviews" || parts[5] == "protection-rules") {
			jsonOut(w, 200, map[string]any{"id": uuid.NewString(), "environment": target.Environment, "state": target.Decision})
			return
		}
		jsonOut(w, 200, map[string]any{"id": depID, "sha": target.CommitSHA, "ref": "main", "environment": target.Environment, "creator": map[string]string{"login": target.Requester}, "repository": map[string]string{"full_name": target.Repository}})
		return
	}
	jsonErr(w, 404, "not found")
}
func workflowState(x *Request) (string, any) {
	switch strings.ToLower(x.Outcome) {
	case "cancelled", "canceled":
		return "completed", "cancelled"
	case "failed", "failure", "timed_out":
		return "completed", "failure"
	case "success", "succeeded":
		return "completed", "success"
	default:
		if strings.EqualFold(x.Decision, "cancelled") || strings.EqualFold(x.Decision, "canceled") {
			return "completed", "cancelled"
		}
		return "in_progress", nil
	}
}
func (s *server) verifyInstallationToken(r *http.Request) error {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		return errors.New("installation bearer token required")
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	s.mu.RLock()
	exp, ok := s.tokens[token]
	s.mu.RUnlock()
	if !ok || exp.Before(time.Now()) {
		return errors.New("invalid or expired installation token")
	}
	return nil
}
func (s *server) failureFor(endpoint string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for k, v := range s.failures {
		if k == endpoint || (k != "" && strings.Contains(endpoint, k)) {
			return v
		}
	}
	return 0
}
