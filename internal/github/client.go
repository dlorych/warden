package github

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/wardenv/service/internal/source"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type cachedToken struct {
	value  string
	expiry time.Time
}
type Client struct {
	BaseURL       string
	AppID         int64
	PrivateKey    *rsa.PrivateKey
	http          *http.Client
	mu            sync.Mutex
	tokens        map[int64]cachedToken
	WebhookSecret string
	ActorSubjects map[string]string
}

var _ source.Adapter = (*Client)(nil)

func New(base string, id int64, pemText string) *Client {
	c := &Client{BaseURL: strings.TrimRight(base, "/"), AppID: id, http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, tokens: make(map[int64]cachedToken)}
	if pemText != "" {
		c.PrivateKey = parseKey(pemText)
	}
	return c
}
func parseKey(v string) *rsa.PrivateKey {
	b, _ := pem.Decode([]byte(v))
	if b == nil {
		return nil
	}
	if k, e := x509.ParsePKCS8PrivateKey(b.Bytes); e == nil {
		if r, ok := k.(*rsa.PrivateKey); ok {
			return r
		}
	}
	if r, e := x509.ParsePKCS1PrivateKey(b.Bytes); e == nil {
		return r
	}
	return nil
}
func (c *Client) installationToken(ctx context.Context, installation int64) (string, error) {
	if c.PrivateKey == nil || c.AppID == 0 {
		return "", fmt.Errorf("github app credentials are not configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cached := c.tokens[installation]; cached.value != "" && time.Until(cached.expiry) > time.Minute {
		return cached.value, nil
	}
	now := time.Now()
	claims := jwt.RegisteredClaims{Issuer: strconv.FormatInt(c.AppID, 10), IssuedAt: jwt.NewNumericDate(now.Add(-30 * time.Second)), ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute))}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	raw, e := t.SignedString(c.PrivateKey)
	if e != nil {
		return "", e
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+fmt.Sprintf("/app/installations/%d/access_tokens", installation), nil)
	if e != nil {
		return "", e
	}
	req.Header.Set("Authorization", "Bearer "+raw)
	req.Header.Set("Accept", "application/vnd.github+json")
	res, e := c.http.Do(req)
	if e != nil {
		return "", e
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return "", fmt.Errorf("github token: %s", res.Status)
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&out); e != nil {
		return "", e
	}
	c.tokens[installation] = cachedToken{value: out.Token, expiry: out.ExpiresAt}
	return out.Token, nil
}
func (c *Client) evictToken(installation int64) {
	c.mu.Lock()
	delete(c.tokens, installation)
	c.mu.Unlock()
}

type Deployment struct {
	Environment  string         `json:"environment"`
	SHA          string         `json:"sha"`
	Repository   string         `json:"repository"`
	Installation int64          `json:"installation_id"`
	CallbackURL  string         `json:"deployment_callback_url"`
	Requester    string         `json:"requester"`
	Context      map[string]any `json:"context"`
}
type WorkflowRun struct {
	ID         int64  `json:"id"`
	RunAttempt int64  `json:"run_attempt"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HeadSHA    string `json:"head_sha"`
	Name       string `json:"name"`
	Actor      struct {
		ID   int64  `json:"id"`
		Name string `json:"login"`
	} `json:"actor"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
}

func (c *Client) do(ctx context.Context, method, path string, installation int64, body any, out any) error {
	var payload []byte
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return e
		}
		payload = b
	}
	for attempt := 0; attempt < 2; attempt++ {
		var rd io.Reader
		if payload != nil {
			rd = bytes.NewReader(payload)
		}
		req, e := http.NewRequestWithContext(ctx, method, c.BaseURL+path, rd)
		if e != nil {
			return e
		}
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if installation > 0 {
			tok, e := c.installationToken(ctx, installation)
			if e != nil {
				return e
			}
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		res, e := c.http.Do(req)
		if e != nil {
			return e
		}
		if res.StatusCode == http.StatusUnauthorized && installation > 0 && attempt == 0 {
			res.Body.Close()
			c.evictToken(installation)
			continue
		}
		defer res.Body.Close()
		if res.StatusCode/100 != 2 {
			return fmt.Errorf("github api %s: %s", path, res.Status)
		}
		if out != nil {
			return json.NewDecoder(io.LimitReader(res.Body, 4<<20)).Decode(out)
		}
		return nil
	}
	return fmt.Errorf("github api %s: unauthorized after token refresh", path)
}
func (c *Client) GetWorkflowRun(ctx context.Context, owner, repo string, id int64, installation int64) (WorkflowRun, error) {
	var x WorkflowRun
	e := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/actions/runs/%d", url.PathEscape(owner), url.PathEscape(repo), id), installation, nil, &x)
	return x, e
}
func (c *Client) GetDeployment(ctx context.Context, owner, repo string, id int64, installation int64) (Deployment, error) {
	var x Deployment
	e := c.do(ctx, http.MethodGet, fmt.Sprintf("/repos/%s/%s/deployments/%d", url.PathEscape(owner), url.PathEscape(repo), id), installation, nil, &x)
	return x, e
}
func (c *Client) Callback(ctx context.Context, callback string, installation int64, state, environment, comment string) error {
	callbackPath, e := c.validateCallback(callback)
	if e != nil {
		return e
	}
	return c.do(ctx, http.MethodPost, callbackPath, installation, map[string]string{"state": state, "environment_name": environment, "comment": comment}, nil)
}
func (c *Client) validateCallback(callback string) (string, error) {
	u, e := url.Parse(callback)
	base, _ := url.Parse(c.BaseURL)
	if e != nil || base == nil || u.Scheme != base.Scheme || u.Host != base.Host || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, strings.TrimRight(base.Path, "/")+"/repos/") {
		return "", fmt.Errorf("callback URL outside github API")
	}
	callbackPath := u.EscapedPath()
	if base.Path != "" {
		callbackPath = strings.TrimPrefix(callbackPath, strings.TrimRight(base.Path, "/"))
	}
	if !callbackRE.MatchString(callbackPath) {
		return "", fmt.Errorf("callback URL is not a deployment protection callback")
	}
	return callbackPath, nil
}

var callbackRE = regexp.MustCompile(`^/repos/[^/]+/[^/]+/actions/runs/[0-9]+/deployment_protection_rule$`)

func (c *Client) AsAdapter(secret string, subjects map[string]string) source.Adapter {
	c.WebhookSecret = secret
	c.ActorSubjects = subjects
	return c
}
func (c *Client) Webhook(ctx context.Context, raw []byte, signature string) (source.Event, error) {
	if !validHMAC(raw, signature, c.WebhookSecret) {
		return source.Event{}, source.ErrInvalidSignature
	}
	var ev struct {
		Action      string `json:"action"`
		SHA         string `json:"sha"`
		Environment string `json:"environment"`
		Deployment  struct {
			ID          int64  `json:"id"`
			Environment string `json:"environment"`
			SHA         string `json:"sha"`
		} `json:"deployment"`
		DeploymentCallbackURL string `json:"deployment_callback_url"`
		Repository            struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Installation struct {
			ID int64 `json:"id"`
		} `json:"installation"`
	}
	if json.Unmarshal(raw, &ev) != nil {
		return source.Event{}, source.ErrMalformed
	}
	if ev.Action != "requested" && ev.Action != "queued" && ev.Action != "waiting" {
		return source.Event{}, source.ErrIgnored
	}
	parts := strings.Split(ev.Repository.FullName, "/")
	if len(parts) != 2 {
		return source.Event{}, fmt.Errorf("%w: invalid repository", source.ErrMalformed)
	}
	runID, ok := callbackRunID(ev.DeploymentCallbackURL)
	if !ok {
		return source.Event{}, fmt.Errorf("%w: invalid deployment callback URL", source.ErrMalformed)
	}
	if _, e := c.validateCallback(ev.DeploymentCallbackURL); e != nil {
		return source.Event{}, fmt.Errorf("%w: %v", source.ErrMalformed, e)
	}
	run, e := c.GetWorkflowRun(ctx, parts[0], parts[1], runID, ev.Installation.ID)
	if e != nil {
		return source.Event{}, fmt.Errorf("%w: %v", source.ErrUpstream, e)
	}
	sha := ev.Deployment.SHA
	if sha == "" {
		sha = ev.SHA
	}
	if sha != "" && run.HeadSHA != "" && sha != run.HeadSHA {
		return source.Event{}, fmt.Errorf("%w: deployment SHA does not match workflow run", source.ErrMalformed)
	}
	env := ev.Deployment.Environment
	if env == "" {
		env = ev.Environment
	}
	subject := run.Actor.Name
	if run.Actor.ID > 0 {
		subject = strconv.FormatInt(run.Actor.ID, 10)
	}
	if x := c.ActorSubjects[subject]; x != "" {
		subject = x
	}
	ctxJSON, _ := json.Marshal(map[string]any{"workflow_run_id": run.ID, "workflow_name": run.Name, "owner": parts[0], "repo": parts[1], "actor": run.Actor.Name, "callback_url": ev.DeploymentCallbackURL, "installation_id": ev.Installation.ID})
	dedup := ev.Deployment.ID
	if dedup == 0 {
		dedup = run.ID
	}
	return source.Event{ID: uuid.NewSHA1(uuid.NameSpaceURL, []byte(ev.Repository.FullName+":"+fmt.Sprint(dedup))).String(), Repository: ev.Repository.FullName, Environment: env, CommitSHA: run.HeadSHA, Requester: run.Actor.Name, RequesterSubject: subject, Context: ctxJSON}, nil
}
func (c *Client) Recheck(ctx context.Context, e source.Event) (bool, error) {
	var cx struct {
		Owner          string `json:"owner"`
		Repo           string `json:"repo"`
		WorkflowRunID  int64  `json:"workflow_run_id"`
		InstallationID int64  `json:"installation_id"`
	}
	if err := json.Unmarshal(e.Context, &cx); err != nil {
		return false, fmt.Errorf("%w: invalid source context", source.ErrMalformed)
	}
	run, err := c.GetWorkflowRun(ctx, cx.Owner, cx.Repo, cx.WorkflowRunID, cx.InstallationID)
	if err != nil {
		return false, fmt.Errorf("%w: %v", source.ErrUpstream, err)
	}
	return !(run.Status == "completed" && (run.Conclusion == "cancelled" || run.Conclusion == "failure" || run.Conclusion == "timed_out")), nil
}
func (c *Client) Deliver(ctx context.Context, e source.Event, decision, comment string) error {
	var cx struct {
		CallbackURL    string `json:"callback_url"`
		InstallationID int64  `json:"installation_id"`
	}
	if err := json.Unmarshal(e.Context, &cx); err != nil {
		return fmt.Errorf("%w: invalid source context", source.ErrMalformed)
	}
	return c.Callback(ctx, cx.CallbackURL, cx.InstallationID, decision, e.Environment, comment)
}
func validHMAC(raw []byte, sig, secret string) bool {
	if secret == "" || !strings.HasPrefix(sig, "sha256=") {
		return false
	}
	want, e := hex.DecodeString(strings.TrimPrefix(sig, "sha256="))
	if e != nil {
		return false
	}
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(raw)
	return hmac.Equal(want, h.Sum(nil))
}
func callbackRunID(raw string) (int64, bool) {
	u, e := url.Parse(raw)
	if e != nil {
		return 0, false
	}
	m := callbackRE.FindStringSubmatch(u.EscapedPath())
	if len(m) == 0 {
		return 0, false
	}
	parts := strings.Split(strings.Trim(u.EscapedPath(), "/"), "/")
	if len(parts) < 7 {
		return 0, false
	}
	id, e := strconv.ParseInt(parts[5], 10, 64)
	return id, e == nil && id > 0
}
