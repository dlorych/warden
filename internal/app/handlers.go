package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/wardenv/service/internal/auth"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/internal/store"
	"github.com/wardenv/service/pkg/evidence"
	"io"
	"net/http"
	"strings"
	"time"
)

func (a *App) bffRouter() http.Handler {
	r := chiRouter()
	r.Use(noStore)
	r.Get("/session", a.session)
	r.Get("/login", a.login)
	r.Get("/callback", a.callback)
	r.Post("/logout", a.logout)
	r.Get("/requests", a.bffRequests)
	r.Get("/requests/{id}", a.bffRequest)
	r.Get("/requests/{id}/evidence", a.bffEvidence)
	r.Get("/decisions", a.bffDecisions)
	return r
}
func chiRouter() *chi.Mux { return chi.NewRouter() }
func (a *App) session(w http.ResponseWriter, r *http.Request) {
	s, e := a.currentSession(r)
	if e != nil {
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, 200, map[string]any{"authenticated": true, "user": map[string]string{"subject": s.Subject, "name": s.Name}, "csrfToken": csrfFor(s)})
}
func csrfFor(s store.Session) string { return s.CSRFHash }
func (a *App) currentSession(r *http.Request) (store.Session, error) {
	c, e := r.Cookie(a.sessionCookieName())
	if e != nil {
		return store.Session{}, e
	}
	return a.Store.GetSession(r.Context(), c.Value, time.Now(), a.Config.SessionIdle)
}
func (a *App) sessionCookieName() string {
	if a.Config.CookieSecure {
		return "__Host-warden_session"
	}
	return "warden_session"
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if a.Auth == nil {
		writeProblem(w, 503, "OIDC unavailable")
		return
	}
	if e := a.Auth.Discovery(r.Context()); e != nil {
		writeProblem(w, 503, "OIDC unavailable")
		return
	}
	state, verifier, nonce := randomToken(32), randomToken(32), randomToken(32)
	if _, e := a.Store.CreateOAuthState(r.Context(), state, verifier, nonce, a.Config.OIDCRedirectURL, time.Now()); e != nil {
		writeProblem(w, 500, "Could not create login transaction")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "warden_login", Value: state, Path: "/bff", HttpOnly: true, Secure: a.Config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, a.Auth.AuthorizationURL(state, verifier, nonce), http.StatusFound)
}
func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	lc, e := r.Cookie("warden_login")
	if e != nil || r.URL.Query().Get("state") == "" || lc.Value != r.URL.Query().Get("state") {
		writeProblem(w, 400, "Invalid login transaction")
		return
	}
	st, e := a.Store.ConsumeOAuthState(r.Context(), r.URL.Query().Get("state"), time.Now())
	if e != nil {
		writeProblem(w, 400, "Invalid login transaction")
		return
	}
	id, e := a.Auth.Exchange(r.Context(), r.URL.Query().Get("code"), st.Verifier, st.NonceHash)
	if e != nil {
		writeProblem(w, 401, "OIDC authentication failed")
		return
	}
	csrf := randomToken(32)
	sess, e := a.Store.CreateSession(r.Context(), id.Subject, id.Name, csrf, time.Now(), a.Config.SessionIdle, a.Config.SessionAbsolute)
	if e != nil {
		writeProblem(w, 500, "Could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: a.sessionCookieName(), Value: sess.ID, Path: "/", HttpOnly: true, Secure: a.Config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: int(a.Config.SessionAbsolute.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: "warden_login", Value: "", Path: "/bff", HttpOnly: true, Secure: a.Config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	http.Redirect(w, r, a.Config.WebURL, http.StatusFound)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireBrowser(w, r); !ok {
		return
	}
	if c, e := r.Cookie(a.sessionCookieName()); e == nil {
		_ = a.Store.DeleteSession(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: a.sessionCookieName(), Value: "", Path: "/", HttpOnly: true, Secure: a.Config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	// Local invalidation is complete before constructing the provider redirect.
	// If discovery or the provider lacks RP-initiated logout, the user is still
	// logged out of Warden and the browser will simply reload the login screen.
	if logoutURL := a.oidcLogoutURL(r.Context()); logoutURL != "" {
		writeJSON(w, http.StatusOK, map[string]string{"logoutURL": logoutURL})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"loggedOut": true})
}

func (a *App) oidcLogoutURL(ctx context.Context) string {
	if a.Auth != nil {
		// Discovery is deliberately refreshed here because the BFF may have
		// restarted since the browser session was created. Local invalidation
		// happens before this network call in logout.
		_ = a.Auth.Discovery(ctx)
		if logoutURL, err := a.Auth.RPInitiatedLogoutURL(a.Config.OIDCPostLogoutRedirectURL); err == nil {
			return logoutURL
		}
	}
	return ""
}
func (a *App) requireBrowser(w http.ResponseWriter, r *http.Request) (store.Session, bool) {
	s, e := a.currentSession(r)
	if e != nil {
		writeProblem(w, 401, "Authentication required")
		return s, false
	}
	if r.Method != "GET" {
		if origin := strings.TrimRight(r.Header.Get("Origin"), "/"); origin == "" || (origin != strings.TrimRight(a.Config.WebURL, "/") && origin != strings.TrimRight(a.Config.PublicURL, "/")) {
			writeProblem(w, 403, "Origin validation failed")
			return s, false
		}
		token := r.Header.Get("X-CSRF-Token")
		if token == "" || token != s.CSRFHash {
			writeProblem(w, 403, "CSRF validation failed")
			return s, false
		}
	}
	return s, true
}

type requestDTO struct {
	ID             string          `json:"id"`
	Repository     string          `json:"repository"`
	Environment    string          `json:"environment"`
	CommitSHA      string          `json:"commit_sha"`
	Requester      string          `json:"requester"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Decision       string          `json:"decision"`
	LogStatus      string          `json:"log_status"`
	DeliveryStatus string          `json:"delivery_status"`
	Reason         string          `json:"reason"`
	Context        json.RawMessage `json:"context,omitempty"`
	Service        string          `json:"service,omitempty"`
	ContextDigest  string          `json:"context_digest,omitempty"`
}

func dto(x store.Request) requestDTO {
	digest := sha256.Sum256(x.Context)
	return requestDTO{ID: x.ID, Repository: x.Repository, Environment: x.Environment, CommitSHA: x.CommitSHA, Requester: x.Requester, CreatedAt: x.CreatedAt, ExpiresAt: x.ExpiresAt, Decision: x.Decision, LogStatus: x.LogStatus, DeliveryStatus: x.DeliveryStatus, Reason: x.Reason, Context: x.Context, Service: "wardenv", ContextDigest: "sha256:" + hex.EncodeToString(digest[:])}
}

type browserRequestDTO struct {
	ID             string    `json:"id"`
	Repository     string    `json:"repository"`
	Environment    string    `json:"environment"`
	CommitSHA      string    `json:"commit_sha"`
	Requester      string    `json:"requester"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Decision       string    `json:"decision"`
	LogStatus      string    `json:"log_status"`
	DeliveryStatus string    `json:"delivery_status"`
	Reason         string    `json:"reason"`
}

func browserDTO(x store.Request) browserRequestDTO {
	return browserRequestDTO{ID: x.ID, Repository: x.Repository, Environment: x.Environment, CommitSHA: x.CommitSHA, Requester: x.Requester, CreatedAt: x.CreatedAt, ExpiresAt: x.ExpiresAt, Decision: x.Decision, LogStatus: x.LogStatus, DeliveryStatus: x.DeliveryStatus, Reason: x.Reason}
}
func (a *App) bffRequests(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireBrowser(w, r); !ok {
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		if _, e := uuid.Parse(cursor); e != nil {
			writeProblem(w, 400, "Invalid cursor")
			return
		}
	}
	items, next, e := a.Store.ListRequests(r.Context(), cursor, 50)
	if e != nil {
		writeProblem(w, 500, "Could not list requests")
		return
	}
	out := make([]browserRequestDTO, len(items))
	for i := range items {
		out[i] = browserDTO(items[i])
	}
	writeJSON(w, 200, map[string]any{"items": out, "nextCursor": next})
}
func (a *App) bffRequest(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireBrowser(w, r); !ok {
		return
	}
	x, e := a.Store.GetRequest(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		writeProblem(w, 404, "Request not found")
		return
	}
	writeJSON(w, 200, browserDTO(x))
}
func (a *App) bffEvidence(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireBrowser(w, r); !ok {
		return
	}
	d, e := a.Store.RequestEvidence(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		writeProblem(w, 500, "Could not read evidence")
		return
	}
	writeJSON(w, 200, map[string]any{"items": d})
}

// publicEvidence serves the exact bundle committed after Rekor inclusion.
// It intentionally has no authentication boundary: the callback reference is
// useful to GitHub users and external auditors. Before publication, the
// decision is indistinguishable from a missing record at this endpoint.
func (a *App) publicEvidence(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, e := uuid.Parse(id); e != nil {
		writeProblem(w, 404, "Evidence not found")
		return
	}
	bundle, found, e := a.Store.PublishedEvidence(r.Context(), id)
	if e != nil {
		writeProblem(w, 500, "Could not read evidence")
		return
	}
	if !found {
		writeProblem(w, 404, "Evidence not found")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

type decisionDTO struct {
	ID        string          `json:"id"`
	RequestID string          `json:"request_id"`
	Reviewer  string          `json:"reviewer"`
	Decision  string          `json:"decision"`
	Reason    string          `json:"reason"`
	CreatedAt time.Time       `json:"created_at"`
	Statement json.RawMessage `json:"statement,omitempty"`
	Signature string          `json:"signature,omitempty"`
}

func (a *App) bffDecisions(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireBrowser(w, r); !ok {
		return
	}
	cursor := r.URL.Query().Get("cursor")
	if cursor != "" {
		if _, e := uuid.Parse(cursor); e != nil {
			writeProblem(w, 400, "Invalid cursor")
			return
		}
	}
	items, next, e := a.Store.ListDecisions(r.Context(), cursor, 50)
	if e != nil {
		writeProblem(w, 500, "Could not list decisions")
		return
	}
	out := make([]decisionDTO, len(items))
	for i, x := range items {
		out[i] = decisionDTO{ID: x.ID, RequestID: x.RequestID, Reviewer: x.ReviewerName, Decision: x.Decision, Reason: x.Reason, CreatedAt: x.CreatedAt, Statement: x.Statement, Signature: x.Signature}
	}
	writeJSON(w, 200, map[string]any{"items": out, "nextCursor": next})
}

func (a *App) apiRouter() http.Handler {
	r := chiRouter()
	r.Use(noStore)
	r.Use(a.requireCLI)
	r.Get("/requests/{id}", a.apiRequest)
	r.Post("/requests/{id}/challenges", a.challenge)
	r.Post("/requests/{id}/decisions", a.decide)
	r.Get("/requests/{id}/evidence", a.apiEvidence)
	return r
}

type cliIdentityKey struct{}

func (a *App) requireCLI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, cookieErr := r.Cookie(a.sessionCookieName()); cookieErr == nil {
			writeProblem(w, 401, "Cookies are not accepted by the CLI API")
			return
		}
		h := r.Header.Get("Authorization")
		if !strings.HasPrefix(h, "Bearer ") {
			writeProblem(w, 401, "Bearer token required")
			return
		}
		id, e := a.Auth.VerifyAccessToken(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
		if e != nil {
			writeProblem(w, 401, "Invalid access token")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/decisions") || strings.HasSuffix(r.URL.Path, "/challenges") {
			reviewer := false
			for _, g := range id.Groups {
				if g == "reviewers" {
					reviewer = true
					break
				}
			}
			if !reviewer {
				writeProblem(w, 403, "Reviewer group required")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), cliIdentityKey{}, id)))
	})
}
func identity(r *http.Request) auth.Identity {
	return r.Context().Value(cliIdentityKey{}).(auth.Identity)
}
func (a *App) apiRequest(w http.ResponseWriter, r *http.Request) {
	x, e := a.Store.GetRequest(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		writeProblem(w, 404, "Request not found")
		return
	}
	writeJSON(w, 200, dto(x))
}
func (a *App) apiEvidence(w http.ResponseWriter, r *http.Request) {
	d, e := a.Store.RequestEvidence(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		writeProblem(w, 500, "Could not read evidence")
		return
	}
	if len(d) == 1 && len(d[0].Statement) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(d[0].Statement)
		return
	}
	writeJSON(w, 200, map[string]any{"items": d})
}
func (a *App) challenge(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Decision != "approved" && in.Decision != "rejected" {
		writeProblem(w, 400, "decision must be approved or rejected")
		return
	}
	if in.Decision == "rejected" {
		if strings.TrimSpace(in.Reason) == "" {
			writeProblem(w, 400, "reason is required for rejection")
			return
		}
	}
	x, e := a.Store.GetRequest(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		writeProblem(w, 404, "Request not found")
		return
	}
	if x.Decision != "pending" || time.Now().After(x.ExpiresAt) || x.RequesterSubject == identity(r).Subject {
		writeProblem(w, 409, "request is not eligible for a challenge")
		return
	}
	nonce := randomToken(24)
	decision := in.Decision
	expiry := time.Now().Add(5 * time.Minute).UTC()
	digest := sha256.Sum256(x.Context)
	statement := evidence.Statement{Version: evidence.StatementVersion, Service: "wardenv", RequestID: x.ID, ContextDigest: "sha256:" + hex.EncodeToString(digest[:]), Decision: decision, Reason: in.Reason, Subject: identity(r).Subject, Nonce: nonce, Expiry: expiry.Unix()}
	if e := a.Store.CreateChallenge(r.Context(), x.ID, identity(r).Subject, decision, in.Reason, hashValue(nonce), expiry); e != nil {
		writeProblem(w, 500, "could not create challenge")
		return
	}
	writeJSON(w, 200, map[string]any{"statement": statement, "challenge": statement})
}
func (a *App) decide(w http.ResponseWriter, r *http.Request) {
	var bundle evidence.Bundle
	body, eRead := io.ReadAll(r.Body)
	if eRead != nil || json.Unmarshal(body, &bundle) != nil || bundle.Signed.Statement.RequestID == "" {
		writeProblem(w, 400, "invalid JSON")
		return
	}
	statementJSON, _ := json.Marshal(bundle.Signed.Statement)
	decision := bundle.Signed.Statement.Decision
	reason := bundle.Signed.Statement.Reason
	if len(bundle.CertificateChain) == 0 {
		writeProblem(w, 400, "certificate-backed evidence bundle is required")
		return
	}
	certs, e := parseCerts(bundle.CertificateChain)
	if e != nil || len(certs) == 0 {
		writeProblem(w, 400, "invalid evidence certificate chain")
		return
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || bundle.Signed.VerifySignature(pub) != nil {
		writeProblem(w, 400, "invalid evidence signature")
		return
	}
	if err := a.verifyEvidenceCertificate(certs, identity(r).Subject); err != nil {
		writeProblem(w, 400, "untrusted evidence certificate")
		return
	}
	if decision != "approved" && decision != "rejected" {
		writeProblem(w, 400, "decision must be approved or rejected")
		return
	}
	if decision == "rejected" && strings.TrimSpace(reason) == "" {
		writeProblem(w, 400, "reason is required for rejection")
		return
	}
	if len(statementJSON) == 0 || strings.TrimSpace(bundle.Signed.Signature) == "" {
		writeProblem(w, 400, "signed evidence is required")
		return
	}
	var st evidence.Statement
	if e := json.Unmarshal(statementJSON, &st); e != nil {
		writeProblem(w, 400, "invalid signed statement")
		return
	}
	reqForDecision, e := a.Store.GetRequest(r.Context(), chi.URLParam(r, "id"))
	if e != nil {
		writeProblem(w, 404, "Request not found")
		return
	}
	ctxDigest := sha256.Sum256(reqForDecision.Context)
	if st.ContextDigest != "sha256:"+hex.EncodeToString(ctxDigest[:]) || st.Service != "wardenv" {
		writeProblem(w, 400, "statement context binding mismatch")
		return
	}
	if st.RequestID != chi.URLParam(r, "id") || st.Subject != identity(r).Subject {
		writeProblem(w, 400, "statement binding mismatch")
		return
	}
	expected := st.Decision
	if expected != decision || st.Reason != reason || st.Expiry < time.Now().Unix() {
		writeProblem(w, 400, "statement binding mismatch")
		return
	}
	if _, e := evidence.CanonicalStatement(st); e != nil {
		writeProblem(w, 400, "invalid signed statement")
		return
	}
	d, e := a.Store.AcceptDecision(r.Context(), chi.URLParam(r, "id"), identity(r).Subject, identity(r).Name, decision, reason, hashValue(st.Nonce), body, bundle.Signed.Signature)
	if e != nil {
		writeProblem(w, 409, e.Error())
		return
	}
	writeJSON(w, 202, decisionDTO{ID: d.ID, RequestID: d.RequestID, Decision: d.Decision, Reason: d.Reason, CreatedAt: d.CreatedAt, Statement: d.Statement, Signature: d.Signature})
}
func (a *App) verifyEvidenceCertificate(certs []*x509.Certificate, subject string) error {
	if len(certs) == 0 || a.Config.EvidenceTrustPEM == "" {
		return fmt.Errorf("evidence trust is not configured")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(a.Config.EvidenceTrustPEM)) {
		return fmt.Errorf("invalid evidence trust")
	}
	leaf := certs[0]
	if !evidence.CertificateSubject(leaf, subject) {
		return fmt.Errorf("certificate subject mismatch")
	}
	if time.Now().Before(leaf.NotBefore) || time.Now().After(leaf.NotAfter) {
		return fmt.Errorf("certificate expired")
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return e
}

func (a *App) githubWebhook(w http.ResponseWriter, r *http.Request) {
	raw, e := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if e != nil {
		writeProblem(w, 400, "invalid body")
		return
	}
	ev, e := a.Source.Webhook(r.Context(), raw, r.Header.Get("X-Hub-Signature-256"))
	if e != nil {
		if errors.Is(e, source.ErrInvalidSignature) {
			writeProblem(w, 401, "invalid webhook signature")
			return
		}
		if errors.Is(e, source.ErrIgnored) {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if errors.Is(e, source.ErrUpstream) {
			writeProblem(w, 502, "could not enrich workflow run")
			return
		}
		writeProblem(w, 400, e.Error())
		return
	}
	if e = a.Store.EnqueueWebhook(r.Context(), store.Request{ID: ev.ID, Repository: ev.Repository, Environment: ev.Environment, CommitSHA: ev.CommitSHA, Requester: ev.Requester, RequesterSubject: ev.RequesterSubject, Context: ev.Context, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(24 * time.Hour)}); e != nil {
		writeProblem(w, 500, "could not store request")
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
func hashValue(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }
