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
	"github.com/jackc/pgx/v5"
	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/auth"
	"github.com/wardenv/service/internal/authz"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/internal/store"
	"github.com/wardenv/service/pkg/evidence"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
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
	r.Get("/audit", a.bffAudit)
	return r
}
func chiRouter() *chi.Mux { return chi.NewRouter() }
func (a *App) session(w http.ResponseWriter, r *http.Request) {
	s, e := a.currentSession(r)
	if e != nil {
		writeJSON(w, 200, map[string]any{"authenticated": false})
		return
	}
	writeJSON(w, 200, map[string]any{"authenticated": true, "user": map[string]any{"subject": s.Subject, "name": s.Name, "roles": s.Roles}, "csrfToken": csrfFor(s)})
}
func csrfFor(s store.Session) string { return s.CSRFHash }
func (a *App) currentSession(r *http.Request) (store.Session, error) {
	c, e := r.Cookie(a.sessionCookieName())
	if e != nil {
		return store.Session{}, e
	}
	return a.Store.GetSession(r.Context(), c.Value, time.Now(), a.Config.SessionIdle)
}

func (a *App) auditRepository() audit.Repository {
	if a.Audit != nil {
		return a.Audit
	}
	if a.Store == nil {
		return nil
	}
	return a.Store
}

func auditActor(subject, name string, roles []string, actorType audit.ActorType) audit.Event {
	return audit.Event{ActorID: subject, ActorName: name, ActorRoles: roles, ActorType: actorType}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (a *App) recordAudit(r *http.Request, event audit.Event, status int) error {
	event = prepareAuditEvent(r, event, status)
	repository := a.auditRepository()
	if repository == nil {
		err := fmt.Errorf("audit repository unavailable")
		a.logAuditFailure(event, err)
		return err
	}
	if err := repository.AppendAuditEvent(r.Context(), event); err != nil {
		a.logAuditFailure(event, err)
		return err
	}
	return nil
}

func prepareAuditEvent(r *http.Request, event audit.Event, status int) audit.Event {
	if event.OperationID == "" {
		event.OperationID = uuid.NewString()
	}
	if event.RequestID == "" {
		event.RequestID = uuid.NewString()
	}
	event.OccurredAt = time.Now().UTC()
	event.SchemaVersion = audit.EventSchemaVersion
	event.IPAddress = clientIP(r)
	event.UserAgent = truncateUserAgent(r.UserAgent(), 512)
	event.Route = r.URL.Path
	if event.Metadata == nil {
		event.Metadata = json.RawMessage(fmt.Sprintf(`{"http_status":%d}`, status))
	}
	return event
}

func (a *App) logAuditFailure(event audit.Event, err error) {
	logger := a.logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Error("audit append failed", "emergency", true, "action", event.ActionCode, "outcome", event.Outcome, "route", event.Route, "error", err)
}

func truncateUserAgent(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	value = value[:maxBytes]
	for len(value) > 0 && !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func (a *App) failAudit(w http.ResponseWriter, r *http.Request, event audit.Event, status int) bool {
	if a.recordAudit(r, event, status) != nil {
		writeProblem(w, http.StatusServiceUnavailable, "Audit service unavailable")
		return false
	}
	return true
}

func readAuditEvent(actor audit.Event, outcome audit.Outcome, reason, resourceID string) audit.Event {
	actor.ActionCode = audit.ActionRequestRead
	actor.Outcome = outcome
	actor.Permission = string(authz.RequestRead)
	actor.PolicyVersion = authz.PolicyVersion
	actor.Reason = reason
	actor.ResourceType = "deployment_request"
	actor.ResourceID = resourceID
	return actor
}

func authAuditEvent(actor audit.Event, action string, outcome audit.Outcome, reason string) audit.Event {
	actor.ActionCode = action
	actor.Outcome = outcome
	actor.PolicyVersion = authz.PolicyVersion
	actor.Reason = reason
	return actor
}

func requestListAuditEvent(actor audit.Event, outcome audit.Outcome, reason string) audit.Event {
	actor.ActionCode = audit.ActionRequestList
	actor.Outcome = outcome
	actor.Permission = string(authz.RequestRead)
	actor.PolicyVersion = authz.PolicyVersion
	actor.Reason = reason
	actor.ResourceType = "deployment_request"
	return actor
}

func decisionListAuditEvent(actor audit.Event, outcome audit.Outcome, reason string) audit.Event {
	actor.ActionCode = audit.ActionDecisionList
	actor.Outcome = outcome
	actor.Permission = string(authz.DecisionRead)
	actor.PolicyVersion = authz.PolicyVersion
	actor.Reason = reason
	actor.ResourceType = "decision"
	return actor
}

func evidenceAuditEvent(actor audit.Event, outcome audit.Outcome, reason, resourceID string) audit.Event {
	actor.ActionCode = audit.ActionEvidenceRead
	actor.Outcome = outcome
	actor.Permission = string(authz.EvidenceRead)
	actor.PolicyVersion = authz.PolicyVersion
	actor.Reason = reason
	actor.ResourceType = "deployment_request"
	actor.ResourceID = resourceID
	return actor
}

func browserActor(r *http.Request, s store.Session, authenticated bool) audit.Event {
	if authenticated {
		return auditActor(s.Subject, s.Name, s.Roles, audit.ActorUser)
	}
	return auditActor("", "", nil, audit.ActorAnonymous)
}

// operationForState gives initiation and callback the same correlation UUID
// without storing raw state in an event or log. SHA-256 is only used as a
// deterministic UUID derivation; the state itself remains a secret.
func operationForState(state string) string {
	digest := sha256.Sum256([]byte(state))
	id := uuid.UUID(digest[:16])
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id.String()
}

func preparedAuditEvent(r *http.Request, event audit.Event, status int) audit.Event {
	return prepareAuditEvent(r, event, status)
}

func (a *App) browserSessionFailureReason(r *http.Request) string {
	if _, err := r.Cookie(a.sessionCookieName()); err != nil {
		return "session_missing"
	}
	return "session_invalid"
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
	sess, e := a.Store.CreateSession(r.Context(), id.Subject, id.Name, csrf, id.Roles, time.Now(), a.Config.SessionIdle, a.Config.SessionAbsolute)
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

// authorizeAuditedRequestRead is the authentication and authorization boundary
// for the first request-detail tracer. Other protected browser reads retain the
// issue-#2 behavior and are intentionally not audited until later tickets.
func (a *App) authorizeAuditedRequestRead(w http.ResponseWriter, r *http.Request, resourceID string) (store.Session, audit.Event, bool) {
	s, err := a.currentSession(r)
	actor := auditActor("", "", nil, audit.ActorAnonymous)
	actor.AuthMethod = "cookie"
	if err != nil {
		event := readAuditEvent(actor, audit.OutcomeUnauthenticated, a.browserSessionFailureReason(r), resourceID)
		if !a.failAudit(w, r, event, http.StatusUnauthorized) {
			return store.Session{}, event, false
		}
		writeProblem(w, http.StatusUnauthorized, "Authentication required")
		return store.Session{}, event, false
	}
	actor = auditActor(s.Subject, s.Name, s.Roles, audit.ActorUser)
	actor.AuthMethod = "cookie"
	decision := a.authorize(s.Roles, s.Subject, authz.RequestRead, authz.Resource{RequestID: resourceID})
	if !decision.Allowed {
		event := readAuditEvent(actor, audit.OutcomeDenied, decision.Reason, resourceID)
		if !a.failAudit(w, r, event, http.StatusNotFound) {
			return store.Session{}, event, false
		}
		writeProblem(w, http.StatusNotFound, "Resource not found")
		return store.Session{}, event, false
	}
	return s, actor, true
}

func (a *App) bffRequests(w http.ResponseWriter, r *http.Request) {
	s, ok := a.requireBrowser(w, r)
	if !ok || !a.allows(s.Roles, s.Subject, authz.RequestRead, authz.Resource{}) {
		if ok {
			writeProblem(w, http.StatusForbidden, "Permission denied")
		}
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
	id := chi.URLParam(r, "id")
	_, eventActor, ok := a.authorizeAuditedRequestRead(w, r, id)
	if !ok {
		return
	}
	if _, e := uuid.Parse(id); e != nil {
		event := readAuditEvent(eventActor, audit.OutcomeInvalid, "request_id_invalid", id)
		if !a.failAudit(w, r, event, http.StatusNotFound) {
			return
		}
		writeProblem(w, http.StatusNotFound, "Request not found")
		return
	}
	x, e := a.Store.GetRequest(r.Context(), id)
	if e != nil {
		outcome, reason := audit.OutcomeInvalid, "request_not_found"
		if !errors.Is(e, pgx.ErrNoRows) {
			outcome, reason = audit.OutcomeFailed, "request_read_failed"
		}
		event := readAuditEvent(eventActor, outcome, reason, id)
		if !a.failAudit(w, r, event, http.StatusNotFound) {
			return
		}
		writeProblem(w, 404, "Request not found")
		return
	}
	event := readAuditEvent(eventActor, audit.OutcomeSuccess, "read", id)
	if !a.failAudit(w, r, event, http.StatusOK) {
		return
	}
	writeJSON(w, 200, browserDTO(x))
}
func (a *App) bffEvidence(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	s, ok := a.requireBrowser(w, r)
	if !ok || !a.allows(s.Roles, s.Subject, authz.EvidenceRead, authz.Resource{RequestID: id}) {
		if ok {
			writeProblem(w, http.StatusNotFound, "Evidence not found")
		}
		return
	}
	if _, e := uuid.Parse(id); e != nil {
		writeProblem(w, http.StatusNotFound, "Evidence not found")
		return
	}
	d, e := a.Store.RequestEvidence(r.Context(), id)
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
	s, ok := a.requireBrowser(w, r)
	if !ok || !a.allows(s.Roles, s.Subject, authz.DecisionRead, authz.Resource{}) {
		if ok {
			writeProblem(w, http.StatusForbidden, "Permission denied")
		}
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

func auditReadEvent(actor audit.Event, outcome audit.Outcome, reason string) audit.Event {
	actor.ActionCode = audit.ActionAuditRead
	actor.Outcome = outcome
	actor.Permission = string(authz.AuditRead)
	actor.PolicyVersion = authz.PolicyVersion
	actor.ResourceType = "audit_log"
	actor.Reason = reason
	return actor
}

func validAuditFilterValue(value string, max int) bool {
	return len(value) <= max && value != "" && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
}

func parseAuditQuery(values url.Values) (audit.Query, error) {
	allowed := map[string]bool{"cursor": true, "limit": true, "action": true, "outcome": true, "actor_id": true, "resource_type": true, "resource_id": true, "operation_id": true, "from": true, "to": true}
	for key := range values {
		if !allowed[key] || len(values[key]) != 1 {
			return audit.Query{}, fmt.Errorf("invalid audit filter")
		}
	}
	q := audit.Query{Cursor: values.Get("cursor"), Limit: 50, Action: values.Get("action"), ActorID: values.Get("actor_id"), ResourceType: values.Get("resource_type"), ResourceID: values.Get("resource_id"), OperationID: values.Get("operation_id")}
	if q.Cursor != "" && !validAuditFilterValue(q.Cursor, 512) {
		return audit.Query{}, fmt.Errorf("invalid cursor")
	}
	if q.Cursor != "" {
		if err := store.ValidateAuditCursor(q.Cursor); err != nil {
			return audit.Query{}, fmt.Errorf("invalid cursor")
		}
	}
	if q.Action != "" && !validAuditFilterValue(q.Action, 128) || q.ActorID != "" && !validAuditFilterValue(q.ActorID, 256) || q.ResourceType != "" && !validAuditFilterValue(q.ResourceType, 128) || q.ResourceID != "" && !validAuditFilterValue(q.ResourceID, 256) {
		return audit.Query{}, fmt.Errorf("invalid audit filter")
	}
	if q.Action != "" && q.Action != audit.ActionRequestRead && q.Action != audit.ActionAuditRead && q.Action != "audit.initialized" {
		return audit.Query{}, fmt.Errorf("invalid audit action")
	}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 100 {
			return audit.Query{}, fmt.Errorf("limit must be between 1 and 100")
		}
		q.Limit = limit
	} else if _, ok := values["limit"]; ok {
		return audit.Query{}, fmt.Errorf("limit must be between 1 and 100")
	}
	if raw := values.Get("outcome"); raw != "" {
		q.Outcome = audit.Outcome(raw)
		switch q.Outcome {
		case audit.OutcomeStarted, audit.OutcomeSuccess, audit.OutcomeUnauthenticated, audit.OutcomeDenied, audit.OutcomeInvalid, audit.OutcomeFailed:
		default:
			return audit.Query{}, fmt.Errorf("invalid audit outcome")
		}
	} else if _, ok := values["outcome"]; ok {
		return audit.Query{}, fmt.Errorf("invalid audit outcome")
	}
	if q.OperationID != "" {
		if _, err := uuid.Parse(q.OperationID); err != nil {
			return audit.Query{}, fmt.Errorf("invalid operation ID")
		}
	} else if _, ok := values["operation_id"]; ok {
		return audit.Query{}, fmt.Errorf("invalid operation ID")
	}
	parseTime := func(key string) (*time.Time, error) {
		raw := values.Get(key)
		if raw == "" {
			if _, ok := values[key]; ok {
				return nil, fmt.Errorf("invalid %s time", key)
			}
			return nil, nil
		}
		if len(raw) > 40 {
			return nil, fmt.Errorf("invalid %s time", key)
		}
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return nil, fmt.Errorf("invalid %s time", key)
		}
		t = t.UTC()
		return &t, nil
	}
	var err error
	if q.From, err = parseTime("from"); err != nil {
		return audit.Query{}, err
	}
	if q.To, err = parseTime("to"); err != nil {
		return audit.Query{}, err
	}
	if q.From != nil && q.To != nil && q.From.After(*q.To) {
		return audit.Query{}, fmt.Errorf("from must not be after to")
	}
	return q, nil
}

func (a *App) bffAudit(w http.ResponseWriter, r *http.Request) {
	s, err := a.currentSession(r)
	actor := auditActor("", "", nil, audit.ActorAnonymous)
	actor.AuthMethod = "cookie"
	if err == nil {
		actor = auditActor(s.Subject, s.Name, s.Roles, audit.ActorUser)
		actor.AuthMethod = "cookie"
	}
	if err != nil {
		if !a.failAudit(w, r, auditReadEvent(actor, audit.OutcomeUnauthenticated, a.browserSessionFailureReason(r)), http.StatusUnauthorized) {
			return
		}
		writeProblem(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	decision := a.authorize(s.Roles, s.Subject, authz.AuditRead, authz.Resource{})
	if !decision.Allowed {
		if !a.failAudit(w, r, auditReadEvent(actor, audit.OutcomeDenied, decision.Reason), http.StatusForbidden) {
			return
		}
		writeProblem(w, http.StatusForbidden, "Permission denied")
		return
	}
	q, err := parseAuditQuery(r.URL.Query())
	if err != nil {
		if !a.failAudit(w, r, auditReadEvent(actor, audit.OutcomeInvalid, err.Error()), http.StatusBadRequest) {
			return
		}
		writeProblem(w, http.StatusBadRequest, err.Error())
		return
	}
	page, queryErr, appendErr := a.selectAndAuditRead(r, q, actor)
	if queryErr != nil {
		if !a.failAudit(w, r, auditReadEvent(actor, audit.OutcomeFailed, "audit_query_failed"), http.StatusInternalServerError) {
			return
		}
		writeProblem(w, http.StatusInternalServerError, "Could not read audit log")
		return
	}
	if appendErr != nil {
		writeProblem(w, http.StatusServiceUnavailable, "Audit service unavailable")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// selectAndAuditRead makes the query-before-append ordering a named seam. A
// successful snapshot is never returned to the caller until its own audit
// event has committed; query failures remain distinguishable so callers can
// record a failed attempt without recursively auditing an append failure.
func (a *App) selectAndAuditRead(r *http.Request, q audit.Query, actor audit.Event) (audit.Page, error, error) {
	page, queryErr := a.auditRepository().ListAuditEvents(r.Context(), q)
	if queryErr != nil {
		return audit.Page{}, queryErr, nil
	}
	event := auditReadEvent(actor, audit.OutcomeSuccess, "read")
	event.Metadata = json.RawMessage(fmt.Sprintf(`{"returned":%d}`, len(page.Items)))
	return page, nil, a.recordAudit(r, event, http.StatusOK)
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
		permission, resourceAware := cliPermission(r.URL.Path)
		resourceID := chi.URLParam(r, "id")
		unauthenticated := func(reason string, status int, title string) {
			event := cliAuditEvent(nil, permission, audit.OutcomeUnauthenticated, reason, resourceID)
			if a.failAudit(w, r, event, status) {
				writeProblem(w, status, title)
			}
		}
		if _, cookieErr := r.Cookie(a.sessionCookieName()); cookieErr == nil {
			unauthenticated("cookie_not_allowed", http.StatusUnauthorized, "Cookies are not accepted by the CLI API")
			return
		}
		h := r.Header.Get("Authorization")
		if h == "" {
			unauthenticated("bearer_missing", http.StatusUnauthorized, "Bearer token required")
			return
		}
		if !strings.HasPrefix(h, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")) == "" {
			unauthenticated("bearer_malformed", http.StatusUnauthorized, "Bearer token required")
			return
		}
		if a.Auth == nil {
			event := cliAuditEvent(nil, permission, audit.OutcomeFailed, "authentication_unavailable", resourceID)
			if a.failAudit(w, r, event, http.StatusServiceUnavailable) {
				writeProblem(w, http.StatusServiceUnavailable, "Authentication unavailable")
			}
			return
		}
		id, e := a.Auth.VerifyAccessToken(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
		if e != nil {
			event := cliAuditEvent(nil, permission, audit.OutcomeUnauthenticated, "bearer_invalid", resourceID)
			if a.failAudit(w, r, event, http.StatusUnauthorized) {
				writeProblem(w, http.StatusUnauthorized, "Invalid access token")
			}
			return
		}
		if resourceAware {
			// This coarse gate prevents non-reviewers from reaching a decision
			// handler. The handler's final Authorize call still needs the
			// request owner and is the only terminal authorization decision.
			if !authz.HasRole(authz.Principal{Subject: id.Subject, Roles: rolesFromStrings(id.Roles)}, authz.RoleReviewer) {
				event := cliAuditEvent(&id, permission, audit.OutcomeDenied, authz.ReasonRoleMissing, resourceID)
				if a.failAudit(w, r, event, http.StatusNotFound) {
					writeProblem(w, http.StatusNotFound, "Resource not found")
				}
				return
			}
		} else if decision := a.authorize(id.Roles, id.Subject, permission, authz.Resource{RequestID: resourceID}); !decision.Allowed {
			event := cliAuditEvent(&id, permission, audit.OutcomeDenied, decision.Reason, resourceID)
			if a.failAudit(w, r, event, http.StatusNotFound) {
				writeProblem(w, http.StatusNotFound, "Resource not found")
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), cliIdentityKey{}, id)))
	})
}

func cliPermission(path string) (authz.Permission, bool) {
	if strings.HasSuffix(path, "/evidence") {
		return authz.EvidenceRead, false
	}
	if strings.HasSuffix(path, "/decisions") {
		return authz.DecisionAdd, true
	}
	if strings.HasSuffix(path, "/challenges") {
		return authz.DecisionPrepare, true
	}
	return authz.RequestRead, false
}

func cliAction(permission authz.Permission) string {
	switch permission {
	case authz.RequestRead:
		return audit.ActionRequestRead
	case authz.EvidenceRead:
		return audit.ActionEvidenceRead
	case authz.DecisionPrepare:
		return audit.ActionDecisionPrepare
	case authz.DecisionAdd:
		return audit.ActionDecisionAdd
	default:
		return string(permission)
	}
}

func cliAuditEvent(id *auth.Identity, permission authz.Permission, outcome audit.Outcome, reason, resourceID string) audit.Event {
	event := audit.Event{
		ActionCode:    cliAction(permission),
		Outcome:       outcome,
		AuthMethod:    "bearer",
		Permission:    string(permission),
		PolicyVersion: authz.PolicyVersion,
		Reason:        reason,
		ResourceType:  "deployment_request",
		ResourceID:    resourceID,
		ActorType:     audit.ActorAnonymous,
	}
	if id != nil && id.Subject != "" {
		event.ActorID = id.Subject
		event.ActorName = id.Name
		event.ActorRoles = append([]string(nil), id.Roles...)
		event.ActorType = audit.ActorUser
	}
	return event
}

func decisionAuditMetadata(decision string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"decision":%q}`, decision))
}

func auditPersistenceFailure(err error) bool {
	var marker interface{ AuditAppendFailure() bool }
	return errors.As(err, &marker) && marker.AuditAppendFailure()
}

func (a *App) cliProblem(w http.ResponseWriter, r *http.Request, event audit.Event, status int, title string) {
	if a.failAudit(w, r, event, status) {
		writeProblem(w, status, title)
	}
}

func decisionMutationFailure(err error) (audit.Outcome, string, int, string) {
	if auditPersistenceFailure(err) {
		return audit.OutcomeFailed, "audit_append_failed", http.StatusServiceUnavailable, "Audit service unavailable"
	}
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return audit.OutcomeInvalid, "request_not_found", http.StatusNotFound, "Request not found"
	case err != nil && err.Error() == "reviewer cannot approve own request":
		return audit.OutcomeDenied, authz.ReasonSelfApproval, http.StatusNotFound, "Request not found"
	case err != nil && err.Error() == "request expired":
		return audit.OutcomeInvalid, "request_expired", http.StatusConflict, "request is not eligible for a decision"
	case err != nil && err.Error() == "request already decided":
		return audit.OutcomeInvalid, "request_already_decided", http.StatusConflict, "request is not eligible for a decision"
	case err != nil && (err.Error() == "challenge is invalid or expired" || err.Error() == "challenge is invalid or already consumed"):
		return audit.OutcomeInvalid, "challenge_invalid", http.StatusConflict, "challenge is invalid or expired"
	default:
		return audit.OutcomeFailed, "decision_commit_failed", http.StatusInternalServerError, "Could not record decision"
	}
}
func identity(r *http.Request) auth.Identity {
	return r.Context().Value(cliIdentityKey{}).(auth.Identity)
}
func (a *App) allows(roles []string, subject string, action authz.Action, resource authz.Resource) bool {
	return a.authorize(roles, subject, action, resource).Allowed
}
func (a *App) authorize(roles []string, subject string, action authz.Action, resource authz.Resource) authz.Decision {
	principal := authz.Principal{Subject: subject, Roles: rolesFromStrings(roles)}
	if a.Policy == nil {
		return authz.Policy{}.Authorize(authz.Request{Principal: principal, Permission: action, Resource: resource})
	}
	return a.Policy.Authorize(authz.Request{Principal: principal, Permission: action, Resource: resource})
}
func rolesFromStrings(roles []string) []authz.Role {
	normalized := authz.NormalizeRoles(roles)
	return normalized
}
func (a *App) apiRequest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := identity(r)
	if _, e := uuid.Parse(id); e != nil {
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.RequestRead, audit.OutcomeInvalid, "request_id_invalid", id), http.StatusNotFound, "Request not found")
		return
	}
	x, e := a.Store.GetRequest(r.Context(), id)
	if e != nil {
		outcome, reason, status, title := audit.OutcomeInvalid, "request_not_found", http.StatusNotFound, "Request not found"
		if !errors.Is(e, pgx.ErrNoRows) {
			outcome, reason, status, title = audit.OutcomeFailed, "request_read_failed", http.StatusInternalServerError, "Could not read request"
		}
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.RequestRead, outcome, reason, id), status, title)
		return
	}
	if !a.failAudit(w, r, cliAuditEvent(&actor, authz.RequestRead, audit.OutcomeSuccess, "read", id), http.StatusOK) {
		return
	}
	writeJSON(w, 200, dto(x))
}
func (a *App) apiEvidence(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := identity(r)
	if _, e := uuid.Parse(id); e != nil {
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.EvidenceRead, audit.OutcomeInvalid, "request_id_invalid", id), http.StatusNotFound, "Evidence not found")
		return
	}
	d, e := a.Store.RequestEvidence(r.Context(), id)
	if e != nil {
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.EvidenceRead, audit.OutcomeFailed, "evidence_read_failed", id), http.StatusInternalServerError, "Could not read evidence")
		return
	}
	if !a.failAudit(w, r, cliAuditEvent(&actor, authz.EvidenceRead, audit.OutcomeSuccess, "read", id), http.StatusOK) {
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
	id := chi.URLParam(r, "id")
	actor := identity(r)
	// Load and authorize the target first so resource denial is indistinguishable
	// from a missing request, even when the submitted challenge body is invalid.
	x, e := a.Store.GetRequest(r.Context(), id)
	if e != nil {
		outcome, reason, status, title := audit.OutcomeInvalid, "request_not_found", http.StatusNotFound, "Request not found"
		if !errors.Is(e, pgx.ErrNoRows) {
			outcome, reason, status, title = audit.OutcomeFailed, "request_lookup_failed", http.StatusInternalServerError, "Could not read request"
		}
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.DecisionPrepare, outcome, reason, id), status, title)
		return
	}
	if decision := a.authorize(actor.Roles, actor.Subject, authz.DecisionPrepare, authz.Resource{RequestID: x.ID, RequesterSubject: x.RequesterSubject}); !decision.Allowed {
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.DecisionPrepare, audit.OutcomeDenied, decision.Reason, id), http.StatusNotFound, "Request not found")
		return
	}
	invalid := func(reason, title string, status int) {
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.DecisionPrepare, audit.OutcomeInvalid, reason, id), status, title)
	}
	var in struct {
		Decision string `json:"decision"`
		Reason   string `json:"reason"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || in.Decision != "approved" && in.Decision != "rejected" {
		invalid("decision_invalid", "decision must be approved or rejected", http.StatusBadRequest)
		return
	}
	if in.Decision == "rejected" {
		if strings.TrimSpace(in.Reason) == "" {
			invalid("reason_required", "reason is required for rejection", http.StatusBadRequest)
			return
		}
	}
	if x.Decision != "pending" || time.Now().After(x.ExpiresAt) {
		invalid("request_not_eligible", "request is not eligible for a challenge", http.StatusConflict)
		return
	}
	nonce := randomToken(24)
	decision := in.Decision
	expiry := time.Now().Add(5 * time.Minute).UTC()
	digest := sha256.Sum256(x.Context)
	statement := evidence.Statement{Version: evidence.StatementVersion, Service: "wardenv", RequestID: x.ID, ContextDigest: "sha256:" + hex.EncodeToString(digest[:]), Decision: decision, Reason: in.Reason, Subject: identity(r).Subject, Nonce: nonce, Expiry: expiry.Unix()}
	successEvent := cliAuditEvent(&actor, authz.DecisionPrepare, audit.OutcomeSuccess, "challenge_created", id)
	successEvent.Metadata = decisionAuditMetadata(decision)
	successEvent = prepareAuditEvent(r, successEvent, http.StatusOK)
	if e := a.Store.CreateChallengeWithAudit(r.Context(), x.ID, actor.Subject, decision, in.Reason, hashValue(nonce), expiry, successEvent); e != nil {
		failureEvent := successEvent
		failureEvent.Outcome = audit.OutcomeFailed
		failureEvent.Metadata = nil
		if auditPersistenceFailure(e) {
			a.logAuditFailure(successEvent, e)
			failureEvent.Reason = "audit_append_failed"
			a.cliProblem(w, r, failureEvent, http.StatusServiceUnavailable, "Audit service unavailable")
			return
		}
		failureEvent.Reason = "challenge_create_failed"
		a.cliProblem(w, r, failureEvent, http.StatusInternalServerError, "Could not create challenge")
		return
	}
	writeJSON(w, 200, map[string]any{"statement": statement, "challenge": statement})
}
func (a *App) decide(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	actor := identity(r)
	// Resolve and authorize the target before parsing untrusted evidence. This
	// keeps missing, unauthorized, and self-owned resources on the same 404
	// path and prevents request existence disclosure through validation errors.
	reqForDecision, e := a.Store.GetRequest(r.Context(), id)
	if e != nil {
		outcome, reason, status, title := audit.OutcomeInvalid, "request_not_found", http.StatusNotFound, "Request not found"
		if !errors.Is(e, pgx.ErrNoRows) {
			outcome, reason, status, title = audit.OutcomeFailed, "request_lookup_failed", http.StatusInternalServerError, "Could not read request"
		}
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.DecisionAdd, outcome, reason, id), status, title)
		return
	}
	if decision := a.authorize(actor.Roles, actor.Subject, authz.DecisionAdd, authz.Resource{RequestID: reqForDecision.ID, RequesterSubject: reqForDecision.RequesterSubject}); !decision.Allowed {
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.DecisionAdd, audit.OutcomeDenied, decision.Reason, id), http.StatusNotFound, "Request not found")
		return
	}
	invalid := func(reason, title string) {
		a.cliProblem(w, r, cliAuditEvent(&actor, authz.DecisionAdd, audit.OutcomeInvalid, reason, id), http.StatusBadRequest, title)
	}
	var bundle evidence.Bundle
	body, eRead := io.ReadAll(r.Body)
	if eRead != nil || json.Unmarshal(body, &bundle) != nil || bundle.Signed.Statement.RequestID == "" {
		invalid("invalid_json", "invalid JSON")
		return
	}
	statementJSON, _ := json.Marshal(bundle.Signed.Statement)
	decision := bundle.Signed.Statement.Decision
	reason := bundle.Signed.Statement.Reason
	if len(bundle.CertificateChain) == 0 {
		invalid("certificate_missing", "certificate-backed evidence bundle is required")
		return
	}
	certs, e := parseCerts(bundle.CertificateChain)
	if e != nil || len(certs) == 0 {
		invalid("certificate_invalid", "invalid evidence certificate chain")
		return
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok || bundle.Signed.VerifySignature(pub) != nil {
		invalid("signature_invalid", "invalid evidence signature")
		return
	}
	if err := a.verifyEvidenceCertificate(certs, identity(r).Subject); err != nil {
		invalid("certificate_untrusted", "untrusted evidence certificate")
		return
	}
	if decision != "approved" && decision != "rejected" {
		invalid("decision_invalid", "decision must be approved or rejected")
		return
	}
	if decision == "rejected" && strings.TrimSpace(reason) == "" {
		invalid("reason_required", "reason is required for rejection")
		return
	}
	if len(statementJSON) == 0 || strings.TrimSpace(bundle.Signed.Signature) == "" {
		invalid("signed_evidence_missing", "signed evidence is required")
		return
	}
	var st evidence.Statement
	if e := json.Unmarshal(statementJSON, &st); e != nil {
		invalid("statement_invalid", "invalid signed statement")
		return
	}
	ctxDigest := sha256.Sum256(reqForDecision.Context)
	if st.ContextDigest != "sha256:"+hex.EncodeToString(ctxDigest[:]) || st.Service != "wardenv" {
		invalid("statement_context_mismatch", "statement context binding mismatch")
		return
	}
	if st.RequestID != id || st.Subject != actor.Subject {
		invalid("statement_binding_mismatch", "statement binding mismatch")
		return
	}
	expected := st.Decision
	if expected != decision || st.Reason != reason || st.Expiry < time.Now().Unix() {
		invalid("statement_binding_mismatch", "statement binding mismatch")
		return
	}
	if _, e := evidence.CanonicalStatement(st); e != nil {
		invalid("statement_invalid", "invalid signed statement")
		return
	}
	successEvent := cliAuditEvent(&actor, authz.DecisionAdd, audit.OutcomeSuccess, "decision_committed", id)
	successEvent.Metadata = decisionAuditMetadata(decision)
	successEvent = prepareAuditEvent(r, successEvent, http.StatusAccepted)
	d, e := a.Store.AcceptDecisionWithAudit(r.Context(), id, actor.Subject, actor.Name, decision, reason, hashValue(st.Nonce), body, bundle.Signed.Signature, successEvent)
	if e != nil {
		if auditPersistenceFailure(e) {
			a.logAuditFailure(successEvent, e)
		}
		outcome, failureReason, status, title := decisionMutationFailure(e)
		failureEvent := successEvent
		failureEvent.Outcome = outcome
		failureEvent.Reason = failureReason
		if !a.failAudit(w, r, failureEvent, status) {
			return
		}
		writeProblem(w, status, title)
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
