package auth

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/wardenv/service/internal/authz"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Service owns the browser OIDC flow. It deliberately does not accept callback
// URLs from requests: the configured redirect URI is persisted with each state.
type Config struct{ OIDCIssuer, OIDCClientID, OIDCClientSecret, OIDCRedirectURL, OIDCAudience, OIDCInternalBaseURL string }

func hash(v string) string { h := sha256.Sum256([]byte(v)); return hex.EncodeToString(h[:]) }

type Service struct {
	cfg    Config
	client *http.Client
	mu     sync.RWMutex
	meta   metadata
	keys   map[string]*rsa.PublicKey
}
type metadata struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

func New(c Config) *Service {
	return &Service{cfg: c, client: &http.Client{Timeout: 10 * time.Second}, keys: make(map[string]*rsa.PublicKey)}
}
func (s *Service) Discovery(ctx context.Context) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.transportURL(s.cfg.OIDCIssuer+"/.well-known/openid-configuration"), nil)
	res, e := s.client.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("oidc discovery: %s", res.Status)
	}
	var md metadata
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&md); e != nil {
		return e
	}
	if md.Issuer == "" || strings.TrimRight(md.Issuer, "/") != s.cfg.OIDCIssuer {
		return fmt.Errorf("oidc issuer mismatch")
	}
	s.mu.Lock()
	s.meta = md
	s.mu.Unlock()
	return nil
}
func (s *Service) metadata() metadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta
}
func (s *Service) transportURL(raw string) string {
	if s.cfg.OIDCInternalBaseURL == "" {
		return raw
	}
	u, e := url.Parse(raw)
	if e != nil {
		return raw
	}
	b, e := url.Parse(s.cfg.OIDCInternalBaseURL)
	if e != nil {
		return raw
	}
	u.Scheme = b.Scheme
	u.Host = b.Host
	return u.String()
}
func (s *Service) AuthorizationURL(state, verifier, nonce string) string {
	md := s.metadata()
	q := url.Values{"response_type": {"code"}, "client_id": {s.cfg.OIDCClientID}, "redirect_uri": {s.cfg.OIDCRedirectURL}, "scope": {"openid profile email groups warden_roles"}, "state": {state}, "nonce": {nonce}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "audience": {s.cfg.OIDCAudience}}
	return md.AuthorizationEndpoint + "?" + q.Encode()
}

// RPInitiatedLogoutURL returns the provider's RP-initiated logout URL. The
// redirect is supplied by application configuration, never by the browser,
// so callers can keep the provider's post-logout allowlist explicit.
//
// We intentionally do not retain or send an ID token hint. Keycloak accepts a
// client_id-only logout request, and avoiding token retention keeps the BFF
// session store free of reusable OIDC credentials.
func (s *Service) RPInitiatedLogoutURL(postLogoutRedirectURL string) (string, error) {
	md := s.metadata()
	if md.EndSessionEndpoint == "" {
		return "", fmt.Errorf("oidc provider does not advertise end-session endpoint")
	}
	u, err := url.Parse(md.EndSessionEndpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("oidc end-session endpoint is invalid")
	}
	redirect, err := url.Parse(postLogoutRedirectURL)
	if err != nil || redirect.Host == "" || redirect.Fragment != "" || (redirect.Scheme != "http" && redirect.Scheme != "https") {
		return "", fmt.Errorf("post-logout redirect URL is invalid")
	}
	q := u.Query()
	q.Set("client_id", s.cfg.OIDCClientID)
	q.Set("post_logout_redirect_uri", postLogoutRedirectURL)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func challenge(v string) string {
	h := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type Identity struct {
	Subject, Name string
	Groups        []string
	// Roles are normalized application roles. Tokens are never retained.
	Roles []string
	scope string
}

func (s *Service) Exchange(ctx context.Context, code, verifier, nonceHash string) (Identity, error) {
	md := s.metadata()
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.cfg.OIDCRedirectURL}, "client_id": {s.cfg.OIDCClientID}, "code_verifier": {verifier}}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, s.transportURL(md.TokenEndpoint), strings.NewReader(form.Encode()))
	if e != nil {
		return Identity{}, e
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if s.cfg.OIDCClientSecret != "" {
		req.SetBasicAuth(s.cfg.OIDCClientID, s.cfg.OIDCClientSecret)
	}
	res, e := s.client.Do(req)
	if e != nil {
		return Identity{}, e
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		return Identity{}, fmt.Errorf("oidc token exchange: %s", res.Status)
	}
	var tok struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&tok); e != nil {
		return Identity{}, e
	}
	id, err := s.verify(tok.IDToken, nonceHash)
	if err != nil {
		return Identity{}, err
	}
	if tok.AccessToken != "" {
		access, err := s.verifyAccessClaims(tok.AccessToken, false)
		if err != nil {
			return Identity{}, fmt.Errorf("invalid oidc access token: %w", err)
		}
		id.Roles = mergeRoles(id.Roles, access.Roles)
	}
	return id, nil
}

type claims struct {
	Typ               string     `json:"typ"`
	Azp               string     `json:"azp"`
	Nonce             string     `json:"nonce"`
	Name              string     `json:"name"`
	PreferredUsername string     `json:"preferred_username"`
	Groups            []string   `json:"groups"`
	Scope             string     `json:"scope"`
	WardenRoles       rolesClaim `json:"warden_roles"`
	jwt.RegisteredClaims
}

// rolesClaim is stricter than []string's JSON decoder: null array elements
// are not strings and therefore make authentication fail as malformed.
type rolesClaim []string

func (r *rolesClaim) UnmarshalJSON(raw []byte) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("warden_roles must be an array of strings")
	}
	var values []json.RawMessage
	if err := json.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("warden_roles must be an array of strings: %w", err)
	}
	result := make([]string, len(values))
	for i, value := range values {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("warden_roles[%d] must be a string", i)
		}
		if err := json.Unmarshal(value, &result[i]); err != nil {
			return fmt.Errorf("warden_roles[%d] must be a string: %w", i, err)
		}
	}
	*r = result
	return nil
}

func (s *Service) verify(raw, nonceHash string) (Identity, error) {
	var c claims
	t, e := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unsupported id token algorithm")
		}
		kid, _ := t.Header["kid"].(string)
		return s.key(kid)
	}, jwt.WithIssuer(s.cfg.OIDCIssuer), jwt.WithAudience(s.cfg.OIDCClientID), jwt.WithExpirationRequired())
	if e != nil || !t.Valid {
		return Identity{}, fmt.Errorf("invalid id token: %w", e)
	}
	if c.Subject == "" || len(c.Audience) == 0 || (len(c.Audience) > 1 && c.Azp != s.cfg.OIDCClientID) || c.Nonce == "" || hash(c.Nonce) != nonceHash {
		return Identity{}, fmt.Errorf("invalid oidc nonce")
	}
	name := c.Name
	if name == "" {
		name = c.PreferredUsername
	}
	return Identity{Subject: c.Subject, Name: name, Groups: c.Groups, Roles: normalizedRoles([]string(c.WardenRoles))}, nil
}
func (s *Service) VerifyAccessToken(raw string) (Identity, error) {
	id, e := s.verifyAccessClaims(raw, true)
	if e != nil {
		return Identity{}, e
	}
	ok := false
	for _, scope := range strings.Fields(id.scope) {
		if scope == "warden:decide" {
			ok = true
			break
		}
	}
	if !ok {
		return Identity{}, fmt.Errorf("missing warden:decide scope")
	}
	return id, nil
}

func (s *Service) verifyAccessClaims(raw string, requireAudience bool) (Identity, error) {
	var c claims
	keyFunc := func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unsupported access token algorithm")
		}
		kid, _ := t.Header["kid"].(string)
		return s.key(kid)
	}
	options := []jwt.ParserOption{jwt.WithIssuer(s.cfg.OIDCIssuer), jwt.WithExpirationRequired()}
	if requireAudience {
		options = append(options, jwt.WithAudience(s.cfg.OIDCAudience))
	}
	t, e := jwt.ParseWithClaims(raw, &c, keyFunc, options...)
	if e != nil || !t.Valid {
		return Identity{}, fmt.Errorf("invalid access token: %w", e)
	}
	if c.Subject == "" || (requireAudience && (len(c.Audience) == 0 || (len(c.Audience) > 1 && c.Azp != s.cfg.OIDCAudience))) {
		return Identity{}, fmt.Errorf("access token claims invalid")
	}
	if c.Typ != "" && c.Typ != "Bearer" && c.Typ != "at+jwt" {
		return Identity{}, fmt.Errorf("token is not an access token")
	}
	name := c.Name
	if name == "" {
		name = c.PreferredUsername
	}
	return Identity{Subject: c.Subject, Name: name, Groups: c.Groups, Roles: normalizedRoles([]string(c.WardenRoles)), scope: c.Scope}, nil
}

func normalizedRoles(raw []string) []string {
	roles := authz.NormalizeRoles(raw)
	result := make([]string, len(roles))
	for i, role := range roles {
		result[i] = string(role)
	}
	return result
}

func mergeRoles(left, right []string) []string {
	return normalizedRoles(append(append([]string(nil), left...), right...))
}
func (s *Service) key(kid string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	k := s.keys[kid]
	s.mu.RUnlock()
	if k != nil {
		return k, nil
	}
	md := s.metadata()
	req, e := http.NewRequest(http.MethodGet, s.transportURL(md.JWKSURI), nil)
	if e != nil {
		return nil, e
	}
	res, e := s.client.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&set); e != nil {
		return nil, e
	}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || j.Use != "sig" && j.Use != "" || j.Alg != "RS256" && j.Alg != "" {
			continue
		}
		nb, e := base64.RawURLEncoding.DecodeString(j.N)
		if e != nil {
			continue
		}
		eb, _ := base64.RawURLEncoding.DecodeString(j.E)
		ev := 0
		for _, b := range eb {
			ev = ev<<8 | int(b)
		}
		if ev == 0 {
			ev = 65537
		}
		pk := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: ev}
		s.mu.Lock()
		s.keys[j.Kid] = pk
		s.mu.Unlock()
		if j.Kid == kid {
			return pk, nil
		}
	}
	return nil, fmt.Errorf("oidc key %q not found", kid)
}
