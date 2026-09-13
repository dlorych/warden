package auth

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
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
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&s.meta); e != nil {
		return e
	}
	if s.meta.Issuer == "" || strings.TrimRight(s.meta.Issuer, "/") != s.cfg.OIDCIssuer {
		return fmt.Errorf("oidc issuer mismatch")
	}
	return nil
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
	q := url.Values{"response_type": {"code"}, "client_id": {s.cfg.OIDCClientID}, "redirect_uri": {s.cfg.OIDCRedirectURL}, "scope": {"openid profile email groups"}, "state": {state}, "nonce": {nonce}, "code_challenge": {challenge(verifier)}, "code_challenge_method": {"S256"}, "audience": {s.cfg.OIDCAudience}}
	return s.meta.AuthorizationEndpoint + "?" + q.Encode()
}

// RPInitiatedLogoutURL returns the provider's RP-initiated logout URL. The
// redirect is supplied by application configuration, never by the browser,
// so callers can keep the provider's post-logout allowlist explicit.
//
// We intentionally do not retain or send an ID token hint. Keycloak accepts a
// client_id-only logout request, and avoiding token retention keeps the BFF
// session store free of reusable OIDC credentials.
func (s *Service) RPInitiatedLogoutURL(postLogoutRedirectURL string) (string, error) {
	if s.meta.EndSessionEndpoint == "" {
		return "", fmt.Errorf("oidc provider does not advertise end-session endpoint")
	}
	u, err := url.Parse(s.meta.EndSessionEndpoint)
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
}

func (s *Service) Exchange(ctx context.Context, code, verifier, nonceHash string) (Identity, error) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {s.cfg.OIDCRedirectURL}, "client_id": {s.cfg.OIDCClientID}, "code_verifier": {verifier}}
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, s.transportURL(s.meta.TokenEndpoint), strings.NewReader(form.Encode()))
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
		IDToken string `json:"id_token"`
	}
	if e = json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&tok); e != nil {
		return Identity{}, e
	}
	return s.verify(tok.IDToken, nonceHash)
}

type claims struct {
	Typ               string   `json:"typ"`
	Azp               string   `json:"azp"`
	Nonce             string   `json:"nonce"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Groups            []string `json:"groups"`
	Scope             string   `json:"scope"`
	jwt.RegisteredClaims
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
	return Identity{Subject: c.Subject, Name: name, Groups: c.Groups}, nil
}
func (s *Service) VerifyAccessToken(raw string) (Identity, error) {
	var c claims
	t, e := jwt.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unsupported access token algorithm")
		}
		kid, _ := t.Header["kid"].(string)
		return s.key(kid)
	}, jwt.WithIssuer(s.cfg.OIDCIssuer), jwt.WithAudience(s.cfg.OIDCAudience), jwt.WithExpirationRequired())
	if e != nil || !t.Valid {
		return Identity{}, fmt.Errorf("invalid access token: %w", e)
	}
	if c.Subject == "" || len(c.Audience) == 0 || (len(c.Audience) > 1 && c.Azp != s.cfg.OIDCAudience) {
		return Identity{}, fmt.Errorf("access token claims invalid")
	}
	if c.Typ != "" && c.Typ != "Bearer" && c.Typ != "at+jwt" {
		return Identity{}, fmt.Errorf("token is not an access token")
	}
	ok := false
	for _, x := range strings.Fields(c.Scope) {
		if x == "warden:decide" {
			ok = true
		}
	}
	if !ok {
		return Identity{}, fmt.Errorf("missing warden:decide scope")
	}
	name := c.Name
	if name == "" {
		name = c.PreferredUsername
	}
	return Identity{Subject: c.Subject, Name: name, Groups: c.Groups}, nil
}
func (s *Service) key(kid string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	k := s.keys[kid]
	s.mu.RUnlock()
	if k != nil {
		return k, nil
	}
	req, e := http.NewRequest(http.MethodGet, s.transportURL(s.meta.JWKSURI), nil)
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
