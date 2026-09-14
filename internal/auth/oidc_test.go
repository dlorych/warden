package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestNormalizedRolesDropsUnknownAndDuplicates(t *testing.T) {
	got := normalizedRoles([]string{"reviewer", "unknown", " reader ", "reviewer", "AUDITOR"})
	want := []string{"reader", "reviewer", "auditor"}
	if len(got) != len(want) {
		t.Fatalf("roles = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roles = %#v, want %#v", got, want)
		}
	}
}

func TestMalformedWardenRolesClaimCannotDecode(t *testing.T) {
	var c claims
	if err := json.Unmarshal([]byte(`{"warden_roles":["reader",7]}`), &c); err == nil {
		t.Fatal("malformed warden_roles claim decoded successfully")
	}
	if err := json.Unmarshal([]byte(`{"warden_roles":[null]}`), &c); err == nil {
		t.Fatal("null warden_roles element decoded successfully")
	}
}

func TestRPInitiatedLogoutURLUsesDiscoveredEndpointAndConfiguredRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "http://" + r.Host,
			"authorization_endpoint": "http://" + r.Host + "/authorize",
			"token_endpoint":         "http://" + r.Host + "/token",
			"jwks_uri":               "http://" + r.Host + "/keys",
			"end_session_endpoint":   "http://" + r.Host + "/logout",
		})
	}))
	defer server.Close()

	s := New(Config{OIDCIssuer: server.URL, OIDCClientID: "warden-bff"})
	if err := s.Discovery(t.Context()); err != nil {
		t.Fatal(err)
	}
	got, err := s.RPInitiatedLogoutURL("http://localhost:8080/")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Path != "/logout" {
		t.Fatalf("path=%q", u.Path)
	}
	if got := u.Query().Get("client_id"); got != "warden-bff" {
		t.Fatalf("client_id=%q", got)
	}
	if got := u.Query().Get("post_logout_redirect_uri"); got != "http://localhost:8080/" {
		t.Fatalf("post_logout_redirect_uri=%q", got)
	}
}

func TestRPInitiatedLogoutURLRequiresProviderEndpoint(t *testing.T) {
	s := New(Config{OIDCClientID: "warden-bff"})
	if _, err := s.RPInitiatedLogoutURL("http://localhost:8080/"); err == nil {
		t.Fatal("expected missing end-session endpoint error")
	}
}

func TestRPInitiatedLogoutURLRejectsUnusableRedirect(t *testing.T) {
	s := New(Config{OIDCClientID: "warden-bff"})
	s.meta.EndSessionEndpoint = "https://idp.example/logout"
	for _, redirect := range []string{"", "/relative", "javascript:alert(1)", "ftp://idp.example/return", "http://localhost:8080/#fragment", "not a URL"} {
		if _, err := s.RPInitiatedLogoutURL(redirect); err == nil {
			t.Fatalf("redirect %q was accepted", redirect)
		}
	}
}
