package app

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr, DatabaseURL                                                     string
	PublicURL, WebURL                                                     string
	OIDCIssuer, OIDCClientID, OIDCClientSecret, OIDCRedirectURL           string
	OIDCPostLogoutRedirectURL                                             string
	OIDCInternalBaseURL                                                   string
	OIDCAudience                                                          string
	GitHubAPIBaseURL, GitHubWebhookSecret                                 string
	RekorURL, RekorCheckpointKey, RekorCheckpointOrigin, EvidenceTrustPEM string
	GitHubAppID                                                           int64
	GitHubActorSubjects                                                   map[string]string
	GitHubPrivateKey                                                      string
	CookieSecure                                                          bool
	SessionSecret                                                         []byte
	SessionIdle, SessionAbsolute                                          time.Duration
}

func LoadConfig() (Config, error) {
	c := Config{Addr: env("ADDR", ":8080"), DatabaseURL: os.Getenv("DATABASE_URL"), PublicURL: env("PUBLIC_URL", "http://localhost:8080"), WebURL: env("WEB_URL", "http://localhost:3000"),
		OIDCIssuer: strings.TrimRight(os.Getenv("OIDC_ISSUER"), "/"), OIDCInternalBaseURL: strings.TrimRight(os.Getenv("OIDC_INTERNAL_BASE_URL"), "/"), OIDCClientID: env("OIDC_CLIENT_ID", "warden-web"), OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"), OIDCRedirectURL: os.Getenv("OIDC_REDIRECT_URL"), OIDCPostLogoutRedirectURL: os.Getenv("OIDC_POST_LOGOUT_REDIRECT_URL"), OIDCAudience: env("OIDC_AUDIENCE", "warden-cli"), GitHubAPIBaseURL: env("GITHUB_API_BASE_URL", "https://api.github.com"), GitHubWebhookSecret: os.Getenv("GITHUB_WEBHOOK_SECRET"), GitHubPrivateKey: os.Getenv("GITHUB_APP_PRIVATE_KEY"), SessionIdle: 30 * time.Minute, SessionAbsolute: 8 * time.Hour}
	c.RekorURL = os.Getenv("REKOR_URL")
	c.RekorCheckpointKey = os.Getenv("REKOR_CHECKPOINT_PUBLIC_KEY")
	c.RekorCheckpointOrigin = env("REKOR_CHECKPOINT_ORIGIN", "rekor-local")
	c.EvidenceTrustPEM = os.Getenv("EVIDENCE_TRUST_PEM")
	c.GitHubActorSubjects = map[string]string{}
	// The bundled GitHub fixture emits actor id 42 for the fixed MVP requester.
	c.GitHubActorSubjects["42"] = "11111111-1111-4111-8111-111111111111"
	if raw := os.Getenv("GITHUB_ACTOR_SUBJECT_MAP"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &c.GitHubActorSubjects); err != nil {
			return c, fmt.Errorf("GITHUB_ACTOR_SUBJECT_MAP: %w", err)
		}
	}
	if c.GitHubPrivateKey == "" {
		c.GitHubPrivateKey = readConfigFile(os.Getenv("GITHUB_APP_PRIVATE_KEY_FILE"))
	}
	if c.EvidenceTrustPEM == "" {
		c.EvidenceTrustPEM = readConfigFile(os.Getenv("EVIDENCE_TRUST_FILE"))
	}
	if c.RekorCheckpointKey == "" {
		if raw := readConfigFile(os.Getenv("REKOR_CHECKPOINT_PUBLIC_KEY_FILE")); raw != "" {
			if block, _ := pem.Decode([]byte(raw)); block != nil {
				if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
					if pub, ok := key.(ed25519.PublicKey); ok {
						c.RekorCheckpointKey = base64.RawStdEncoding.EncodeToString(pub)
					}
				}
			}
		}
	}
	if c.OIDCRedirectURL == "" {
		c.OIDCRedirectURL = strings.TrimRight(c.PublicURL, "/") + "/bff/callback"
	}
	if c.OIDCPostLogoutRedirectURL == "" {
		c.OIDCPostLogoutRedirectURL = strings.TrimRight(c.PublicURL, "/") + "/"
	}
	c.CookieSecure = strings.HasPrefix(c.PublicURL, "https://")
	if c.DatabaseURL == "" {
		return c, fmt.Errorf("DATABASE_URL is required")
	}
	if c.OIDCIssuer == "" {
		return c, fmt.Errorf("OIDC_ISSUER is required")
	}
	if c.SessionSecret = []byte(os.Getenv("SESSION_SECRET")); len(c.SessionSecret) < 32 {
		return c, fmt.Errorf("SESSION_SECRET must contain at least 32 bytes")
	}
	if x := os.Getenv("GITHUB_APP_ID"); x != "" {
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return c, fmt.Errorf("GITHUB_APP_ID: %w", err)
		}
		c.GitHubAppID = n
	}
	if c.GitHubAppID == 0 || c.GitHubPrivateKey == "" || c.GitHubWebhookSecret == "" {
		return c, fmt.Errorf("GitHub App credentials, private key, and webhook secret are required")
	}
	if c.RekorURL == "" || c.RekorCheckpointKey == "" || c.EvidenceTrustPEM == "" {
		return c, fmt.Errorf("Rekor URL, checkpoint key, and evidence trust are required")
	}
	if u, err := url.Parse(c.OIDCRedirectURL); err != nil || u.Scheme == "" || u.Host == "" {
		return c, fmt.Errorf("OIDC_REDIRECT_URL must be an absolute URL")
	}
	if u, err := url.Parse(c.OIDCPostLogoutRedirectURL); err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return c, fmt.Errorf("OIDC_POST_LOGOUT_REDIRECT_URL must be an absolute HTTP(S) URL")
	}
	return c, nil
}
func readConfigFile(name string) string {
	if name == "" {
		return ""
	}
	b, err := os.ReadFile(name)
	if err != nil {
		return ""
	}
	return string(b)
}
func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
