// Command warden is the developer/user CLI. Production authentication always
// goes through OIDC; --access-token is an explicit headless test hook.
package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/wardenv/service/pkg/evidence"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "warden:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: warden verify BUNDLE --trust DEV_TRUST_FILE | warden decide REQUEST_ID | warden evidence download REQUEST_ID")
	}
	switch args[0] {
	case "verify":
		return verifyCmd(args[1:])
	case "decide":
		return decideCmd(args[1:])
	case "evidence":
		if len(args) > 1 && args[1] == "download" {
			return downloadCmd(args[2:])
		}
		return errors.New("usage: warden evidence download REQUEST_ID")
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func verifyCmd(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: warden verify BUNDLE --trust DEV_TRUST_FILE")
	}
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	trust := fs.String("trust", "", "CA trust JSON or PEM")
	subject := fs.String("subject", "", "expected OIDC subject")
	keyPath := fs.String("rekor-key", "", "independent Ed25519 checkpoint key")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *trust == "" {
		return errors.New("--trust is required")
	}
	raw, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var b evidence.Bundle
	if err = json.Unmarshal(raw, &b); err != nil {
		return err
	}
	pool, key, origin, err := loadTrust(*trust, *keyPath)
	if err != nil {
		return err
	}
	if err = b.VerifyWithOrigin(pool, *subject, key, origin); err != nil {
		return err
	}
	fmt.Println("valid evidence")
	return nil
}

type trustConfig struct {
	CAFile              string `json:"ca_file"`
	CheckpointPublicKey string `json:"checkpoint_public_key"`
	CheckpointOrigin    string `json:"checkpoint_origin"`
}

func loadTrust(path, keyPath string) (*x509.CertPool, ed25519.PublicKey, string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, "", err
	}
	ca := raw
	var cfg trustConfig
	if json.Unmarshal(raw, &cfg) == nil && cfg.CAFile != "" {
		p := cfg.CAFile
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(path), p)
		}
		ca, err = os.ReadFile(p)
		if err != nil {
			return nil, nil, "", err
		}
		if cfg.CheckpointPublicKey != "" {
			k, e := base64.StdEncoding.DecodeString(cfg.CheckpointPublicKey)
			if e != nil {
				return nil, nil, "", e
			}
			pool, e := certPool(ca)
			return pool, ed25519.PublicKey(k), cfg.CheckpointOrigin, e
		}
	}
	var key []byte
	if keyPath != "" {
		k, e := os.ReadFile(keyPath)
		if e != nil {
			return nil, nil, "", e
		}
		if p, _ := pem.Decode(k); p != nil {
			v, e := x509.ParsePKIXPublicKey(p.Bytes)
			if e != nil {
				return nil, nil, "", e
			}
			key, _ = v.(ed25519.PublicKey)
		} else {
			key, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(string(k)))
		}
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, nil, "", errors.New("independent Rekor Ed25519 key required")
	}
	pool, err := certPool(ca)
	return pool, ed25519.PublicKey(key), "", err
}
func certPool(raw []byte) (*x509.CertPool, error) {
	p := x509.NewCertPool()
	ok := false
	for len(raw) > 0 {
		b, rest := pem.Decode(raw)
		if b == nil {
			break
		}
		raw = rest
		if b.Type == "CERTIFICATE" {
			c, e := x509.ParseCertificate(b.Bytes)
			if e != nil {
				return nil, e
			}
			p.AddCert(c)
			ok = true
		}
	}
	if !ok {
		return nil, errors.New("trust file has no certificate")
	}
	return p, nil
}

type cliFlags struct{ api, token, authURL, tokenURL, clientID, key, cert string }

func parseClientFlags(args []string) (cliFlags, []string, error) {
	fs := flag.NewFlagSet("client", flag.ContinueOnError)
	var f cliFlags
	fs.StringVar(&f.api, "api", "http://localhost:8080", "warden API URL")
	fs.StringVar(&f.token, "access-token", "", "explicit headless access token test hook")
	fs.StringVar(&f.authURL, "auth-url", "http://localhost:8180/realms/warden/protocol/openid-connect/auth", "OIDC authorization endpoint")
	fs.StringVar(&f.tokenURL, "token-url", "http://localhost:8180/realms/warden/protocol/openid-connect/token", "OIDC token endpoint")
	fs.StringVar(&f.clientID, "client-id", "warden-cli", "OIDC client ID")
	fs.StringVar(&f.key, "key", ".dev/reviewer-key.pem", "user signing key")
	fs.StringVar(&f.cert, "cert", ".dev/reviewer.pem", "user signing certificate")
	pos := []string{}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos = append(pos, args[0])
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return f, nil, err
	}
	return f, append(pos, fs.Args()...), nil
}

type challenge struct {
	Service       string              `json:"service"`
	RequestID     string              `json:"request_id"`
	ContextDigest string              `json:"context_digest"`
	Nonce         string              `json:"nonce"`
	Subject       string              `json:"subject"`
	Expiry        int64               `json:"expiry"`
	Context       json.RawMessage     `json:"context"`
	Statement     *evidence.Statement `json:"statement"`
}

func decideCmd(args []string) error {
	f, rest, err := parseClientFlags(args)
	if err != nil {
		return err
	}
	if len(rest) != 1 {
		return errors.New("usage: warden decide REQUEST_ID [flags]")
	}
	id := rest[0]
	tok := f.token
	if tok == "" {
		tok, err = oidcToken(f)
		if err != nil {
			return err
		}
	}
	client := &http.Client{Timeout: 30 * time.Second}
	ctx := context.Background()
	reqCtx, err := getRequest(ctx, client, f.api, id, tok)
	if err != nil {
		return err
	}
	fmt.Printf("Request %s\nService: %s\nContext digest: %s\nContext: %s\n", id, reqCtx.Service, reqCtx.ContextDigest, string(reqCtx.Context))
	reader := bufio.NewReader(os.Stdin)
	decision := prompt(reader, "Decision (approved/rejected): ")
	if decision != "approved" && decision != "rejected" {
		return errors.New("decision must be approved or rejected")
	}
	reason := prompt(reader, "Reason: ")
	certRaw, err := os.ReadFile(f.cert)
	if err != nil {
		return err
	}
	subject, err := certificateSubject(certRaw)
	if err != nil {
		return err
	}
	ch, err := postChallenge(ctx, client, f.api, id, tok, decision, reason)
	if err != nil {
		return err
	}
	if ch.Statement == nil {
		return errors.New("challenge response has no statement")
	}
	st := *ch.Statement
	if st.RequestID != id || st.Service != reqCtx.Service || st.ContextDigest != reqCtx.ContextDigest || st.Subject != subject || st.Decision != decision || st.Reason != reason {
		return errors.New("challenge statement does not match displayed request, decision, reason, or certificate identity")
	}
	if prompt(reader, "Submit signed decision? [y/N] ") != "y" {
		return errors.New("decision cancelled")
	}
	pkRaw, err := os.ReadFile(f.key)
	if err != nil {
		return err
	}
	pk, err := evidence.LoadPrivateKey(pkRaw)
	if err != nil {
		return err
	}
	ec, ok := pk.(crypto.Signer)
	if !ok {
		return errors.New("user key is not ECDSA")
	}
	signed, err := evidence.SignStatement(st, ec)
	if err != nil {
		return err
	}
	chain, err := readPEMChain(f.cert)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(evidence.Bundle{Version: evidence.StatementVersion, Signed: signed, CertificateChain: chain})
	post, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(f.api, "/")+"/api/v1/requests/"+url.PathEscape(id)+"/decisions", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	post.Header.Set("Authorization", "Bearer "+tok)
	post.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(post)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("decision HTTP %s: %s", resp.Status, body)
	}
	fmt.Println("decision submitted")
	return nil
}
func getRequest(ctx context.Context, c *http.Client, api, id, tok string) (challenge, error) {
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(api, "/")+"/api/v1/requests/"+url.PathEscape(id), nil)
	if e != nil {
		return challenge{}, e
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, e := c.Do(req)
	if e != nil {
		return challenge{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return challenge{}, fmt.Errorf("request HTTP %s", resp.Status)
	}
	var ch challenge
	e = json.NewDecoder(resp.Body).Decode(&ch)
	if e != nil {
		return ch, e
	}
	if ch.Service == "" || ch.ContextDigest == "" {
		return challenge{}, errors.New("request response missing service/context digest")
	}
	return ch, nil
}
func postChallenge(ctx context.Context, c *http.Client, api, id, tok, decision, reason string) (challenge, error) {
	body, _ := json.Marshal(map[string]string{"decision": decision, "reason": reason})
	req, e := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(api, "/")+"/api/v1/requests/"+url.PathEscape(id)+"/challenges", strings.NewReader(string(body)))
	if e != nil {
		return challenge{}, e
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, e := c.Do(req)
	if e != nil {
		return challenge{}, e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return challenge{}, fmt.Errorf("challenge HTTP %s", resp.Status)
	}
	var ch challenge
	e = json.NewDecoder(resp.Body).Decode(&ch)
	return ch, e
}
func prompt(reader *bufio.Reader, s string) string {
	fmt.Print(s)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}
func certificateSubject(raw []byte) (string, error) {
	b, _ := pem.Decode(raw)
	if b == nil {
		return "", errors.New("certificate file has no PEM certificate")
	}
	c, e := x509.ParseCertificate(b.Bytes)
	if e != nil {
		return "", e
	}
	for _, u := range c.URIs {
		if strings.HasPrefix(u.String(), "urn:warden:oidc:") {
			return strings.TrimPrefix(u.String(), "urn:warden:oidc:"), nil
		}
	}
	return "", errors.New("certificate has no exact warden OIDC URI subject")
}
func readPEMChain(path string) ([]string, error) {
	raw, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	var out []string
	for len(raw) > 0 {
		b, rest := pem.Decode(raw)
		if b == nil {
			break
		}
		raw = rest
		if b.Type == "CERTIFICATE" {
			out = append(out, string(pem.EncodeToMemory(b)))
		}
	}
	if len(out) == 0 {
		return nil, errors.New("certificate file has no certificate")
	}
	return out, nil
}

func oidcToken(f cliFlags) (string, error) {
	v := make([]byte, 32)
	if _, e := rand.Read(v); e != nil {
		return "", e
	}
	verifier := base64.RawURLEncoding.EncodeToString(v)
	sum := sha256.Sum256([]byte(verifier))
	state := base64.RawURLEncoding.EncodeToString(v[:16])
	nonce := base64.RawURLEncoding.EncodeToString(v[16:])
	ln, e := net.Listen("tcp", "127.0.0.1:18765")
	if e != nil {
		return "", fmt.Errorf("OIDC loopback 127.0.0.1:18765: %w", e)
	}
	defer ln.Close()
	redirect := "http://127.0.0.1:18765/callback"
	q := url.Values{"client_id": {f.clientID}, "response_type": {"code"}, "redirect_uri": {redirect}, "scope": {"openid warden:decide"}, "audience": {"warden-cli"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "state": {state}, "nonce": {nonce}}
	openBrowser(f.authURL + "?" + q.Encode())
	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		err := http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/callback" || r.URL.Query().Get("state") != state {
				http.Error(w, "invalid callback", 400)
				return
			}
			fmt.Fprintln(w, "Authentication complete")
			done <- result{code: r.URL.Query().Get("code")}
		}))
		if err != nil {
			done <- result{err: err}
		}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return "", r.err
		}
		if r.code == "" {
			return "", errors.New("OIDC callback missing code")
		}
		return exchangeCode(f.tokenURL, f.clientID, redirect, r.code, verifier, nonce)
	case <-time.After(3 * time.Minute):
		return "", errors.New("OIDC login timed out")
	}
}
func exchangeCode(endpoint, client, redirect, code, verifier, nonce string) (string, error) {
	resp, e := http.PostForm(endpoint, url.Values{"grant_type": {"authorization_code"}, "client_id": {client}, "redirect_uri": {redirect}, "code": {code}, "code_verifier": {verifier}})
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("OIDC token HTTP %s", resp.Status)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if e = json.NewDecoder(resp.Body).Decode(&out); e != nil || out.AccessToken == "" {
		return "", errors.New("OIDC response has no access_token")
	}
	if out.IDToken != "" {
		if err := verifyIDTokenNonce(out.IDToken, nonce); err != nil {
			return "", err
		}
	}
	return out.AccessToken, nil
}
func verifyIDTokenNonce(raw, expected string) error {
	p := strings.Split(raw, ".")
	if len(p) != 3 {
		return errors.New("malformed OIDC id_token")
	}
	b, e := base64.RawURLEncoding.DecodeString(p[1])
	if e != nil {
		return e
	}
	var c struct {
		Nonce string `json:"nonce"`
	}
	if e = json.Unmarshal(b, &c); e != nil {
		return e
	}
	if c.Nonce != expected {
		return errors.New("OIDC id_token nonce mismatch")
	}
	return nil
}
func openBrowser(link string) {
	var c *exec.Cmd
	if runtime.GOOS == "darwin" {
		c = exec.Command("open", link)
	} else if runtime.GOOS == "windows" {
		c = exec.Command("rundll32", "url.dll,FileProtocolHandler", link)
	} else {
		c = exec.Command("xdg-open", link)
	}
	_ = c.Start()
}

func downloadCmd(args []string) error {
	fs := flag.NewFlagSet("evidence download", flag.ContinueOnError)
	api := fs.String("api", "http://localhost:8080", "warden API URL")
	token := fs.String("access-token", "", "explicit headless access token test hook")
	authURL := fs.String("auth-url", "http://localhost:8180/realms/warden/protocol/openid-connect/auth", "OIDC authorization endpoint")
	tokenURL := fs.String("token-url", "http://localhost:8180/realms/warden/protocol/openid-connect/token", "OIDC token endpoint")
	clientID := fs.String("client-id", "warden-cli", "OIDC client ID")
	out := fs.String("output", "", "output path")
	pos := []string{}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		pos = append(pos, args[0])
		args = args[1:]
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	ids := append(pos, fs.Args()...)
	if len(ids) != 1 {
		return errors.New("usage: warden evidence download REQUEST_ID [--access-token TOKEN] [--output FILE]")
	}
	if *token == "" {
		var err error
		*token, err = oidcToken(cliFlags{authURL: *authURL, tokenURL: *tokenURL, clientID: *clientID})
		if err != nil {
			return err
		}
	}
	if *out == "" {
		*out = ids[0] + ".bundle.json"
	}
	req, e := http.NewRequest(http.MethodGet, strings.TrimRight(*api, "/")+"/api/v1/requests/"+url.PathEscape(ids[0])+"/evidence", nil)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	resp, e := http.DefaultClient.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("evidence HTTP %s", resp.Status)
	}
	f, e := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	_, e = io.Copy(f, resp.Body)
	if e == nil {
		fmt.Println("saved", *out)
	}
	return e
}
