// Package evidence contains the portable, signed decision format used by
// warden.  It intentionally has no dependency on the HTTP service so that
// evidence can be verified offline.
package evidence

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

const StatementVersion = "warden.evidence.v1"

// Statement is the exact set of values signed for a decision. ContextDigest
// is the SHA-256 digest of the request context as returned by the service.
type Statement struct {
	Version       string `json:"version"`
	Service       string `json:"service"`
	RequestID     string `json:"request_id"`
	ContextDigest string `json:"context_digest"`
	Decision      string `json:"decision"`
	Reason        string `json:"reason"`
	Subject       string `json:"subject"`
	Nonce         string `json:"nonce"`
	Expiry        int64  `json:"expiry"`
}

func (s Statement) normalized() (Statement, error) {
	if s.Version == "" {
		s.Version = StatementVersion
	}
	if s.Version != StatementVersion {
		return Statement{}, fmt.Errorf("unsupported statement version %q", s.Version)
	}
	if s.Service == "" || s.RequestID == "" || s.ContextDigest == "" || s.Decision == "" || s.Subject == "" || s.Nonce == "" || s.Expiry <= 0 {
		return Statement{}, errors.New("statement requires service, request_id, context_digest, decision, subject, nonce and positive expiry")
	}
	if s.Decision != "approved" && s.Decision != "rejected" {
		return Statement{}, errors.New("decision must be approved or rejected")
	}
	for name, value := range map[string]string{"service": s.Service, "request_id": s.RequestID, "context_digest": s.ContextDigest, "decision": s.Decision, "reason": s.Reason, "subject": s.Subject, "nonce": s.Nonce} {
		if !utf8.ValidString(value) || len(value) > 4096 {
			return Statement{}, fmt.Errorf("%s is invalid UTF-8 or too long", name)
		}
	}
	digest := strings.TrimPrefix(s.ContextDigest, "sha256:")
	raw, err := hex.DecodeString(digest)
	if err != nil || len(raw) != sha256.Size {
		return Statement{}, errors.New("context_digest must be a 32-byte SHA-256 hex digest")
	}
	if s.Expiry > 9007199254740991 {
		return Statement{}, errors.New("expiry exceeds RFC8785 safe integer range")
	}
	return s, nil
}

// CanonicalStatement returns RFC 8785-style canonical JSON. Statement keys
// are ASCII and all numeric values are integral, making the representation
// independent of Go's map and JSON formatting behavior.
func CanonicalStatement(s Statement) ([]byte, error) {
	s, err := s.normalized()
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteByte('{')
	fields := []struct{ k, v string }{
		{"context_digest", quote(s.ContextDigest)}, {"decision", quote(s.Decision)},
		{"expiry", strconv.FormatInt(s.Expiry, 10)}, {"nonce", quote(s.Nonce)},
		{"reason", quote(s.Reason)}, {"request_id", quote(s.RequestID)},
		{"service", quote(s.Service)}, {"subject", quote(s.Subject)},
		{"version", quote(s.Version)},
	}
	for i, f := range fields {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(quote(f.k))
		b.WriteByte(':')
		b.WriteString(f.v)
	}
	b.WriteByte('}')
	return []byte(b.String()), nil
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

type SignedDecision struct {
	Statement Statement `json:"statement"`
	Signature string    `json:"signature"` // base64 DER-encoded ECDSA signature
}

// SignStatement accepts any crypto.Signer whose public key is ECDSA P-256.
// LoadPrivateKey currently supplies PEM-backed keys; callers can provide a
// PKCS#11, HSM, or OS keystore signer without changing the evidence format.
func SignStatement(s Statement, signer crypto.Signer) (SignedDecision, error) {
	if signer == nil {
		return SignedDecision{}, errors.New("signing key is required")
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub == nil || pub.Curve != elliptic.P256() {
		return SignedDecision{}, errors.New("signing key must be ECDSA P-256")
	}
	normalized, err := s.normalized()
	if err != nil {
		return SignedDecision{}, err
	}
	s = normalized
	b, err := CanonicalStatement(s)
	if err != nil {
		return SignedDecision{}, err
	}
	d := sha256.Sum256(b)
	sig, err := signer.Sign(rand.Reader, d[:], crypto.SHA256)
	if err != nil {
		return SignedDecision{}, err
	}
	return SignedDecision{Statement: s, Signature: base64.StdEncoding.EncodeToString(sig)}, nil
}

func (d SignedDecision) VerifySignature(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve != elliptic.P256() {
		return errors.New("verification key must be ECDSA P-256")
	}
	b, err := CanonicalStatement(d.Statement)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(d.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	digest := sha256.Sum256(b)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("invalid decision signature")
	}
	return nil
}

func (d SignedDecision) CanonicalBytes() ([]byte, error) { return CanonicalStatement(d.Statement) }
func (d SignedDecision) ContextHash() ([]byte, error) {
	b, e := d.CanonicalBytes()
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	return h[:], nil
}

// RekorProof contains the data needed for an offline inclusion check. Hashes
// are hex encoded SHA-256 values; checkpoint signature is Ed25519 over the
// exact checkpoint bytes using the independently configured key.
type RekorProof struct {
	Version             string   `json:"version"`
	EntryID             string   `json:"entry_id"`
	LogIndex            int64    `json:"log_index"`
	LeafHash            string   `json:"leaf_hash"`
	InclusionPath       []string `json:"inclusion_path"`
	RootHash            string   `json:"root_hash"`
	Checkpoint          string   `json:"checkpoint"`
	CheckpointSignature string   `json:"checkpoint_signature"`
	TreeSize            int64    `json:"tree_size"`
	Entry               string   `json:"entry,omitempty"` // base64 exact hashedrekord entry bytes
}

type Bundle struct {
	Version          string         `json:"version"`
	Signed           SignedDecision `json:"signed"`
	CertificateChain []string       `json:"certificate_chain"` // leaf first, PEM
	Rekor            *RekorProof    `json:"rekor,omitempty"`
}

// Verification intentionally defers historical RFC 3161 timestamp validity;
// Rekor v2 integrated time is not treated as a trusted timestamp.

func (b Bundle) MarshalJSON() ([]byte, error) {
	type plain Bundle
	if b.Version == "" {
		b.Version = StatementVersion
	}
	return json.Marshal(plain(b))
}

func (b Bundle) Verify(trust *x509.CertPool, expectedSubject string, checkpointKey ed25519.PublicKey) error {
	return b.VerifyWithOrigin(trust, expectedSubject, checkpointKey, "")
}
func (b Bundle) VerifyWithOrigin(trust *x509.CertPool, expectedSubject string, checkpointKey ed25519.PublicKey, expectedOrigin string) error {
	if b.Version != "" && b.Version != StatementVersion {
		return fmt.Errorf("unsupported bundle version %q", b.Version)
	}
	if len(b.CertificateChain) == 0 {
		return errors.New("bundle has no certificate chain")
	}
	certs, err := parsePEMChain(b.CertificateChain)
	if err != nil {
		return err
	}
	leaf, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("leaf certificate key is not ECDSA")
	}
	if trust == nil {
		return errors.New("explicit CA trust pool is required")
	}
	if expectedSubject == "" {
		expectedSubject = b.Signed.Statement.Subject
	}
	if expectedSubject != "" && CertificateSubject(leafCert(certs), expectedSubject) == false {
		return fmt.Errorf("certificate identity does not match subject %q", expectedSubject)
	}
	if err := b.Signed.VerifySignature(leaf); err != nil {
		return err
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: trust, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("certificate chain: %w", err)
	}
	if b.Rekor == nil {
		return errors.New("bundle has no Rekor inclusion proof")
	}
	return b.Rekor.VerifyWithCertificateOrigin(b.Signed, certs[0], checkpointKey, expectedOrigin)
}

func leafCert(cs []*x509.Certificate) *x509.Certificate {
	if len(cs) == 0 {
		return nil
	}
	return cs[0]
}
func CertificateSubject(c *x509.Certificate, expected string) bool {
	if c == nil {
		return false
	}
	for _, u := range c.URIs {
		if u.String() == "urn:warden:oidc:"+expected {
			return true
		}
	}
	return false
}

func parsePEMChain(chain []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(chain))
	for i, text := range chain {
		p, _ := pem.Decode([]byte(text))
		if p == nil {
			return nil, fmt.Errorf("certificate %d is not PEM", i)
		}
		c, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func (p RekorProof) Verify(d SignedDecision, key ed25519.PublicKey) error {
	return p.VerifyWithCertificate(d, nil, key)
}

func (p RekorProof) VerifyWithCertificate(d SignedDecision, cert *x509.Certificate, key ed25519.PublicKey) error {
	return p.VerifyWithCertificateOrigin(d, cert, key, "")
}
func (p RekorProof) VerifyWithCertificateOrigin(d SignedDecision, cert *x509.Certificate, key ed25519.PublicKey, expectedOrigin string) error {
	if len(key) != ed25519.PublicKeySize {
		return errors.New("independent Rekor checkpoint key is required")
	}
	if p.Entry == "" {
		return errors.New("Rekor canonicalized_body is required")
	}
	leafBytes, err := base64.StdEncoding.DecodeString(p.Entry)
	if err != nil {
		return fmt.Errorf("Rekor entry: %w", err)
	}
	if err := verifyRekorEntry(leafBytes, d, cert); err != nil {
		return err
	}
	origin := strings.SplitN(strings.ReplaceAll(p.Checkpoint, "\r\n", "\n"), "\n", 2)[0]
	if strings.TrimSpace(origin) == "" {
		return errors.New("empty Rekor checkpoint origin")
	}
	if expectedOrigin != "" && strings.TrimSpace(origin) != expectedOrigin {
		return fmt.Errorf("unexpected Rekor checkpoint origin %q", strings.TrimSpace(origin))
	}
	vkey, err := note.NewEd25519VerifierKey(origin, key)
	if err != nil {
		return err
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		return err
	}
	n, err := note.Open([]byte(p.Checkpoint), note.VerifierList(verifier))
	if err != nil {
		return fmt.Errorf("Rekor checkpoint signature: %w", err)
	}
	if len(n.Sigs) == 0 {
		return errors.New("Rekor checkpoint has no trusted signature")
	}
	checkpointSize, checkpointRoot, _, err := parseCheckpoint(n.Text)
	if err != nil {
		return err
	}
	if p.TreeSize > 0 && p.TreeSize != checkpointSize {
		return errors.New("Rekor checkpoint tree size mismatch")
	}
	leafHash := sha256.Sum256(append([]byte{0}, leafBytes...))
	got := leafHash[:]
	if p.LeafHash != "" {
		want, e := decodeHash(p.LeafHash)
		if e != nil || !bytes.Equal(want, got) {
			return errors.New("Rekor leaf hash mismatch")
		}
	}
	idx := p.LogIndex
	if idx < 0 || idx >= checkpointSize {
		return errors.New("invalid Rekor log index/tree size")
	}
	path := make([][]byte, len(p.InclusionPath))
	for i, raw := range p.InclusionPath {
		path[i], err = decodeHash(raw)
		if err != nil {
			return err
		}
	}
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(p.LogIndex), uint64(checkpointSize), got, path, checkpointRoot); err != nil {
		return fmt.Errorf("Rekor inclusion proof: %w", err)
	}
	return nil
}

func decodeHash(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if x, e := hex.DecodeString(strings.TrimPrefix(s, "0x")); e == nil && len(x) == sha256.Size {
		return x, nil
	}
	if x, e := base64.StdEncoding.DecodeString(s); e == nil && len(x) == sha256.Size {
		return x, nil
	}
	return nil, fmt.Errorf("invalid SHA-256 hash %q", s)
}
func parseCheckpoint(s string) (int64, []byte, []byte, error) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) < 3 {
		return 0, nil, nil, errors.New("malformed Rekor checkpoint")
	}
	origin := strings.TrimSpace(lines[0])
	if origin == "" {
		return 0, nil, nil, errors.New("empty Rekor checkpoint origin")
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(lines[1]), 10, 64)
	if err != nil || parsed <= 0 {
		return 0, nil, nil, errors.New("malformed Rekor checkpoint tree size")
	}
	checkpointRoot, err := decodeHash(strings.TrimSpace(lines[2]))
	if err != nil {
		return 0, nil, nil, errors.New("malformed Rekor checkpoint root")
	}
	marker := strings.Index(s, "\n—")
	if marker >= 0 {
		s = s[:marker+1]
	}
	return parsed, checkpointRoot, []byte(s), nil
}

func verifyRekorEntry(body []byte, d SignedDecision, cert *x509.Certificate) error {
	var e struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Spec       struct {
			HR struct {
				Data struct {
					Algorithm string `json:"algorithm"`
					Digest    string `json:"digest"`
				} `json:"data"`
				Signature struct {
					Content  string `json:"content"`
					Verifier struct {
						KeyDetails string `json:"keyDetails"`
						PublicKey  struct {
							RawBytes string `json:"rawBytes"`
						} `json:"publicKey"`
						X509Certificate struct {
							RawBytes string `json:"rawBytes"`
						} `json:"x509Certificate"`
					} `json:"verifier"`
				} `json:"signature"`
			} `json:"hashedRekordV002"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(body, &e); err != nil {
		return fmt.Errorf("Rekor canonicalized_body: %w", err)
	}
	if e.Kind != "hashedrekord" || e.APIVersion != "0.0.2" {
		return errors.New("unsupported Rekor canonicalized_body kind/version")
	}
	if e.Spec.HR.Data.Algorithm != "SHA2_256" || e.Spec.HR.Data.Digest == "" || e.Spec.HR.Signature.Content == "" || e.Spec.HR.Signature.Verifier.KeyDetails != "PKIX_ECDSA_P256_SHA_256" {
		return errors.New("incomplete Rekor hashedrekord body")
	}
	canonical, err := d.CanonicalBytes()
	if err != nil {
		return err
	}
	h := sha256.Sum256(canonical)
	digest, err := base64.StdEncoding.DecodeString(e.Spec.HR.Data.Digest)
	if err != nil || !bytes.Equal(digest, h[:]) {
		return errors.New("Rekor artifact digest does not match decision")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Spec.HR.Signature.Content)
	expected, _ := base64.StdEncoding.DecodeString(d.Signature)
	if err != nil || !bytes.Equal(sig, expected) {
		return errors.New("Rekor signature does not match decision")
	}
	if cert != nil {
		der, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
		raw := e.Spec.HR.Signature.Verifier.PublicKey.RawBytes
		if raw == "" {
			raw = e.Spec.HR.Signature.Verifier.X509Certificate.RawBytes
			certDER := cert.Raw
			got, _ := base64.StdEncoding.DecodeString(raw)
			if !bytes.Equal(got, certDER) {
				return errors.New("Rekor verifier certificate does not match bundle")
			}
		} else {
			got, _ := base64.StdEncoding.DecodeString(raw)
			if !bytes.Equal(got, der) {
				return errors.New("Rekor verifier key does not match bundle")
			}
		}
	}
	return nil
}
func canonicalSignedForRekor(d SignedDecision) ([]byte, error) {
	return CanonicalStatement(d.Statement)
}

// LoadPrivateKey accepts PEM EC PRIVATE KEY, PKCS#8 and RSA keys (RSA is
// useful to callers for unrelated app credentials, but cannot sign decisions).
func LoadPrivateKey(p []byte) (crypto.PrivateKey, error) {
	b, _ := pem.Decode(p)
	if b == nil {
		return nil, errors.New("missing PEM private key")
	}
	if k, e := x509.ParseECPrivateKey(b.Bytes); e == nil {
		return k, nil
	}
	if k, e := x509.ParsePKCS8PrivateKey(b.Bytes); e == nil {
		return k, nil
	}
	if k, e := x509.ParsePKCS1PrivateKey(b.Bytes); e == nil {
		return k, nil
	}
	return nil, errors.New("unsupported private key PEM")
}

// NewDevCA and NewDevCertificate are used by cmd/devinit and test fixtures.
func NewDevCA(now time.Time) (key *ecdsa.PrivateKey, cert *x509.Certificate, certPEM, keyPEM []byte, err error) {
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkixName("Warden Development CA"), NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if e != nil {
		err = e
		return
	}
	cert, err = x509.ParseCertificate(der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return
}

// pkixName is kept as a helper to keep dev certificate creation centralized.
func pkixName(cn string) pkix.Name {
	return pkix.Name{CommonName: cn, Organization: []string{"Warden Development"}}
}

func NewDevCertificate(now time.Time, ca *x509.Certificate, caKey *ecdsa.PrivateKey, subject string) (key *ecdsa.PrivateKey, cert *x509.Certificate, certPEM, keyPEM []byte, err error) {
	if ca == nil || caKey == nil || subject == "" {
		err = errors.New("CA, CA key and subject are required")
		return
	}
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	u, _ := url.Parse("urn:warden:oidc:" + subject)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkixName(subject), URIs: []*url.URL{u}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if e != nil {
		err = e
		return
	}
	cert, err = x509.ParseCertificate(der)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	kb, _ := x509.MarshalECPrivateKey(key)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
	return
}
