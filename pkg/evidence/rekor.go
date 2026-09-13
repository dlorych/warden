package evidence

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// RekorClient is a small Rekor v2 client for hashedrekord entries. The
// checkpoint key is supplied by the caller and is never learned from Rekor.
type RekorClient struct {
	BaseURL             string
	HTTPClient          *http.Client
	CheckpointPublicKey []byte // Ed25519 public key; independent trust anchor
	CheckpointOrigin    string
}

func (c *RekorClient) client() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

// Submit posts a v2 hashedrekord entry. Rekor itself computes the Merkle leaf;
// the response must contain an inclusion proof and signed checkpoint.
func (c *RekorClient) Submit(ctx context.Context, d SignedDecision, cert *x509.Certificate) (*RekorProof, error) {
	if c == nil || c.BaseURL == "" {
		return nil, errors.New("Rekor URL is required")
	}
	if cert == nil {
		return nil, errors.New("signing certificate is required")
	}
	if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
		return nil, errors.New("signing certificate must contain ECDSA key")
	}
	statement, err := d.CanonicalBytes()
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(statement)
	sig, err := base64.StdEncoding.DecodeString(d.Signature)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"hashedRekordRequestV002": map[string]any{
		"digest": base64.StdEncoding.EncodeToString(h[:]),
		"signature": map[string]any{"content": base64.StdEncoding.EncodeToString(sig), "verifier": map[string]any{
			"x509Certificate": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(cert.Raw)}, "keyDetails": "PKIX_ECDSA_P256_SHA_256",
		}},
	}}
	encoded, _ := json.Marshal(body)
	endpoint := strings.TrimRight(c.BaseURL, "/") + "/api/v2/log/entries"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("Rekor submit HTTP %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var response any
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("Rekor response: %w", err)
	}
	p, err := proofFromJSON(response)
	if err != nil {
		return nil, err
	}
	if len(c.CheckpointPublicKey) != ed25519.PublicKeySize {
		return nil, errors.New("independent Rekor checkpoint key is required")
	}
	if err := p.VerifyWithCertificateOrigin(d, cert, ed25519.PublicKey(c.CheckpointPublicKey), c.CheckpointOrigin); err != nil {
		return nil, err
	}
	return &p, nil
}

// proofFromJSON preserves the exact canonicalized_body returned by Rekor so
// offline verification hashes the bytes that Rekor witnessed.
func proofFromJSON(v any) (RekorProof, error) {
	b, _ := json.Marshal(v)
	var e struct {
		UUID              string          `json:"uuid"`
		CanonicalizedBody string          `json:"canonicalizedBody"`
		LogIndex          json.RawMessage `json:"logIndex"`
		InclusionProof    struct {
			LogIndex   json.RawMessage `json:"logIndex"`
			TreeSize   json.RawMessage `json:"treeSize"`
			RootHash   string          `json:"rootHash"`
			Hashes     []string        `json:"hashes"`
			Checkpoint struct {
				Envelope string `json:"envelope"`
			} `json:"checkpoint"`
		} `json:"inclusionProof"`
	}
	if err := json.Unmarshal(b, &e); err != nil {
		return RekorProof{}, err
	}
	p := RekorProof{Version: "rekor.v2", EntryID: e.UUID, InclusionPath: e.InclusionProof.Hashes, Checkpoint: e.InclusionProof.Checkpoint.Envelope}
	if e.CanonicalizedBody != "" {
		p.Entry = e.CanonicalizedBody
	}
	if p.Entry == "" {
		return RekorProof{}, errors.New("Rekor response missing canonicalized_body")
	}
	idx := e.LogIndex
	if len(idx) > 0 {
		var n int64
		if json.Unmarshal(idx, &n) == nil {
			p.LogIndex = n
		} else if s, ok := jsonNumberString(idx); ok {
			p.LogIndex, _ = strconv.ParseInt(s, 10, 64)
		}
	}
	ts := e.InclusionProof.TreeSize
	if len(ts) > 0 {
		var n int64
		if json.Unmarshal(ts, &n) == nil {
			p.TreeSize = n
		} else if s, ok := jsonNumberString(ts); ok {
			p.TreeSize, _ = strconv.ParseInt(s, 10, 64)
		}
	}
	if p.TreeSize <= 0 {
		return RekorProof{}, errors.New("Rekor response missing checkpoint tree size")
	}
	// Root hash and tree size are taken from the verified checkpoint, per v2.
	parts := strings.Split(strings.ReplaceAll(p.Checkpoint, "\r\n", "\n"), "\n")
	if len(parts) < 3 {
		return RekorProof{}, errors.New("Rekor response missing checkpoint envelope")
	}
	p.RootHash = strings.TrimSpace(parts[2])
	sigLine := ""
	for _, line := range parts {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "—") {
			fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(trimmed, "—")))
			if len(fields) >= 2 {
				sigLine = fields[len(fields)-1]
			}
			break
		}
	}
	if sigLine == "" {
		return RekorProof{}, errors.New("Rekor checkpoint has no signature")
	}
	sigRaw, err := base64.StdEncoding.DecodeString(sigLine)
	if err != nil {
		return RekorProof{}, errors.New("Rekor checkpoint signature is not base64")
	}
	p.CheckpointSignature = base64.StdEncoding.EncodeToString(sigRaw)
	return p, nil
}
func jsonNumberString(raw []byte) (string, bool) {
	var x json.Number
	if json.Unmarshal(raw, &x) == nil {
		return string(x), true
	}
	return "", false
}
