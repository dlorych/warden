package evidence

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/note"
)

func TestSignAndVerifyBundleOneLeaf(t *testing.T) {
	now := time.Now().UTC()
	cak, cac, capem, _, err := NewDevCA(now)
	if err != nil {
		t.Fatal(err)
	}
	uk, ucert, ucertpem, _, err := NewDevCertificate(now, cac, cak, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	d, err := SignStatement(Statement{Service: "svc", RequestID: "r1", ContextDigest: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), Decision: "approved", Reason: "ok", Subject: "11111111-1111-4111-8111-111111111111", Nonce: "n", Expiry: time.Now().Add(time.Hour).Unix()}, uk)
	if err != nil {
		t.Fatal(err)
	}
	statement, _ := d.CanonicalBytes()
	statementHash := sha256.Sum256(statement)
	pubDER, _ := x509.MarshalPKIXPublicKey(ucert.PublicKey)
	entry, _ := json.Marshal(map[string]any{"apiVersion": "0.0.2", "kind": "hashedrekord", "spec": map[string]any{"hashedRekordV002": map[string]any{"data": map[string]any{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(statementHash[:])}, "signature": map[string]any{"content": d.Signature, "verifier": map[string]any{"keyDetails": "PKIX_ECDSA_P256_SHA_256", "publicKey": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(pubDER)}}}}}})
	leaf := sha256.Sum256(append([]byte{0}, entry...))
	root := base64.StdEncoding.EncodeToString(leaf[:])
	checkpointText := "rekor-local\n1\n" + root + "\n"
	sk, vk, _ := note.GenerateKey(rand.Reader, "rekor-local")
	signer, _ := note.NewSigner(sk)
	checkpointBytes, _ := note.Sign(&note.Note{Text: checkpointText}, signer)
	checkpoint := string(checkpointBytes)
	ck := verifierPublic(vk)
	pool := x509Pool(capem)
	b := Bundle{Version: StatementVersion, Signed: d, CertificateChain: []string{string(ucertpem), string(capem)}, Rekor: &RekorProof{Version: "rekor.v2", LogIndex: 0, TreeSize: 1, LeafHash: hex.EncodeToString(leaf[:]), RootHash: root, Checkpoint: checkpoint, Entry: base64.StdEncoding.EncodeToString(entry)}}
	if err := b.Verify(pool, "11111111-1111-4111-8111-111111111111", ck); err != nil {
		t.Fatal(err)
	}
}

func x509Pool(p []byte) *x509.CertPool {
	pool := x509.NewCertPool()
	block, _ := pem.Decode(p)
	c, _ := x509.ParseCertificate(block.Bytes)
	pool.AddCert(c)
	return pool
}

func TestRekorProofTreeSizesAndBinding(t *testing.T) {
	now := time.Now().UTC()
	cak, cac, _, _, _ := NewDevCA(now)
	uk, cert, _, _, _ := NewDevCertificate(now, cac, cak, "11111111-1111-4111-8111-111111111111")
	var ds []SignedDecision
	var entries, leaves [][]byte
	for i := 0; i < 3; i++ {
		d, e := SignStatement(Statement{Service: "svc", RequestID: fmt.Sprintf("r%d", i), ContextDigest: hex.EncodeToString(bytes.Repeat([]byte{byte(i + 2)}, 32)), Decision: "approved", Reason: "ok", Subject: "11111111-1111-4111-8111-111111111111", Nonce: fmt.Sprintf("n%d", i), Expiry: now.Add(time.Hour).Unix()}, uk)
		if e != nil {
			t.Fatal(e)
		}
		body := rekorBodyForTest(t, d, cert)
		h := sha256.Sum256(append([]byte{0}, body...))
		ds = append(ds, d)
		entries = append(entries, body)
		leaves = append(leaves, h[:])
	}
	inner := nodeHash(leaves[0], leaves[1])
	root2 := inner
	root3 := nodeHash(inner, leaves[2])
	cases := []struct {
		idx, size int
		root      []byte
		path      [][]byte
	}{{0, 2, root2, [][]byte{leaves[1]}}, {1, 2, root2, [][]byte{leaves[0]}}, {0, 3, root3, [][]byte{leaves[1], leaves[2]}}, {2, 3, root3, [][]byte{inner}}}
	for _, tc := range cases {
		sk, vk, _ := note.GenerateKey(rand.Reader, "rekor-local")
		signer, _ := note.NewSigner(sk)
		text := fmt.Sprintf("rekor-local\n%d\n%s\n", tc.size, base64.StdEncoding.EncodeToString(tc.root))
		env, _ := note.Sign(&note.Note{Text: text}, signer)
		p := &RekorProof{LogIndex: int64(tc.idx), TreeSize: int64(tc.size), Entry: base64.StdEncoding.EncodeToString(entries[tc.idx]), Checkpoint: string(env), InclusionPath: hashStrings(tc.path)}
		if err := p.VerifyWithCertificateOrigin(ds[tc.idx], cert, verifierPublic(vk), "rekor-local"); err != nil {
			t.Fatal(err)
		}
	}
	sk, vk, _ := note.GenerateKey(rand.Reader, "rekor-local")
	signer, _ := note.NewSigner(sk)
	env, _ := note.Sign(&note.Note{Text: fmt.Sprintf("rekor-local\n2\n%s\n", base64.StdEncoding.EncodeToString(root2))}, signer)
	bad := &RekorProof{LogIndex: 0, TreeSize: 2, Entry: base64.StdEncoding.EncodeToString(entries[1]), Checkpoint: string(env), InclusionPath: hashStrings([][]byte{leaves[1]})}
	if err := bad.VerifyWithCertificateOrigin(ds[0], cert, verifierPublic(vk), "rekor-local"); err == nil {
		t.Fatal("swapped Rekor body accepted")
	}
}

func TestRekorV2ResponseEnvelopeParsing(t *testing.T) {
	text := "rekor-local\n1\n" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)) + "\n"
	sk, _, _ := note.GenerateKey(rand.Reader, "rekor-local")
	signer, _ := note.NewSigner(sk)
	env, _ := note.Sign(&note.Note{Text: text}, signer)
	p, err := proofFromJSON(map[string]any{"logIndex": "0", "canonicalizedBody": base64.StdEncoding.EncodeToString([]byte(`{"apiVersion":"0.0.2","kind":"hashedrekord","spec":{"hashedRekordV002":{}}}`)), "inclusionProof": map[string]any{"treeSize": "1", "hashes": []string{}, "checkpoint": map[string]string{"envelope": string(env)}}})
	if err != nil {
		t.Fatal(err)
	}
	if p.CheckpointSignature == "" {
		t.Fatal("checkpoint signature not parsed from em-dash line")
	}
}

func TestSignStatementUsesCryptoSigner(t *testing.T) {
	now := time.Now().UTC()
	cak, cac, _, _, _ := NewDevCA(now)
	uk, _, _, _, _ := NewDevCertificate(now, cac, cak, "11111111-1111-4111-8111-111111111111")
	s := Statement{Service: "svc", RequestID: "r", ContextDigest: hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), Decision: "approved", Subject: "11111111-1111-4111-8111-111111111111", Nonce: "n", Expiry: now.Add(time.Hour).Unix()}
	if _, err := SignStatement(s, uk); err != nil {
		t.Fatal(err)
	}
	if _, err := SignStatement(s, rejectingSigner{pub: uk.Public()}); err == nil || err.Error() != "sign rejected" {
		t.Fatalf("unexpected rejecting signer result: %v", err)
	}
}
func rekorBodyForTest(t *testing.T, d SignedDecision, c *x509.Certificate) []byte {
	t.Helper()
	b, _ := d.CanonicalBytes()
	h := sha256.Sum256(b)
	pub, _ := x509.MarshalPKIXPublicKey(c.PublicKey)
	v, _ := json.Marshal(map[string]any{"apiVersion": "0.0.2", "kind": "hashedrekord", "spec": map[string]any{"hashedRekordV002": map[string]any{"data": map[string]any{"algorithm": "SHA2_256", "digest": base64.StdEncoding.EncodeToString(h[:])}, "signature": map[string]any{"content": d.Signature, "verifier": map[string]any{"keyDetails": "PKIX_ECDSA_P256_SHA_256", "publicKey": map[string]string{"rawBytes": base64.StdEncoding.EncodeToString(pub)}}}}}})
	return v
}
func nodeHash(a, b []byte) []byte {
	x := sha256.Sum256(append(append([]byte{1}, a...), b...))
	return x[:]
}
func hashStrings(path [][]byte) []string {
	out := make([]string, len(path))
	for i, h := range path {
		out[i] = base64.StdEncoding.EncodeToString(h)
	}
	return out
}
func verifierPublic(vk string) ed25519.PublicKey {
	_, rest, _ := strings.Cut(vk, "+")
	_, key64, _ := strings.Cut(rest, "+")
	b, _ := base64.StdEncoding.DecodeString(key64)
	return ed25519.PublicKey(b[1:])
}

type rejectingSigner struct{ pub crypto.PublicKey }

func (s rejectingSigner) Public() crypto.PublicKey { return s.pub }
func (s rejectingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("sign rejected")
}
