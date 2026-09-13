package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/internal/store"
	"github.com/wardenv/service/pkg/evidence"
	"net/url"
	"strings"
	"time"
)

// startWorker is deliberately single threaded: claiming uses SKIP LOCKED so a
// second process can be added later without publishing an item twice.
func (a *App) startWorker(ctx context.Context) {
	if a.Config.RekorURL == "" {
		return
	}
	go func() {
		tick := time.NewTicker(2 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				a.processOne(ctx)
			}
		}
	}()
}
func (a *App) processOne(ctx context.Context) {
	j, e := a.Store.ClaimJob(ctx)
	if e != nil {
		return
	}
	if e = a.publish(ctx, j); e != nil {
		_ = a.Store.FinishJob(ctx, j.ID, false, e.Error())
		return
	}
	_ = a.Store.FinishJob(ctx, j.ID, true, "")
}
func (a *App) publish(ctx context.Context, j store.Job) error {
	req, e := a.Store.GetRequest(ctx, j.RequestID)
	if e != nil {
		return e
	}
	// Delivery retries reuse the durable publication marker and never submit
	// another Rekor entry.
	if req.LogStatus == "published" {
		return a.deliver(ctx, req)
	}
	var bundle evidence.Bundle

	if e := json.Unmarshal(j.Payload, &bundle); e != nil {
		return fmt.Errorf("evidence bundle: %w", e)
	}
	if bundle.Signed.Statement.RequestID == "" {
		return fmt.Errorf("evidence bundle statement is required")
	}
	if len(bundle.CertificateChain) == 0 {
		return fmt.Errorf("evidence certificate chain is required")
	}
	certs, e := parseCerts(bundle.CertificateChain)
	if e != nil {
		return e
	}
	var trust *x509.CertPool
	if a.Config.EvidenceTrustPEM != "" {
		trust = x509.NewCertPool()
		if !trust.AppendCertsFromPEM([]byte(a.Config.EvidenceTrustPEM)) {
			return fmt.Errorf("invalid evidence trust PEM")
		}
	} else {
		return fmt.Errorf("EVIDENCE_TRUST_PEM is required")
	}
	keyRaw, e := base64.RawStdEncoding.DecodeString(a.Config.RekorCheckpointKey)
	if e != nil || len(keyRaw) != ed25519.PublicKeySize {
		keyRaw, e = base64.StdEncoding.DecodeString(a.Config.RekorCheckpointKey)
	}
	if e != nil || len(keyRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Rekor checkpoint key")
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("evidence leaf is not ECDSA")
	}
	if e = bundle.Signed.VerifySignature(pub); e != nil {
		return e
	}
	rekor := evidence.RekorClient{BaseURL: a.Config.RekorURL, CheckpointPublicKey: keyRaw, CheckpointOrigin: a.Config.RekorCheckpointOrigin}
	proof, e := rekor.Submit(ctx, bundle.Signed, certs[0])
	if e != nil {
		return e
	}
	bundle.Rekor = proof
	if e = bundle.VerifyWithOrigin(trust, bundle.Signed.Statement.Subject, ed25519.PublicKey(keyRaw), a.Config.RekorCheckpointOrigin); e != nil {
		return fmt.Errorf("Rekor proof: %w", e)
	}
	published, e := json.Marshal(bundle)
	if e != nil {
		return e
	}
	if e = a.Store.SavePublishedAndMark(ctx, j.RequestID, published); e != nil {
		return e
	}
	return a.deliver(ctx, req)
}

func (a *App) evidenceURL(requestID string) string {
	return strings.TrimRight(a.Config.PublicURL, "/") + "/evidence/" + url.PathEscape(requestID)
}

func (a *App) decisionComment(requestID string) string {
	return "Warden decision recorded. Evidence: " + a.evidenceURL(requestID)
}

func (a *App) deliver(ctx context.Context, req store.Request) error {
	if time.Now().After(req.ExpiresAt) {
		return a.Store.SetStatuses(ctx, req.ID, "", "expired")
	}
	event := source.Event{ID: req.ID, Repository: req.Repository, Environment: req.Environment, CommitSHA: req.CommitSHA, Requester: req.Requester, Context: req.Context}
	if ok, e := a.Source.Recheck(ctx, event); e != nil {
		return e
	} else if !ok {
		return a.Store.SetStatuses(ctx, req.ID, "", "cancelled")
	}
	state := "rejected"
	if req.Decision == "approved" {
		state = "approved"
	}
	if e := a.Source.Deliver(ctx, event, state, a.decisionComment(req.ID)); e != nil {
		return e
	}
	return a.Store.SetStatuses(ctx, req.ID, "", "delivered")
}
func parseCerts(chain []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(chain))
	for _, raw := range chain {
		b, _ := pem.Decode([]byte(raw))
		if b == nil {
			return nil, fmt.Errorf("invalid certificate PEM")
		}
		c, e := x509.ParseCertificate(b.Bytes)
		if e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, nil
}
