package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/wardenv/service/internal/audit"
	"github.com/wardenv/service/internal/authz"
	"github.com/wardenv/service/internal/source"
	"github.com/wardenv/service/internal/store"
	"github.com/wardenv/service/pkg/evidence"
)

const workerSubject = "warden-worker"

var workerPrincipal = authz.Principal{Subject: workerSubject, Roles: []authz.Role{authz.RoleWorker}}

type workerOperation struct {
	operationID, logicalOperationID, jobID, phase string
	attempt                                       int
}

func newWorkerOperation(j store.Job, requestID, phase string) workerOperation {
	attempt := j.Attempts
	if attempt < 1 {
		attempt = 1
	}
	logical := uuid.NewSHA1(uuid.Nil, []byte("warden-worker:"+requestID+":"+phase)).String()
	return workerOperation{
		operationID:        logical,
		logicalOperationID: logical,
		jobID:              j.ID,
		phase:              phase,
		attempt:            attempt,
	}
}

func (o workerOperation) metadata() json.RawMessage {
	b, _ := json.Marshal(map[string]any{
		"job_id": o.jobID, "attempt": o.attempt, "phase": o.phase,
		"logical_operation_id": o.logicalOperationID,
	})
	return b
}

func (a *App) workerRequest(ctx context.Context, id string) (store.Request, error) {
	if a.workerGetRequest != nil {
		return a.workerGetRequest(ctx, id)
	}
	if a.Store == nil {
		return store.Request{}, errors.New("worker store unavailable")
	}
	return a.Store.GetRequest(ctx, id)
}

func (a *App) workerSavePublishedAndMark(ctx context.Context, id string, bundle []byte, event audit.Event) error {
	if a.workerSavePublishedAndMarkFn != nil {
		return a.workerSavePublishedAndMarkFn(ctx, id, bundle, event)
	}
	if a.Store == nil {
		return errors.New("worker store unavailable")
	}
	return a.Store.SavePublishedAndMarkWithAudit(ctx, id, bundle, event)
}

func (a *App) workerSetStatuses(ctx context.Context, id, logStatus, deliveryStatus string, event audit.Event) error {
	if a.workerSetStatusesFn != nil {
		return a.workerSetStatusesFn(ctx, id, logStatus, deliveryStatus, event)
	}
	if a.Store == nil {
		return errors.New("worker store unavailable")
	}
	return a.Store.SetStatusesWithAudit(ctx, id, logStatus, deliveryStatus, event)
}

func (a *App) workerAuditEvent(op workerOperation, requestID, action string, outcome audit.Outcome, permission authz.Permission, decision authz.Decision, reason string) audit.Event {
	correlation := requestID
	if _, err := uuid.Parse(correlation); err != nil {
		correlation = uuid.NewString()
	}
	return audit.Event{
		OperationID: op.operationID, RequestID: correlation,
		ActorID: workerPrincipal.Subject, ActorName: "Warden worker", ActorType: audit.ActorService,
		ActorRoles: []string{string(authz.RoleWorker)}, ActionCode: action, Outcome: outcome,
		AuthMethod: "internal", Permission: string(permission), PolicyVersion: decision.PolicyVersion,
		Reason: reason, ResourceType: "deployment_request", ResourceID: requestID, Metadata: op.metadata(),
	}
}

func (a *App) appendWorkerAudit(ctx context.Context, event audit.Event) error {
	repository := a.auditRepository()
	if repository == nil {
		err := errors.New("audit repository unavailable")
		a.logAuditFailure(event, err)
		return err
	}
	if err := repository.AppendAuditEvent(ctx, event); err != nil {
		a.logAuditFailure(event, err)
		return err
	}
	return nil
}

// authorizeWorker records default-deny decisions and prevents any external
// call when the decision or its required Audit Event cannot be persisted.
func (a *App) authorizeWorker(ctx context.Context, requestID string, op workerOperation, action string, permission authz.Permission) (authz.Decision, error) {
	decision := authz.Policy{}.Authorize(authz.Request{Principal: workerPrincipal, Permission: permission, Resource: authz.Resource{RequestID: requestID}})
	if a.Policy != nil {
		decision = a.Policy.Authorize(authz.Request{Principal: workerPrincipal, Permission: permission, Resource: authz.Resource{RequestID: requestID}})
	}
	if decision.Allowed {
		return decision, nil
	}
	event := a.workerAuditEvent(op, requestID, action, audit.OutcomeDenied, permission, decision, decision.Reason)
	if err := a.appendWorkerAudit(ctx, event); err != nil {
		return decision, fmt.Errorf("worker authorization audit: %w", err)
	}
	return decision, fmt.Errorf("worker authorization denied: %s", decision.Reason)
}

func workerAuditAppendFailure(err error) bool {
	var marker interface{ AuditAppendFailure() bool }
	return errors.As(err, &marker) && marker.AuditAppendFailure()
}

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
	if a.Store == nil {
		return
	}
	j, err := a.Store.ClaimJob(ctx)
	if err != nil {
		return
	}
	if err = a.publish(ctx, j); err != nil {
		_ = a.Store.FinishJob(ctx, j.ID, false, err.Error())
		return
	}
	_ = a.Store.FinishJob(ctx, j.ID, true, "")
}

func (a *App) publish(ctx context.Context, j store.Job) error {
	req, err := a.workerRequest(ctx, j.RequestID)
	if err != nil {
		return err
	}
	if req.LogStatus == "published" {
		return a.deliverJob(ctx, j, req)
	}
	op := newWorkerOperation(j, req.ID, audit.ActionTransparencyPublish)
	transparency, err := a.authorizeWorker(ctx, req.ID, op, audit.ActionTransparencyPublish, authz.TransparencyPublish)
	if err != nil {
		return err
	}
	if _, err = a.authorizeWorker(ctx, req.ID, op, audit.ActionEvidenceUpdate, authz.EvidenceUpdate); err != nil {
		return err
	}
	if _, err = a.authorizeWorker(ctx, req.ID, op, audit.ActionRequestUpdate, authz.RequestUpdate); err != nil {
		return err
	}
	var bundle evidence.Bundle
	if err := json.Unmarshal(j.Payload, &bundle); err != nil {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "evidence_bundle_invalid", err)
	}
	if bundle.Signed.Statement.RequestID == "" {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "statement_missing", errors.New("evidence bundle statement is required"))
	}
	if bundle.Signed.Statement.RequestID != req.ID {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "statement_request_mismatch", errors.New("evidence statement request does not match job request"))
	}
	if bundle.Version != "" && bundle.Version != evidence.StatementVersion {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "bundle_version_invalid", fmt.Errorf("unsupported bundle version %q", bundle.Version))
	}
	if len(bundle.CertificateChain) == 0 {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "certificate_chain_missing", errors.New("evidence certificate chain is required"))
	}
	certs, err := parseCerts(bundle.CertificateChain)
	if err != nil {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "certificate_invalid", err)
	}
	trust, err := evidenceTrust(a.Config.EvidenceTrustPEM)
	if err != nil {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "evidence_trust_invalid", err)
	}
	keyRaw, err := checkpointKey(a.Config.RekorCheckpointKey)
	if err != nil {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "rekor_checkpoint_key_invalid", err)
	}
	pub, ok := certs[0].PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "certificate_key_invalid", errors.New("evidence leaf is not ECDSA"))
	}
	if err = bundle.Signed.VerifySignature(pub); err != nil {
		return a.workerInvalidPublication(ctx, op, req.ID, transparency, "decision_signature_invalid", err)
	}

	started := a.workerAuditEvent(op, req.ID, audit.ActionTransparencyPublish, audit.OutcomeStarted, authz.TransparencyPublish, transparency, "external_invocation_started")
	if err = a.appendWorkerAudit(ctx, started); err != nil {
		return fmt.Errorf("publication started audit: %w", err)
	}
	var proof *evidence.RekorProof
	if a.workerRekorSubmit != nil {
		proof, err = a.workerRekorSubmit(ctx, bundle.Signed, certs[0])
	} else {
		rekor := evidence.RekorClient{BaseURL: a.Config.RekorURL, CheckpointPublicKey: keyRaw, CheckpointOrigin: a.Config.RekorCheckpointOrigin}
		proof, err = rekor.Submit(ctx, bundle.Signed, certs[0])
	}
	if err != nil {
		return a.workerExternalFailure(ctx, op, req.ID, audit.ActionTransparencyPublish, authz.TransparencyPublish, transparency, "rekor_submit_failed", err)
	}
	bundle.Rekor = proof
	if a.workerVerifyPublicationFn != nil {
		err = a.workerVerifyPublicationFn(bundle, trust, ed25519.PublicKey(keyRaw), a.Config.RekorCheckpointOrigin)
	} else {
		err = bundle.VerifyWithOrigin(trust, bundle.Signed.Statement.Subject, ed25519.PublicKey(keyRaw), a.Config.RekorCheckpointOrigin)
	}
	if err != nil {
		return a.workerExternalFailure(ctx, op, req.ID, audit.ActionTransparencyPublish, authz.TransparencyPublish, transparency, "rekor_verification_failed", err)
	}
	published, err := json.Marshal(bundle)
	if err != nil {
		return a.workerExternalFailure(ctx, op, req.ID, audit.ActionTransparencyPublish, authz.TransparencyPublish, transparency, "evidence_bundle_encode_failed", err)
	}
	terminal := a.workerAuditEvent(op, req.ID, audit.ActionTransparencyPublish, audit.OutcomeSuccess, authz.TransparencyPublish, transparency, "published")
	if err = a.workerSavePublishedAndMark(ctx, j.RequestID, published, terminal); err != nil {
		if workerAuditAppendFailure(err) {
			a.logAuditFailure(terminal, err)
			return err
		}
		return a.workerExternalFailure(ctx, op, req.ID, audit.ActionTransparencyPublish, authz.TransparencyPublish, transparency, "publication_commit_failed", err)
	}
	return a.deliverJob(ctx, j, req)
}

func (a *App) workerExternalFailure(ctx context.Context, op workerOperation, requestID, action string, permission authz.Permission, decision authz.Decision, reason string, cause error) error {
	event := a.workerAuditEvent(op, requestID, action, audit.OutcomeFailed, permission, decision, reason)
	if err := a.appendWorkerAudit(ctx, event); err != nil {
		return fmt.Errorf("%s: %v; failure audit: %w", reason, cause, err)
	}
	return fmt.Errorf("%s: %w", reason, cause)
}

// workerInvalidPublication records validation failures before an external
// Rekor invocation. There is intentionally no started event in this case:
// the external action was never attempted.
func (a *App) workerInvalidPublication(ctx context.Context, op workerOperation, requestID string, decision authz.Decision, reason string, cause error) error {
	event := a.workerAuditEvent(op, requestID, audit.ActionTransparencyPublish, audit.OutcomeInvalid, authz.TransparencyPublish, decision, reason)
	if err := a.appendWorkerAudit(ctx, event); err != nil {
		return fmt.Errorf("%s: %v; invalid audit: %w", reason, cause, err)
	}
	return fmt.Errorf("%s: %w", reason, cause)
}

func (a *App) evidenceURL(requestID string) string {
	return strings.TrimRight(a.Config.PublicURL, "/") + "/evidence/" + url.PathEscape(requestID)
}

func (a *App) decisionComment(requestID string) string {
	return "Warden decision recorded. Evidence: " + a.evidenceURL(requestID)
}

// deliver preserves the original narrow worker seam for callers that already
// have a request. The job-aware implementation is used by the claim loop so
// retry attempt metadata remains accurate.
func (a *App) deliver(ctx context.Context, req store.Request) error {
	return a.deliverJob(ctx, store.Job{ID: "", RequestID: req.ID, Attempts: 1}, req)
}

func (a *App) deliverJob(ctx context.Context, j store.Job, req store.Request) error {
	if time.Now().After(req.ExpiresAt) {
		op := newWorkerOperation(j, req.ID, audit.ActionRequestUpdate)
		decision, err := a.authorizeWorker(ctx, req.ID, op, audit.ActionRequestUpdate, authz.RequestUpdate)
		if err != nil {
			return err
		}
		terminal := a.workerAuditEvent(op, req.ID, audit.ActionRequestUpdate, audit.OutcomeSuccess, authz.RequestUpdate, decision, "expired")
		if err = a.workerSetStatuses(ctx, req.ID, "", "expired", terminal); err != nil {
			if workerAuditAppendFailure(err) {
				a.logAuditFailure(terminal, err)
				return err
			}
			return a.workerExternalFailure(ctx, op, req.ID, audit.ActionRequestUpdate, authz.RequestUpdate, decision, "expiry_commit_failed", err)
		}
		return nil
	}
	event := source.Event{ID: req.ID, Repository: req.Repository, Environment: req.Environment, CommitSHA: req.CommitSHA, Requester: req.Requester, RequesterSubject: req.RequesterSubject, Context: req.Context}
	recheckDecision, deliverDecision, err := a.authorizeDelivery(ctx, req.ID, j)
	if err != nil {
		return err
	}
	eligible, err := a.recheckSource(ctx, j, req, event, recheckDecision)
	if err != nil {
		return err
	}
	if !eligible {
		return nil
	}
	return a.deliverSource(ctx, j, req, event, deliverDecision)
}

func (a *App) authorizeDelivery(ctx context.Context, requestID string, j store.Job) (authz.Decision, authz.Decision, error) {
	op := newWorkerOperation(j, requestID, audit.ActionSourceRecheck)
	recheckDecision, err := a.authorizeWorker(ctx, requestID, op, audit.ActionSourceRecheck, authz.SourceDeliver)
	if err != nil {
		return authz.Decision{}, authz.Decision{}, err
	}
	deliverOp := newWorkerOperation(j, requestID, audit.ActionSourceDeliver)
	deliverDecision, err := a.authorizeWorker(ctx, requestID, deliverOp, audit.ActionSourceDeliver, authz.SourceDeliver)
	if err != nil {
		return authz.Decision{}, authz.Decision{}, err
	}
	if _, err = a.authorizeWorker(ctx, requestID, op, audit.ActionRequestUpdate, authz.RequestUpdate); err != nil {
		return authz.Decision{}, authz.Decision{}, err
	}
	return recheckDecision, deliverDecision, nil
}

func (a *App) recheckSource(ctx context.Context, j store.Job, req store.Request, event source.Event, decision authz.Decision) (bool, error) {
	op := newWorkerOperation(j, req.ID, audit.ActionSourceRecheck)
	started := a.workerAuditEvent(op, req.ID, audit.ActionSourceRecheck, audit.OutcomeStarted, authz.SourceDeliver, decision, "external_invocation_started")
	if err := a.appendWorkerAudit(ctx, started); err != nil {
		return false, fmt.Errorf("source recheck started audit: %w", err)
	}
	if a.Source == nil {
		return false, a.workerExternalFailure(ctx, op, req.ID, audit.ActionSourceRecheck, authz.SourceDeliver, decision, "source_recheck_failed", errors.New("source adapter unavailable"))
	}
	ok, err := a.Source.Recheck(ctx, event)
	if err != nil {
		return false, a.workerExternalFailure(ctx, op, req.ID, audit.ActionSourceRecheck, authz.SourceDeliver, decision, "source_recheck_failed", err)
	}
	reason, status := "eligible", ""
	if !ok {
		reason, status = "not_eligible", "cancelled"
	}
	terminal := a.workerAuditEvent(op, req.ID, audit.ActionSourceRecheck, audit.OutcomeSuccess, authz.SourceDeliver, decision, reason)
	if status != "" {
		if err = a.workerSetStatuses(ctx, req.ID, "", status, terminal); err != nil {
			if workerAuditAppendFailure(err) {
				a.logAuditFailure(terminal, err)
				return false, err
			}
			return false, a.workerExternalFailure(ctx, op, req.ID, audit.ActionSourceRecheck, authz.SourceDeliver, decision, "cancel_commit_failed", err)
		}
		return false, nil
	}
	if err := a.appendWorkerAudit(ctx, terminal); err != nil {
		return false, err
	}
	return true, nil
}

func (a *App) deliverSource(ctx context.Context, j store.Job, req store.Request, event source.Event, decision authz.Decision) error {
	op := newWorkerOperation(j, req.ID, audit.ActionSourceDeliver)
	started := a.workerAuditEvent(op, req.ID, audit.ActionSourceDeliver, audit.OutcomeStarted, authz.SourceDeliver, decision, "external_invocation_started")
	if err := a.appendWorkerAudit(ctx, started); err != nil {
		return fmt.Errorf("source delivery started audit: %w", err)
	}
	if a.Source == nil {
		return a.workerExternalFailure(ctx, op, req.ID, audit.ActionSourceDeliver, authz.SourceDeliver, decision, "source_delivery_failed", errors.New("source adapter unavailable"))
	}
	state := "rejected"
	if req.Decision == "approved" {
		state = "approved"
	}
	if err := a.Source.Deliver(ctx, event, state, a.decisionComment(req.ID)); err != nil {
		return a.workerExternalFailure(ctx, op, req.ID, audit.ActionSourceDeliver, authz.SourceDeliver, decision, "source_delivery_failed", err)
	}
	terminal := a.workerAuditEvent(op, req.ID, audit.ActionSourceDeliver, audit.OutcomeSuccess, authz.SourceDeliver, decision, "delivered")
	if err := a.workerSetStatuses(ctx, req.ID, "", "delivered", terminal); err != nil {
		if workerAuditAppendFailure(err) {
			a.logAuditFailure(terminal, err)
			return err
		}
		return a.workerExternalFailure(ctx, op, req.ID, audit.ActionSourceDeliver, authz.SourceDeliver, decision, "delivery_commit_failed", err)
	}
	return nil
}

func evidenceTrust(raw string) (*x509.CertPool, error) {
	if raw == "" {
		return nil, fmt.Errorf("EVIDENCE_TRUST_PEM is required")
	}
	trust := x509.NewCertPool()
	if !trust.AppendCertsFromPEM([]byte(raw)) {
		return nil, fmt.Errorf("invalid evidence trust PEM")
	}
	return trust, nil
}

func checkpointKey(raw string) ([]byte, error) {
	key, err := base64.RawStdEncoding.DecodeString(raw)
	if err != nil || len(key) != ed25519.PublicKeySize {
		key, err = base64.StdEncoding.DecodeString(raw)
	}
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Rekor checkpoint key")
	}
	return key, nil
}

func parseCerts(chain []string) ([]*x509.Certificate, error) {
	out := make([]*x509.Certificate, 0, len(chain))
	for _, raw := range chain {
		block, _ := pem.Decode([]byte(raw))
		if block == nil {
			return nil, fmt.Errorf("invalid certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, cert)
	}
	return out, nil
}
