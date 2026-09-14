// Package audit contains the stable, source-neutral Audit Event contract.
package audit

import (
	"context"
	"encoding/json"
	"time"
)

const EventSchemaVersion = 1

// Action codes identify semantic actions independently of HTTP routes. Keep
// these values stable: they are part of the Audit Log contract consumed by
// operators and downstream evidence tooling.
const (
	ActionRequestRead     = "request.read"
	ActionAuditRead       = "audit.read"
	ActionEvidenceRead    = "evidence.read"
	ActionDecisionPrepare = "decision.prepare"
	ActionDecisionAdd     = "decision.add"
)

type ActorType string

const (
	ActorUser      ActorType = "user"
	ActorWebhook   ActorType = "webhook"
	ActorSystem    ActorType = "system"
	ActorService   ActorType = "service"
	ActorAnonymous ActorType = "anonymous"
)

type Outcome string

const (
	OutcomeStarted         Outcome = "started"
	OutcomeSuccess         Outcome = "success"
	OutcomeUnauthenticated Outcome = "unauthenticated"
	OutcomeDenied          Outcome = "denied"
	OutcomeInvalid         Outcome = "invalid"
	OutcomeFailed          Outcome = "failed"
)

// Event is the immutable envelope persisted by Warden. OperationID identifies
// the semantic operation; RequestID identifies the HTTP/request correlation.
// ResourceID is deliberately text so an event remains useful after a mutable
// domain row is removed and so system events need not invent a domain UUID.
type Event struct {
	ID            int64           `json:"id"`
	OccurredAt    time.Time       `json:"occurred_at"`
	SchemaVersion int             `json:"schema_version"`
	OperationID   string          `json:"operation_id"`
	RequestID     string          `json:"request_id"`
	ActorID       string          `json:"actor_id"`
	ActorName     string          `json:"actor_name"`
	ActorType     ActorType       `json:"actor_type"`
	ActorRoles    []string        `json:"actor_roles"`
	ActionCode    string          `json:"action_code"`
	Outcome       Outcome         `json:"outcome"`
	AuthMethod    string          `json:"auth_method"`
	Permission    string          `json:"permission"`
	PolicyVersion string          `json:"policy_version"`
	Reason        string          `json:"reason"`
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id"`
	IPAddress     string          `json:"ip_address"`
	UserAgent     string          `json:"user_agent"`
	Route         string          `json:"route"`
	Metadata      json.RawMessage `json:"metadata"`
}

type Query struct {
	Cursor       string
	Limit        int
	Action       string
	Outcome      Outcome
	ActorID      string
	ResourceType string
	ResourceID   string
	OperationID  string
	From         *time.Time
	To           *time.Time
}

type Page struct {
	Items      []Event `json:"items"`
	NextCursor string  `json:"nextCursor,omitempty"`
}

type Repository interface {
	AppendAuditEvent(ctx context.Context, event Event) error
	ListAuditEvents(ctx context.Context, query Query) (Page, error)
}
