// Package authz contains Warden's pure, default-deny authorization policy.
package authz

import "strings"

const PolicyVersion = "warden-policy-v1"

type Role string

const (
	RoleReader   Role = "reader"
	RoleReviewer Role = "reviewer"
	RoleAuditor  Role = "auditor"
	RoleSource   Role = "source"
	RoleWorker   Role = "worker"
)

// Stable semantic permission codes. These values are also suitable for later
// audit evidence; callers should not derive them from IdP groups or URLs.
type Permission string

const (
	RequestRead         Permission = "request.read"
	DecisionRead        Permission = "decision.read"
	EvidenceRead        Permission = "evidence.read"
	DecisionPrepare     Permission = "decision.prepare"
	DecisionAdd         Permission = "decision.add"
	AuditRead           Permission = "audit.read"
	RequestAdd          Permission = "request.add"
	RequestUpdate       Permission = "request.update"
	EvidenceUpdate      Permission = "evidence.update"
	TransparencyPublish Permission = "transparency.publish"
	SourceDeliver       Permission = "source.deliver"
)

// Action is retained as an alias for callers of the initial policy draft.
type Action = Permission

const (
	ReadRequests       = RequestRead
	ReadDecisions      = DecisionRead
	ReadEvidence       = EvidenceRead
	PrepareDecision    = DecisionPrepare
	SubmitDecision     = DecisionAdd
	ReadAuditLog       = AuditRead
	ReceiveSourceEvent = RequestAdd
	DeliverSourceEvent = SourceDeliver
	PublishEvidence    = TransparencyPublish
)

type Principal struct {
	Subject string
	Roles   []Role
}

type Resource struct {
	RequestID        string
	RequesterSubject string
}

// Request is the decision input crossing the authorization seam.
type Request struct {
	Principal  Principal
	Permission Permission
	Resource   Resource
}

// Decision is policy evidence, not merely a boolean. Stable reason and policy
// version fields let audit recording be added later without exposing rules.
type Decision struct {
	Allowed       bool
	Permission    Permission
	Reason        string
	PolicyVersion string
}

const (
	ReasonAllowed           = "allowed"
	ReasonRoleMissing       = "role_missing"
	ReasonSelfApproval      = "self_approval_denied"
	ReasonResourceContext   = "resource_context_required"
	ReasonUnknownPermission = "unknown_permission"
)

type Authorizer interface {
	Authorize(Request) Decision
}

type Policy struct{}

func (Policy) Authorize(request Request) Decision {
	return authorize(request)
}

// HasRole is a coarse route gate only. It must not replace Authorize for
// resource actions because it has no resource facts and cannot enforce the
// self-approval rule.
func HasRole(p Principal, role Role) bool {
	for _, candidate := range NormalizeRoles(roleStrings(p.Roles)) {
		if candidate == role {
			return true
		}
	}
	return false
}

// Allows is a compatibility convenience for simple callers; handlers use the
// decision-oriented Authorizer interface so the policy evidence is retained.
func Allows(p Principal, permission Permission, resource Resource) bool {
	return Policy{}.Authorize(Request{Principal: p, Permission: permission, Resource: resource}).Allowed
}

func NormalizeRoles(raw []string) []Role {
	seen := make(map[Role]struct{}, len(raw))
	for _, value := range raw {
		role := Role(strings.ToLower(strings.TrimSpace(value)))
		switch role {
		case RoleReader, RoleReviewer, RoleAuditor, RoleSource, RoleWorker:
			seen[role] = struct{}{}
		}
	}
	ordered := []Role{RoleReader, RoleReviewer, RoleAuditor, RoleSource, RoleWorker}
	out := make([]Role, 0, len(seen))
	for _, role := range ordered {
		if _, ok := seen[role]; ok {
			out = append(out, role)
		}
	}
	return out
}

func hasRole(p Principal, role Role) bool {
	for _, candidate := range NormalizeRoles(roleStrings(p.Roles)) {
		if candidate == role {
			return true
		}
	}
	return false
}

func authorize(request Request) Decision {
	decision := Decision{Permission: request.Permission, PolicyVersion: PolicyVersion}
	grant := func() Decision {
		decision.Allowed = true
		decision.Reason = ReasonAllowed
		return decision
	}
	deny := func(reason string) Decision {
		decision.Reason = reason
		return decision
	}
	switch request.Permission {
	case RequestRead, DecisionRead, EvidenceRead:
		if hasRole(request.Principal, RoleReader) || hasRole(request.Principal, RoleReviewer) {
			return grant()
		}
		return deny(ReasonRoleMissing)
	case DecisionPrepare, DecisionAdd:
		if !hasRole(request.Principal, RoleReviewer) {
			return deny(ReasonRoleMissing)
		}
		if request.Resource.RequesterSubject == "" {
			return deny(ReasonResourceContext)
		}
		if request.Principal.Subject == "" {
			return deny(ReasonResourceContext)
		}
		if request.Principal.Subject == request.Resource.RequesterSubject {
			return deny(ReasonSelfApproval)
		}
		return grant()
	case AuditRead:
		if hasRole(request.Principal, RoleAuditor) {
			return grant()
		}
		return deny(ReasonRoleMissing)
	case RequestAdd:
		if hasRole(request.Principal, RoleSource) {
			return grant()
		}
		return deny(ReasonRoleMissing)
	case RequestUpdate, EvidenceUpdate, TransparencyPublish:
		if hasRole(request.Principal, RoleWorker) {
			return grant()
		}
		return deny(ReasonRoleMissing)
	case SourceDeliver:
		if hasRole(request.Principal, RoleWorker) {
			return grant()
		}
		return deny(ReasonRoleMissing)
	default:
		return deny(ReasonUnknownPermission)
	}
}

func roleStrings(roles []Role) []string {
	result := make([]string, len(roles))
	for i, role := range roles {
		result[i] = string(role)
	}
	return result
}
