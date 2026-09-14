package authz

import "testing"

func TestNormalizeRolesIsAdditiveAndIgnoresUnknownRoles(t *testing.T) {
	got := NormalizeRoles([]string{" reviewer ", "unknown", "reader", "reviewer", "AUDITOR"})
	want := []Role{RoleReader, RoleReviewer, RoleAuditor}
	if len(got) != len(want) {
		t.Fatalf("roles = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("roles = %#v, want %#v", got, want)
		}
	}
}

func TestPolicyCompleteRolePermissionMatrix(t *testing.T) {
	reader := Principal{Subject: "reader", Roles: []Role{RoleReader}}
	reviewer := Principal{Subject: "reviewer", Roles: []Role{RoleReviewer}}
	auditor := Principal{Subject: "auditor", Roles: []Role{RoleAuditor}}
	source := Principal{Subject: "source", Roles: []Role{RoleSource}}
	worker := Principal{Subject: "worker", Roles: []Role{RoleWorker}}
	request := Resource{RequestID: "request", RequesterSubject: "requester"}
	allPermissions := []Permission{RequestRead, DecisionRead, EvidenceRead, DecisionPrepare, DecisionAdd, AuditRead, RequestAdd, RequestUpdate, EvidenceUpdate, TransparencyPublish, SourceDeliver}
	cases := []struct {
		name  string
		p     Principal
		allow []Permission
	}{
		{"reader", reader, []Permission{RequestRead, DecisionRead, EvidenceRead}},
		{"reviewer inherits reader", reviewer, []Permission{RequestRead, DecisionRead, EvidenceRead, DecisionPrepare, DecisionAdd}},
		{"auditor", auditor, []Permission{AuditRead}},
		{"source", source, []Permission{RequestAdd}},
		{"worker", worker, []Permission{RequestUpdate, EvidenceUpdate, TransparencyPublish, SourceDeliver}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			allowed := map[Permission]bool{}
			for _, permission := range tc.allow {
				allowed[permission] = true
				decision := (Policy{}).Authorize(Request{Principal: tc.p, Permission: permission, Resource: request})
				if !decision.Allowed || decision.Permission != permission || decision.PolicyVersion != PolicyVersion || decision.Reason != ReasonAllowed {
					t.Fatalf("Authorize(%s) = %#v", permission, decision)
				}
			}
			for _, permission := range allPermissions {
				if allowed[permission] {
					continue
				}
				if decision := (Policy{}).Authorize(Request{Principal: tc.p, Permission: permission, Resource: request}); decision.Allowed {
					t.Fatalf("Authorize(%s) allowed for %s", permission, tc.name)
				}
			}
		})
	}
}

func TestPolicyDefaultDenyUnknownPermission(t *testing.T) {
	permission := Permission("future.permission")
	decision := (Policy{}).Authorize(Request{Principal: Principal{Subject: "admin", Roles: []Role{"admin"}}, Permission: permission})
	if decision.Allowed || decision.Reason != ReasonUnknownPermission || decision.Permission != permission || decision.PolicyVersion != PolicyVersion {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestPolicyDeniesSelfApprovalWithResourceContext(t *testing.T) {
	p := Principal{Subject: "requester", Roles: []Role{RoleReviewer}}
	for _, permission := range []Permission{DecisionPrepare, DecisionAdd} {
		decision := (Policy{}).Authorize(Request{Principal: p, Permission: permission, Resource: Resource{RequestID: "request", RequesterSubject: "requester"}})
		if decision.Allowed || decision.Reason != ReasonSelfApproval {
			t.Fatalf("decision = %#v", decision)
		}
	}
	if decision := (Policy{}).Authorize(Request{Principal: p, Permission: DecisionAdd}); decision.Allowed || decision.Reason != ReasonResourceContext {
		t.Fatalf("missing resource context was allowed: %#v", decision)
	}
}

func TestSourceCannotDeliver(t *testing.T) {
	decision := (Policy{}).Authorize(Request{Principal: Principal{Subject: "source", Roles: []Role{RoleSource}}, Permission: SourceDeliver})
	if decision.Allowed {
		t.Fatal("source principal was granted source.deliver")
	}
}
