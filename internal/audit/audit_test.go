package audit

import "testing"

func TestCLIAuditActionCodesMatchSemanticPermissions(t *testing.T) {
	cases := []struct {
		name   string
		action string
		want   string
	}{
		{name: "request read", action: ActionRequestRead, want: "request.read"},
		{name: "evidence read", action: ActionEvidenceRead, want: "evidence.read"},
		{name: "decision preparation", action: ActionDecisionPrepare, want: "decision.prepare"},
		{name: "decision add", action: ActionDecisionAdd, want: "decision.add"},
	}
	seen := make(map[string]string, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.action != tc.want {
				t.Fatalf("action code = %q, want %q", tc.action, tc.want)
			}
			if previous, ok := seen[tc.action]; ok {
				t.Fatalf("action code %q is shared with %s", tc.action, previous)
			}
			seen[tc.action] = tc.name
		})
	}
}
