package mcpaccess

import (
	"errors"
	"strings"
	"testing"
)

func TestLintTable(t *testing.T) {
	base := goldenSpec()
	mk := func(mut func(s *Spec)) Spec {
		s := base
		s.Grants = append([]Grant(nil), base.Grants...)
		s.Registry.VServers = append([]VServer(nil), base.Registry.VServers...)
		mut(&s)
		return s
	}
	cases := []struct {
		name     string
		spec     Spec
		wantCode string
		wantErr  bool
	}{
		{"golden is clean", base, "", false},
		{"judge effect -> feature_unavailable", mk(func(s *Spec) { s.Grants[0].Effect = EffectJudge }), CodeFeatureUnavailable, true},
		{"taint condition -> feature_unavailable", mk(func(s *Spec) { s.Grants[0].Conditions.Taint = true }), CodeFeatureUnavailable, true},
		{"requires_mfa -> feature_unavailable", mk(func(s *Spec) { s.Grants[0].Conditions.RequiresMFA = true }), CodeFeatureUnavailable, true},
		{"unknown action", mk(func(s *Spec) { s.Grants[0].Action = "tasks/create" }), CodeUnknownAction, true},
		{"wildcard action", mk(func(s *Spec) { s.Grants[0].Action = "*" }), CodeWildcardAction, true},
		{"empty action", mk(func(s *Spec) { s.Grants[0].Action = "" }), CodeWildcardAction, true},
		{"unknown effect", mk(func(s *Spec) { s.Grants[0].Effect = "maybe" }), CodeUnknownEffect, true},
		{"role subject kind unsupported (no minted claim)", mk(func(s *Spec) { s.Grants[0].Subject = Subject{Kind: "role", Value: "x"} }), CodeUnsupportedSubjectKind, true},
		{"app subject kind unsupported (no minted claim)", mk(func(s *Spec) { s.Grants[0].Subject = Subject{Kind: "app", Value: "x"} }), CodeUnsupportedSubjectKind, true},
		{"project value is not a project hash (P11(e))", mk(func(s *Spec) { s.Grants[0].Subject = Subject{Kind: SubjectProject, Value: "billing-service"} }), CodeInvalidSubjectValue, true},
		{"project value upper-case hex refused", mk(func(s *Spec) { s.Grants[0].Subject = Subject{Kind: SubjectProject, Value: "ABCDEF0123456789"} }), CodeInvalidSubjectValue, true},
		{"team value over the roster entry bound", mk(func(s *Spec) { s.Grants[0].Subject = Subject{Kind: SubjectTeam, Value: strings.Repeat("t", 129)} }), CodeInvalidSubjectValue, true},
		{"vserver declares a malformed project scope", mk(func(s *Spec) { s.Registry.VServers[0].Projects = []string{"not-a-hash"} }), CodeInvalidRegistry, true},
		{"subject value required", mk(func(s *Spec) { s.Grants[0].Subject = Subject{Kind: SubjectUser} }), CodeSubjectValueRequired, true},
		{"unknown vserver", mk(func(s *Spec) { s.Grants[0].Resource.VServer = "vs-nope" }), CodeUnknownVServer, true},
		{"unknown server", mk(func(s *Spec) { s.Grants[0].Resource.Server = "nope" }), CodeUnknownServer, true},
		{"unknown rank", mk(func(s *Spec) { s.Grants[0].Conditions.RequiresCredAssurance = "titanium" }), CodeUnknownRank, true},
		{"condition on deny", mk(func(s *Spec) { s.Grants[1].Conditions.RequiresClientAttestation = "ipc_bound" }), CodeConditionOnDeny, true},
		{"unknown audit class", mk(func(s *Spec) { s.Grants[0].AuditClass = "loud" }), CodeUnknownAuditClass, true},
		{"duplicate id", mk(func(s *Spec) { s.Grants[1].ID = "g1" }), CodeDuplicateGrant, true},
		{"passthrough on a dpop vserver (R14.11)", mk(func(s *Spec) {
			s.Registry.VServers[0].SenderConstraint = "dpop"
			s.Registry.VServers[0].Servers = []Server{{ID: "gh", Target: "gh", CredentialMode: "passthrough"}}
		}), CodePassthroughOnNonBearer, true},
		{"passthrough on a bearer vserver is fine", mk(func(s *Spec) {
			s.Registry.VServers[0].Servers = []Server{{ID: "gh", Target: "gh", CredentialMode: "passthrough"}}
		}), "", false},
		{"missing issuer", mk(func(s *Spec) { s.Registry.Issuer = "" }), CodeInvalidRegistry, true},
		{"unknown sender constraint", mk(func(s *Spec) { s.Registry.VServers[0].SenderConstraint = "carrier-pigeon" }), CodeInvalidRegistry, true},
		{"empty grant set -> WARN deny-all", mk(func(s *Spec) { s.Grants = nil }), CodeEmptyGrantSet, false},
		{"all disabled -> WARN deny-all", mk(func(s *Spec) { s.Grants[0].Enabled, s.Grants[1].Enabled = false, false }), CodeEmptyGrantSet, false},
		{"deny-only -> WARN", mk(func(s *Spec) { s.Grants = s.Grants[1:] }), CodeDenyOnlySet, false},
		{"expired grant -> WARN", mk(func(s *Spec) { s.Grants[0].Conditions.ExpiresAt = 1000 }), CodeExpiredGrant, false},
		{"tasks/get grant -> feature_unavailable (no CEL method discriminator)", mk(func(s *Spec) { s.Grants[0].Action, s.Grants[0].Resource.Name = ActionTasksGet, "task-1" }), CodeFeatureUnavailable, true},
		{"tasks/update grant -> feature_unavailable", mk(func(s *Spec) { s.Grants[0].Action, s.Grants[0].Resource.Name = ActionTasksUpdate, "task-1" }), CodeFeatureUnavailable, true},
		{"tasks/cancel grant -> feature_unavailable", mk(func(s *Spec) { s.Grants[0].Action, s.Grants[0].Resource.Name = ActionTasksCancel, "task-1" }), CodeFeatureUnavailable, true},
		{"approved snapshot without id", mk(func(s *Spec) {
			s.Registry.VServers[0].Servers = []Server{{ID: "gh", Target: "gh", Snapshot: &ApprovedSnapshot{Tools: []string{"create_issue"}}}}
		}), CodeInvalidRegistry, true},
		{"named grant outside the approved snapshot -> WARN", mk(func(s *Spec) {
			s.Registry.VServers[0].Servers = []Server{{ID: "gh", Target: "gh", Snapshot: &ApprovedSnapshot{ID: "snap-1", Tools: []string{"delete_repo"}}}}
		}), CodeUnapprovedToolName, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ps := Lint(c.spec, 2000)
			if c.wantCode != "" && !Has(ps, c.wantCode) {
				t.Fatalf("problems %v lack %s", ps, c.wantCode)
			}
			if c.wantCode == "" && len(ps) != 0 {
				t.Fatalf("unexpected problems %v", ps)
			}
			if HasErrors(ps) != c.wantErr {
				t.Fatalf("HasErrors=%v want %v: %v", HasErrors(ps), c.wantErr, ps)
			}
			_, err := Normalize(c.spec, 2000)
			var le *LintError
			if errors.As(err, &le) != c.wantErr {
				t.Fatalf("Normalize err = %v, want lint error %v", err, c.wantErr)
			}
			if c.wantErr {
				assertAllCompilersRefuse(t, c.spec, c.wantCode)
			}
		})
	}
}

// TestNormalizeOrderAndDefaults pins the canonical order (hierarchy, ord,
// id) and the defaults an authored row may omit.
func TestNormalizeOrderAndDefaults(t *testing.T) {
	s := goldenSpec()
	s.Grants = []Grant{
		{ID: "c", Ord: 1, HierarchyLevel: 2, Subject: Subject{}, Resource: Resource{VServer: "vs-gh", Name: "*"}, Action: ActionList, Effect: EffectAllow, Enabled: true},
		{ID: "b", Ord: 2, HierarchyLevel: 0, Subject: Subject{Kind: SubjectAny}, Resource: Resource{VServer: "vs-gh"}, Action: ActionCall, Effect: EffectAllow, Enabled: true},
		{ID: "a", Ord: 1, HierarchyLevel: 0, Subject: Subject{Kind: SubjectAny}, Resource: Resource{VServer: "vs-gh"}, Action: ActionCall, Effect: EffectDeny, Enabled: true},
		{ID: "gone", Ord: 0, Subject: Subject{Kind: SubjectAny}, Resource: Resource{VServer: "vs-gh"}, Action: ActionCall, Effect: EffectAllow, Enabled: false},
	}
	n, err := Normalize(s, 0)
	if err != nil {
		t.Fatal(err)
	}
	ids := ""
	for _, g := range n.Grants {
		ids += g.ID + ","
	}
	if ids != "a,b,c," {
		t.Fatalf("order = %s", ids)
	}
	if n.Grants[2].Subject.Kind != SubjectAny || n.Grants[2].Resource.Name != "" || n.Grants[2].AuditClass != "normal" {
		t.Fatalf("defaults not applied: %+v", n.Grants[2])
	}
	if !Has(n.Problems, CodeDisabledGrant) {
		t.Fatalf("disabled grant not reported: %v", n.Problems)
	}
	if AcceptedAtLeast(ClientAttestationRanks, "ipc_bound")[1] != "ipc_bound" || len(AcceptedAtLeast(CredAssuranceRanks, "claimed")) != 6 {
		t.Fatal("rank expansion")
	}
}
