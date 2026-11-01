package policy

import "testing"

// TestSecurityContractVocabularies is the compile-only check of the
// security pillar's type contract (security.go): every closed vocabulary
// is non-empty and has no duplicate spelling, and the Event carries the
// Security facts by pointer so an inactive module leaves it nil.
func TestSecurityContractVocabularies(t *testing.T) {
	t.Parallel()
	vocabs := map[string][]string{
		"category":    strs(FindingCategories()),
		"severity":    strs(FindingSeverities()),
		"confidence":  strs(FindingConfidences()),
		"scope":       strs(FindingScopes()),
		"baseline":    strs(FindingBaselines()),
		"status":      strs(FindingStatuses()),
		"attribution": strs(FindingAttributions()),
		"posture":     strs(SecurityPostures()),
		"git_write":   strs(GitWriteForms()),
	}
	for name, vs := range vocabs {
		if len(vs) == 0 {
			t.Errorf("%s: empty vocabulary", name)
		}
		seen := map[string]bool{}
		for _, v := range vs {
			if v == "" || seen[v] {
				t.Errorf("%s: empty or duplicate value %q", name, v)
			}
			seen[v] = true
		}
	}
	var ev Event
	if ev.Security != nil {
		t.Fatal("a zero Event must carry no Security facts")
	}
	ev.Security = &Security{Posture: SecurityPostureClean, Hits: []SecurityHit{{Category: FindingSecret}}}
	_ = []EventKind{KindAgentLaunch}
	_ = []Category{CategoryCodeSecurity}
	_ = []string{SourcePackSecurity, SecurityRuleIDPrefix, SinkGitCommit}
	_ = GitWrite{Form: GitWriteCommit}
}

func strs[T ~string](in []T) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = string(v)
	}
	return out
}

func TestSecurityMatchHelpers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ev   *Event
		want bool
	}{
		{nil, false},
		{&Event{Kind: KindShellExec}, true},
		{&Event{Kind: KindMCPCall}, true},
		{&Event{Kind: KindConfigChange}, true},
		{&Event{Kind: KindFileAccess, ActionType: "write_file"}, true},
		{&Event{Kind: KindFileAccess, ActionType: "edit_file"}, true},
		{&Event{Kind: KindFileAccess, ActionType: "read_file"}, false},
		{&Event{Kind: KindUserPrompt}, false},
	}
	for i, tc := range cases {
		if got := IsWriteCapable(tc.ev); got != tc.want {
			t.Errorf("case %d: IsWriteCapable = %v, want %v", i, got, tc.want)
		}
	}
	if SecurityPostureOf(&Event{}) != SecurityPostureAbsent {
		t.Error("no facts reads as absent")
	}
	if SecurityPostureOf(&Event{Security: &Security{}}) != SecurityPostureUnknown {
		t.Error("an unset state reads as unknown")
	}
	if SecurityPostureOf(&Event{Security: &Security{Posture: SecurityPostureDirty}}) != SecurityPostureDirty {
		t.Error("a set state reads as itself")
	}
}
