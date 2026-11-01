package termcore

import (
	"errors"
	"testing"
)

// TestAgentPolicyRows: one case per check of the agent authorization,
// and an unchecked key never refuses (ruling P-203).
func TestAgentPolicyRows(t *testing.T) {
	root := t.TempDir()
	for _, tc := range []struct {
		name string
		p    AgentPolicy
		want error
	}{
		{"nothing checked", AgentPolicy{}, nil},
		{"fresh off", AgentPolicy{CheckFresh: true}, ErrFreshLaunchDisabled},
		{"fresh on", AgentPolicy{CheckFresh: true, AllowFresh: true}, nil},
		{"tool off the list", AgentPolicy{CheckTools: true, Tools: []string{"codex"}}, ErrToolNotAllowed},
		{"tool on the list", AgentPolicy{CheckTools: true, Tools: []string{"claude-code"}}, nil},
		{"root outside", AgentPolicy{CheckRoots: true, Roots: []string{t.TempDir()}}, ErrProjectRootDenied},
		{"root inside", AgentPolicy{CheckRoots: true, Roots: []string{root}}, nil},
	} {
		if _, err := tc.p.Authorize("claude-code", root); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if _, err := AuthorizeAgent(false, nil, nil, "claude-code", root); !errors.Is(err, ErrFreshLaunchDisabled) {
		t.Fatalf("the full authorization skipped a check: %v", err)
	}
}
