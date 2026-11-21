package policy

import (
	"testing"
	"time"
)

// TestSelfApprovalOrgShellOptIn (OSH-142, plans ruling P-241): the
// laptop-relay opt-in is the person's consent, never an agent's, so an
// agent's `observer sandbox org-shell opt-in` is asked about by R-165 in
// BOTH modes, with or without the command's own --yes; its sibling verbs
// (opt-out, status) are not.
func TestSelfApprovalOrgShellOptIn(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, line string
		hit        bool
	}{
		{name: "opt-in", line: `observer sandbox org-shell opt-in`, hit: true},
		{name: "opt-in --yes", line: `observer sandbox org-shell opt-in --yes`, hit: true},
		{name: "opt-in --yes=true", line: `observer sandbox org-shell opt-in --yes=true`, hit: true},
		{name: "opt-in piped yes", line: `echo yes | observer sandbox org-shell opt-in`, hit: true},
		{name: "opt-in --yes via npx", line: `npx -y @superbased/observer sandbox org-shell opt-in --yes`, hit: true},
		{name: "opt-in, flag first", line: `observer --config /tmp/c.toml sandbox org-shell opt-in --yes`, hit: true},
		{name: "opt-in binary by path", line: `/opt/observer/bin/observer sandbox org-shell opt-in --yes`, hit: true},
		{name: "flags before: opt-in (OSH-141)", line: `observer sandbox org-shell --x y opt-in --yes`, hit: true},
		{name: "flags before at the root: opt-in", line: `observer --x y sandbox org-shell opt-in`, hit: true},
		{name: "flags before: opt-out passes", line: `observer sandbox org-shell --x y opt-out`},
		{name: "opt-out only takes the consent away", line: `observer sandbox org-shell opt-out`},
		{name: "status is a read", line: `observer sandbox org-shell status`},
		{name: "npx of another package", line: `npx other-tool sandbox org-shell opt-in --yes`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			const home, root = "/home/u", "/home/u/proj"
			ev := Event{
				Kind: KindShellExec, Target: tc.line,
				Cwd: root, ProjectRoot: root, SessionID: "s1",
				Now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC),
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				e, err := New(Config{Mode: mode, Home: home})
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				v := e.Evaluate(ev)
				switch {
				case tc.hit && (v.RuleID != "R-165" || v.Decision != DecisionAsk):
					t.Fatalf("%s: want R-165 ask, got %q %s (%q)", mode, v.RuleID, v.Decision, v.Reason)
				case !tc.hit && v.RuleID == "R-165":
					t.Fatalf("%s: want no R-165 hit, got %s (%q)", mode, v.Decision, v.Reason)
				}
			}
		})
	}
}

// TestOrgShellOptInAskIsNotEnforced pins that the OSH-142 ask row, like
// R-168's, is not Enforced: an Enforced row would make every observe-mode
// node's tool gate count as enforcing (Guard.GateEnforcement).
func TestOrgShellOptInAskIsNotEnforced(t *testing.T) {
	t.Parallel()
	for _, r := range selfApprovalRules() {
		if r.Observe == DecisionAsk && r.Enforced {
			t.Fatalf("an R-165 ask row is Enforced: %q", r.Doc)
		}
	}
}
