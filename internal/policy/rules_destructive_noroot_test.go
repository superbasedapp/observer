package policy

import (
	"testing"
	"time"
)

// TestR101HomeChildWithUnknownRoot pins D-MU10 (live macOS install
// 2026-10-29): a Claude Code pre-tool event with cwd ~/sbo-user-proj/demo
// and no known project root allowed `rm -rf ~/Desktop`. With the root
// unknown a recursive delete of a folder directly in the home directory is
// now denied in every spelling; with a known root the existing
// outside-the-project arm still denies it; a path inside the cwd stays
// allowed, and the home directory itself stays denied either way.
func TestR101HomeChildWithUnknownRoot(t *testing.T) {
	t.Parallel()
	const home = "/Users/u"
	const cwd = "/Users/u/sbo-user-proj/demo"
	cases := []struct {
		name string
		cmd  string
		root string
		want Decision
	}{
		{"tilde Desktop, no root", "rm -rf ~/Desktop", "", DecisionDeny},
		{"tilde Desktop trailing slash, no root", "rm -rf ~/Desktop/", "", DecisionDeny},
		{"$HOME Documents, no root", "rm -rf $HOME/Documents", "", DecisionDeny},
		{"${HOME} Documents, no root", "rm -rf ${HOME}/Documents", "", DecisionDeny},
		{"absolute Downloads, no root", "rm -rf /Users/u/Downloads", "", DecisionDeny},
		{"relative climb to a home child, no root", "rm -rf ../../Pictures", "", DecisionDeny},
		{"home itself, no root", "rm -rf ~/", "", DecisionDeny},
		{"inside the cwd, no root", "rm -rf build", "", DecisionAllow},
		{"deeper under home, no root", "rm -rf ~/sbo-user-proj/demo/out", "", DecisionAllow},
		{"tilde Desktop, known root", "rm -rf ~/Desktop", cwd, DecisionDeny},
		{"$HOME Documents, known root", "rm -rf $HOME/Documents", cwd, DecisionDeny},
		{"absolute Downloads, known root", "rm -rf /Users/u/Downloads", cwd, DecisionDeny},
		{"inside the known root", "rm -rf build", cwd, DecisionAllow},
	}
	enforce, err := New(Config{Mode: ModeEnforce, Home: home})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		ev := Event{
			Kind: KindShellExec, ActionType: "run_command", Target: c.cmd,
			Cwd: cwd, ProjectRoot: c.root, SessionID: "s1",
			Now: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC),
		}
		v := enforce.Evaluate(ev)
		switch c.want {
		case DecisionDeny:
			if v.Decision != DecisionDeny || v.RuleID != "R-101" {
				t.Errorf("%s: %s/%s (%q), want R-101/deny", c.name, v.RuleID, v.Decision, v.Reason)
			}
		default:
			if v.RuleID == "R-101" {
				t.Errorf("%s: R-101 hit (%q), want no R-101", c.name, v.Reason)
			}
		}
	}
}
