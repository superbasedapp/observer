package policy

import (
	"testing"
	"time"
)

// TestGuardEnvPersistFileOnUnseenContent pins FR-SEC-11 (review
// 2026-11-22): R-165's file form judged only the text an edit shows, so an
// apply_patch rename onto a startup file the guard reads (`*** Update File:
// notes.txt` + `*** Move to: ~/.pam_environment`, where notes.txt already
// says OBSERVER_GUARD_MODE=off) was R-150/ask, while writing the same text
// directly is R-165/deny. Content the guard cannot see (EditUnknown, the
// rename marker) is judged as content that may name the override. The
// startup files R-154 already denies by path are not the gap: these are the
// rows of shellStartupPatterns that R-154 does not cover.
func TestGuardEnvPersistFileOnUnseenContent(t *testing.T) {
	t.Parallel()
	unknown := []ProposedEdit{{Kind: EditUnknown}}
	withFragment := []ProposedEdit{{Kind: EditFragment, Old: "a", New: "b"}, {Kind: EditUnknown}}
	plain := []ProposedEdit{{Kind: EditWhole, New: "LANG=C.UTF-8"}}
	cases := []struct {
		name, target string
		edits        []ProposedEdit
		wantRule     string
		want         Decision
	}{
		{"rename onto the PAM environment", "/home/u/.pam_environment", unknown, "R-165", DecisionDeny},
		{"rename onto the PAM environment, ~ form", "~/.pam_environment", unknown, "R-165", DecisionDeny},
		{"rename with a hunk onto the PAM environment", "/home/u/.pam_environment", withFragment, "R-165", DecisionDeny},
		{"rename onto the systemd user environment", "/home/u/.config/environment.d/x.conf", unknown, "R-165", DecisionDeny},
		{"rename onto a fish startup file", "/home/u/.config/fish/conf.d/x.fish", unknown, "R-165", DecisionDeny},
		{"rename onto a PowerShell profile", "/home/u/.config/powershell/Microsoft.PowerShell_profile.ps1", unknown, "R-165", DecisionDeny},
		{"visible text that does not name the override", "/home/u/.pam_environment", plain, "R-150", DecisionAsk},
	}
	e, err := New(Config{Mode: ModeEnforce, Home: "/home/u", ReadFile: func(string) ([]byte, bool) { return nil, false }})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := e.Evaluate(Event{
				Kind: KindFileAccess, ActionType: "edit_file", Target: tc.target, Edits: tc.edits,
				Cwd: "/home/u/proj", ProjectRoot: "/home/u/proj", SessionID: "s1",
				Now: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC),
			})
			if v.RuleID != tc.wantRule || v.Decision != tc.want {
				t.Fatalf("got %s/%s (%q), want %s/%s", v.RuleID, v.Decision, v.Reason, tc.wantRule, tc.want)
			}
		})
	}
}
