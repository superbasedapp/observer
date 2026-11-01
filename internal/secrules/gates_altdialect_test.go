package secrules

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestCommitGateAltDialect (SEC-GATE5 follow-up): on a host that states no
// shell on a Windows working directory (Codex, Copilot CLI), S-791 to
// S-794 match a commit or push only the PowerShell reading sees (`\;`
// escapes the separator for POSIX); without that reading the same line
// matches nothing, and an ordinary own-repository commit is unchanged.
func TestCommitGateAltDialect(t *testing.T) {
	blocking := func() *policy.Security {
		return &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 2}
	}
	for _, tc := range []struct {
		name  string
		cmd   string
		alt   policy.Dialect
		state *policy.Security
		rule  string
	}{
		{"escaped commit, blocking", `cd C:\x\; git commit -m x`, policy.DialectPowerShell, blocking(), "S-791"},
		{"escaped commit, POSIX reading alone", `cd C:\x\; git commit -m x`, "", blocking(), ""},
		{"PowerShell-only push, blocking", `cd C:\x\; git push origin main`, policy.DialectPowerShell, blocking(), "S-792"},
		{"PowerShell-only push, POSIX reading alone", `cd C:\x\; git push origin main`, "", blocking(), ""},
		{"escaped commit, unknown", `cd C:\x\; git commit -m x`, policy.DialectPowerShell, &policy.Security{Posture: policy.SecurityPostureUnknown}, "S-794"},
		{"own commit, blocking", "git commit -m x", policy.DialectPowerShell, blocking(), "S-791"},
		{"own commit, clean", "git commit -m x", policy.DialectPowerShell, &policy.Security{Posture: policy.SecurityPostureClean}, ""},
	} {
		ev := shellEvent(tc.cmd, true, tc.state)
		ev.Cwd, ev.ProjectRoot, ev.AltDialect = `C:\r`, `C:\r`, tc.alt
		v := gateEngine(t, policy.ModeEnforce).Evaluate(ev)
		got := v.RuleID
		if !strings.HasPrefix(got, "S-79") {
			got = ""
		}
		if got != tc.rule {
			t.Errorf("%s: rule %q (verdict %+v), want %q", tc.name, v.RuleID, v, tc.rule)
		}
	}
}
