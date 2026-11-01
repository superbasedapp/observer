package dashboard

import (
	"strings"
	"testing"
)

// joinFakeManager is a LaunchManager that answers RunSandboxed only.
type joinFakeManager struct {
	LaunchManager
	runs map[string]bool // handle -> sandboxed
}

func (m joinFakeManager) RunSandboxed(handle string) (bool, bool) {
	sb, ok := m.runs[handle]
	return sb, ok
}

// TestTerminalJoinGate (OSH-R-003): joining a live run (Jump-in, a tab
// reconnecting) asks the org terminals decision with the run's own sandbox
// answer; a setup PTY (no run) is never asked, and no gate allows.
func TestTerminalJoinGate(t *testing.T) {
	mgr := joinFakeManager{runs: map[string]bool{"plain": false, "boxed": true}}
	var asked []bool
	gate := func(sb bool) (bool, string) {
		asked = append(asked, sb)
		if sb {
			return true, ""
		}
		return false, "organization policy requires a sandboxed terminal for this feature; retry with sandbox enabled"
	}
	s := &Server{opts: Options{LaunchManager: mgr, TerminalFeatureGate: gate}}
	if reason, refused := s.terminalJoinRefused("plain"); !refused || !strings.Contains(reason, "sandboxed terminal") {
		t.Fatalf("an unsandboxed run under sandbox_required was joined: %q", reason)
	}
	if _, refused := s.terminalJoinRefused("boxed"); refused {
		t.Fatal("a sandboxed run was refused")
	}
	if _, refused := s.terminalJoinRefused("setup-pty"); refused || len(asked) != 2 {
		t.Fatalf("a setup PTY was judged (asked %v)", asked)
	}
	s.opts.TerminalFeatureGate = nil
	if _, refused := s.terminalJoinRefused("plain"); refused {
		t.Fatal("no gate refused a join")
	}
}
