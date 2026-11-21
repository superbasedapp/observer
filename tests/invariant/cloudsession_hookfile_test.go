package invariant

import (
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestCloudSessionHookFilesAreR160 pins ledger CLOUDSESS-5: every committed
// hook file `observer cloud-session init` writes for a supported agent (the
// file carrying the sandbox gate and flush hooks) is on R-160's integrity
// surface, so an enforce gate denies the agent editing its own gate out.
// internal/policy imports no observer package, so its pattern rows are
// listed by hand; this walks the agent table against them, and a new agent
// whose hook file is not covered fails here.
func TestCloudSessionHookFilesAreR160(t *testing.T) {
	eng, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: "/home/u"})
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, a := range cloudsession.Agents() {
		if !a.Supported() {
			continue
		}
		f, ok := cloudsession.HookFile(a)
		if !ok {
			t.Errorf("%s: supported agent with no hook file", a.ID)
			continue
		}
		checked++
		for _, kind := range []struct {
			name string
			ev   policy.Event
		}{
			{"edit", policy.Event{Kind: policy.KindFileAccess, ActionType: "write_file", Target: f.Path}},
			{"shell", policy.Event{Kind: policy.KindShellExec, ActionType: "run_command", Target: "echo '{}' > " + f.Path}},
		} {
			ev := kind.ev
			ev.Cwd, ev.ProjectRoot, ev.SessionID = "/home/u/repo", "/home/u/repo", "s1"
			ev.Now = time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
			v := eng.Evaluate(ev)
			if v.RuleID != "R-160" || v.Decision != policy.DecisionDeny {
				t.Errorf("%s %s of %s: verdict %s/%s, want R-160/deny", a.ID, kind.name, f.Path, v.RuleID, v.Decision)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no supported cloud-session agent checked")
	}
}
