package policy

import (
	"reflect"
	"testing"
)

// gatingCounts counts the gating commits and pushes a classification holds.
func gatingCounts(cls []ClassifiedGitWrite) (commits, pushes int) {
	for _, c := range cls {
		if !GitWriteGates(c.Write) {
			continue
		}
		if GitWriteIsPush(c.Write) {
			pushes++
		} else {
			commits++
		}
	}
	return commits, pushes
}

// TestClassifyGitWritesCtxAltDialect (SEC-GATE5 follow-up): on a host that
// states no shell on a Windows working directory (Codex, Copilot CLI), the
// commit gate's classifier reads the PowerShell reading too, so a write
// only PowerShell sees (`\;` escapes the separator for POSIX) is
// classified; a line both readings read alike is classified once.
func TestClassifyGitWritesCtxAltDialect(t *testing.T) {
	for _, tc := range []struct {
		name                      string
		line                      string
		posixCommits, posixPushes int
		bothCommits, bothPushes   int
	}{
		{"escaped separator commit", `cd C:\x\; git commit -m x`, 0, 0, 1, 0},
		{"PowerShell-only push", `cd C:\x\; git push origin main`, 0, 0, 0, 1},
		{"PowerShell-only commit after Set-Location", `Set-Location C:\x\; git commit -m x`, 0, 0, 1, 0},
		{"own commit", "git commit -m x", 1, 0, 1, 0},
		{"own push", "git push", 0, 1, 0, 1},
		{"commit then push", "git commit -m x; git push", 1, 1, 1, 1},
		{"readings disagree on the operands", `git commit -m x\ y`, 1, 0, 1, 0},
		{"not a write", "git status", 0, 0, 0, 0},
	} {
		ev := &Event{Kind: KindShellExec, Target: tc.line, Cwd: `C:\work\repo`}
		pc, pp := gatingCounts(ClassifyGitWritesCtx(&MatchContext{Event: ev, Cfg: &Config{}}))
		if pc != tc.posixCommits || pp != tc.posixPushes {
			t.Errorf("%s: POSIX reading alone %d commits %d pushes, want %d and %d", tc.name, pc, pp, tc.posixCommits, tc.posixPushes)
		}
		ev.AltDialect = DialectPowerShell
		bc, bp := gatingCounts(ClassifyGitWritesCtx(&MatchContext{Event: ev, Cfg: &Config{}}))
		if bc != tc.bothCommits || bp != tc.bothPushes {
			t.Errorf("%s: both readings %d commits %d pushes, want %d and %d", tc.name, bc, bp, tc.bothCommits, tc.bothPushes)
		}
		if got := len(GatedGitWrites(&MatchContext{Event: ev, Cfg: &Config{}})); got != tc.bothCommits {
			t.Errorf("%s: GatedGitWrites %d, want %d", tc.name, got, tc.bothCommits)
		}
	}
	// A stated PowerShell host has one reading; an argv event is never
	// read twice.
	own := &Event{Kind: KindShellExec, Target: "git commit -m x", Cwd: `C:\r`, Dialect: DialectPowerShell, AltDialect: DialectPowerShell}
	if got := ClassifyGitWritesCtx(&MatchContext{Event: own, Cfg: &Config{}}); len(got) != 1 {
		t.Fatalf("same dialect twice: %+v, want one write", got)
	}
	argv := &Event{Kind: KindShellExec, Args: []string{"git", "commit", "-m", "x"}, Cwd: `C:\r`, AltDialect: DialectPowerShell}
	if got := ClassifyGitWritesCtx(&MatchContext{Event: argv, Cfg: &Config{}}); len(got) != 1 {
		t.Fatalf("argv: %+v, want one write", got)
	}
}

// TestUnionGitWriteReadings: a write of the second reading folds into the
// first unpaired write of its kind (the more restrictive flags win), and
// one with no partner is added.
func TestUnionGitWriteReadings(t *testing.T) {
	commit := ClassifiedGitWrite{Write: GitWrite{Form: GitWriteCommit}, Detail: "git commit"}
	push := ClassifiedGitWrite{Write: GitWrite{Push: true, PushOperands: []string{"origin"}}, Detail: "git push origin"}
	a := []ClassifiedGitWrite{commit}
	if got := unionGitWriteReadings(a, nil); !reflect.DeepEqual(got, a) {
		t.Fatalf("no second reading: %+v", got)
	}
	if got := unionGitWriteReadings(a, a); !reflect.DeepEqual(got, a) {
		t.Fatalf("alike readings: %+v, want a unchanged", got)
	}
	amend := commit
	amend.Write.Amend = true
	amend.Write.Pathspecs = []string{"y"}
	got := unionGitWriteReadings(a, []ClassifiedGitWrite{amend, push})
	if len(got) != 2 {
		t.Fatalf("fold and add: %+v, want two writes", got)
	}
	if w := got[0].Write; !w.Amend || !w.All || !reflect.DeepEqual(w.Pathspecs, []string{"y"}) || got[0].Detail != "git commit" {
		t.Fatalf("folded commit: %+v", got[0])
	}
	if !reflect.DeepEqual(got[1], push) {
		t.Fatalf("added push: %+v", got[1])
	}
	other := push
	other.Write.PushOperands = []string{"backup"}
	got = unionGitWriteReadings([]ClassifiedGitWrite{push}, []ClassifiedGitWrite{other})
	if len(got) != 1 || !got[0].Write.PushOpaque || PushTargetFor(got[0].Write, "").Known {
		t.Fatalf("pushes disagreeing on the remote: %+v, want one push with an unknown target", got)
	}
	if a[0].Write.Amend || a[0].Write.All || len(a[0].Write.Pathspecs) != 0 {
		t.Fatalf("the input was modified: %+v", a)
	}
}
