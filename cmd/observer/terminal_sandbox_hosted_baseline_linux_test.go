//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// baselineBox plays, on top of the hosted harness, the box's answers to the
// diff against the upload's baseline commit (the smaller item "diff against
// the box's baseline" of the sandbox decisions): the baseline commit's name
// after the upload, and `git diff --cached <baseline>` at teardown.
type baselineBox struct {
	hh       *hostedHarness
	baseline string
	// diff is the baseline diff's output, code its exit.
	diff string
	code int
	// headRead and baselineDiffs count the two execs; guestDiffs the guest
	// one-shot's.
	mu                                  sync.Mutex
	headRead, baselineDiffs, guestDiffs int
}

// counts reads the three counters.
func (bb *baselineBox) counts() (head, baseline, guest int) {
	bb.mu.Lock()
	defer bb.mu.Unlock()
	return bb.headRead, bb.baselineDiffs, bb.guestDiffs
}

func newBaselineBox(t *testing.T, against string) *baselineBox {
	t.Helper()
	sha := strings.Repeat("c", 40)
	old := hostedMeasureUploadBase
	hostedMeasureUploadBase = func(context.Context, string, int) hostedDiffBase {
		return hostedDiffBase{Commit: sha, StatusKnown: true, StatusClean: true, AgentCommits: -1}
	}
	t.Cleanup(func() { hostedMeasureUploadBase = old })
	hh := newHostedHarness(t, sandboxremote.VendorE2B)
	hh.run.plan.DiffAgainst = against
	bb := &baselineBox{hh: hh, baseline: strings.Repeat("b", 40)}
	hh.client.execs = func(b *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
		bb.mu.Lock()
		defer bb.mu.Unlock()
		switch {
		case len(spec.Argv) >= 3 && spec.Argv[0] == "sh" && spec.Argv[2] == hostedBaselineHeadScript:
			bb.headRead++
			return newFakeProcess(bb.baseline+"\n", 0), nil
		case len(spec.Argv) > 0 && spec.Argv[0] == "git" && slices.Contains(spec.Argv, "--cached"):
			bb.baselineDiffs++
			if want, _ := workspace.BoxCloneDiffArgv(bb.baseline); !slices.Equal(spec.Argv, want) || spec.Env["GIT_EXTERNAL_DIFF"] != "" || spec.Env["GIT_PAGER"] != "cat" {
				return newFakeProcess("unexpected diff argv\n", 2), nil
			}
			return newFakeProcess(bb.diff, bb.code), nil
		case strings.Contains(strings.Join(spec.Argv, " "), " "+sandbox.GuestStagedDiff+" "):
			bb.guestDiffs++
		}
		return hh.exec(b, spec)
	}
	return bb
}

// run drives the run to its end and returns the saved diff's record.
func (bb *baselineBox) run(t *testing.T) hostedDiffRecord {
	t.Helper()
	code := make(chan int, 1)
	go func() { code <- bb.hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { bb.hh.mu.Lock(); defer bb.hh.mu.Unlock(); return len(bb.hh.ptys) > 0 })
	if c := hostedEndRun(t, bb.hh, code); c != 5 {
		t.Errorf("exit %d", c)
	}
	rec, ok := readHostedDiffRecord(bb.hh.run.plan.ObserverDir, "run-h1")
	if !ok {
		t.Fatalf("no diff record; output %s", bb.hh.out.String())
	}
	return rec
}

// TestHostedUploadDiffAgainstBaseline: an upload run where the agent made
// commits of its own, from a clean, committed folder, saves a diff taken
// against the upload's baseline commit, which holds those commits, and it
// opens as a branch.
func TestHostedUploadDiffAgainstBaseline(t *testing.T) {
	bb := newBaselineBox(t, "")
	bb.diff = "diff --git a/main.go b/main.go\n+// committed by the agent, then changed\n"
	bb.hh.diff = "diff --git a/main.go b/main.go\n+// only after the last commit\n"
	bb.hh.agentCommits = "2\n"
	rec := bb.run(t)
	if h, b, g := bb.counts(); h != 1 || b != 1 || g != 0 {
		t.Fatalf("execs: head %d, baseline diffs %d, guest diffs %d", h, b, g)
	}
	if !rec.Base.DiffFromStart || rec.Base.AgentCommits != 2 || rec.Base.Truncated {
		t.Fatalf("record %+v", rec.Base)
	}
	if v := workspace.DecideDiffBase(rec.Base.facts()); !v.Exact {
		t.Fatalf("an upload run with agent commits does not open as a branch: %+v", v)
	}
	diffPath, _ := hostedDiffPaths(bb.hh.run.plan.ObserverDir, "run-h1")
	if b, err := os.ReadFile(diffPath); err != nil || !strings.Contains(string(b), "committed by the agent") {
		t.Fatalf("saved diff %q %v", b, err)
	}
	if got := bb.hh.run.rec.Extra[hostedExtraUploadBaseline]; got != "" && got != bb.baseline {
		t.Fatalf("baseline on the record %q", got)
	}
}

// TestHostedUploadDiffBaselineFallsBack: when the diff against the baseline
// cannot be read (the agent removed the box's repository), the guest's
// capture against HEAD is saved instead, as before, and with commits of the
// agent's it is offered as a file only.
func TestHostedUploadDiffBaselineFallsBack(t *testing.T) {
	bb := newBaselineBox(t, config.HostedDiffAgainstBaseline)
	bb.code = 128
	bb.diff = "fatal: bad revision\n"
	bb.hh.diff = "diff --git a/main.go b/main.go\n+// after the last commit\n"
	bb.hh.agentCommits = "1\n"
	rec := bb.run(t)
	if _, b, g := bb.counts(); b != 1 || g != 1 {
		t.Fatalf("execs: baseline diffs %d, guest diffs %d", b, g)
	}
	if rec.Base.DiffFromStart || rec.Base.AgentCommits != 1 {
		t.Fatalf("record %+v", rec.Base)
	}
	if v := workspace.DecideDiffBase(rec.Base.facts()); v.Exact || !strings.Contains(v.Reason, "commit(s) of its own") {
		t.Fatalf("verdict %+v", v)
	}
	if !strings.Contains(bb.hh.out.String(), "against the box's last commit instead") {
		t.Errorf("the fallback is not said: %q", bb.hh.out.String())
	}
}

// TestHostedUploadDiffAgainstHead: diff_against = "head" keeps the earlier
// capture: no baseline is read, the guest's diff against HEAD is saved, and
// the agent's commits (counted from the root, the baseline not being the
// agent's) leave it a file only.
func TestHostedUploadDiffAgainstHead(t *testing.T) {
	bb := newBaselineBox(t, config.HostedDiffAgainstHead)
	bb.hh.diff = "diff --git a/main.go b/main.go\n+// after the last commit\n"
	bb.hh.agentCommits = "3\n"
	rec := bb.run(t)
	if h, b, g := bb.counts(); h != 0 || b != 0 || g != 1 {
		t.Fatalf("execs: head %d, baseline diffs %d, guest diffs %d", h, b, g)
	}
	if rec.Base.DiffFromStart || rec.Base.AgentCommits != 2 {
		t.Fatalf("record %+v", rec.Base)
	}
	if v := workspace.DecideDiffBase(rec.Base.facts()); v.Exact {
		t.Fatalf("verdict %+v", v)
	}
}

// TestHostedStagedDiffSpecRows: which capture each run takes. A row whose
// guest keeps its own baseline (the organization's row) always takes the
// guest's one-shot.
func TestHostedStagedDiffSpecRows(t *testing.T) {
	base, clone := strings.Repeat("b", 40), strings.Repeat("d", 40)
	guest := sandboxremote.ExecSpec{Argv: []string{"/box/observer", "sandbox-guest", sandbox.GuestStagedDiff}}
	for _, tc := range []struct {
		name      string
		plan      hostedPlanFile
		extra     map[string]string
		keeps     bool
		fromStart bool
		against   string
	}{
		{"an upload run with a recorded baseline", hostedPlanFile{}, map[string]string{hostedExtraUploadBaseline: base}, false, true, base},
		{"an upload run with no recorded baseline", hostedPlanFile{}, nil, false, false, ""},
		{"an upload run set to head", hostedPlanFile{DiffAgainst: config.HostedDiffAgainstHead}, map[string]string{hostedExtraUploadBaseline: base}, false, false, ""},
		{"a box-side clone at its commit", hostedPlanFile{Delivery: hostedDeliveryRemoteClone}, map[string]string{hostedExtraCloneCommit: clone}, false, true, clone},
		{"a box-side clone set to head still diffs against its clone", hostedPlanFile{Delivery: hostedDeliveryRemoteClone, DiffAgainst: config.HostedDiffAgainstHead}, map[string]string{hostedExtraCloneCommit: clone}, false, true, clone},
		{"a box-side clone never takes the upload baseline", hostedPlanFile{Delivery: hostedDeliveryRemoteClone}, map[string]string{hostedExtraUploadBaseline: base}, false, false, ""},
		{"the org row keeps its own baseline", hostedPlanFile{}, map[string]string{hostedExtraUploadBaseline: base}, true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &hostedRun{plan: tc.plan}
			r.rec.Extra = tc.extra
			if tc.keeps {
				r.vendor.BoxRunDir = "/run/observer"
			}
			spec, ok, fromStart := r.stagedDiffSpec(guest, func(int) bool { return true })
			if fromStart != tc.fromStart {
				t.Fatalf("fromStart %v", fromStart)
			}
			if !fromStart {
				if !slices.Equal(spec.Argv, guest.Argv) || !ok(sandbox.StagedDiffTruncatedExit) {
					t.Fatalf("not the guest's capture: %v", spec.Argv)
				}
				return
			}
			want, _ := workspace.BoxCloneDiffArgv(tc.against)
			if !slices.Equal(spec.Argv, want) || ok(1) || !ok(0) {
				t.Fatalf("argv %v", spec.Argv)
			}
		})
	}
}
