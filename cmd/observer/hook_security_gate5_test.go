//go:build !sbo_omit_security

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// gate5Repos is a gatefix node whose project is a real repository, plus a
// second real repository the agent's line reaches (lane SEC-GATE5
// milestone 1).
type gate5Repos struct {
	gatefixNode
	other string
	seq   uint64
}

func newGate5Repos(t *testing.T) *gate5Repos {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	mk := func() string {
		d := t.TempDir()
		if r, err := filepath.EvalSymlinks(d); err == nil {
			d = r
		}
		gitIn(t, d, "init", "-q")
		return d
	}
	n := newGatefixNode(t)
	n.root = mk()
	return &gate5Repos{gatefixNode: n, other: mk()}
}

// writePostureFor signs a current posture for root whose clean record
// covers root's dirty counter as it is now, with a sequence above every
// earlier one (the daemon's output for that project after a clean quick
// scan); mut adjusts it.
func (n *gate5Repos) writePostureFor(t *testing.T, root string, mut func(f *secposture.File)) {
	t.Helper()
	m := n.gatefixNode
	m.root = root
	counter, err := secposture.ReadDirty(n.layout, secposture.ProjectRootHash(root))
	if err != nil {
		counter = 0
	}
	n.seq++
	seq := n.seq
	m.writeCleanPosture(t, func(f *secposture.File) {
		f.Sequence, f.DirtyCleanEpoch = seq, counter
		if mut != nil {
			mut(f)
		}
	})
}

// otherRepoLines are the spellings of a commit that runs in the other
// repository from a shell whose working directory is the event's project.
func otherRepoLines(other string) map[string]string {
	return map[string]string{
		"cd":           "cd " + shPath(other) + " && git commit -m wip",
		"pushd":        "pushd " + shPath(other) + " && git commit -m wip",
		"subshell":     "(cd " + shPath(other) + " && git commit -m wip)",
		"-C":           "git -C " + shPath(other) + " commit -m wip",
		"--git-dir":    "git --git-dir=" + shPath(filepath.Join(other, ".git")) + " commit -m wip",
		"GIT_DIR":      "GIT_DIR=" + shPath(filepath.Join(other, ".git")) + " git commit -m wip",
		"GIT_DIR env":  "export GIT_DIR=" + shPath(filepath.Join(other, ".git")) + "; git commit -m wip",
		"nested shell": "bash -c 'cd " + shPath(other) + " && git commit -m wip'",
		"push via -C":  "git -C " + shPath(other) + " push",
	}
}

// TestSecurityOtherRepoCommitAnswersUnknown (P-021, P-041): the event's
// project is clean and signed; a line commits in another repository that
// has no posture of its own. Every spelling reads unknown and S-794 asks
// on an individual node, and denies on a host that cannot ask (D-791
// Q27); before this lane the opaque plan only mattered while dirty, so
// each of these was allowed.
func TestSecurityOtherRepoCommitAnswersUnknown(t *testing.T) {
	n := newGate5Repos(t)
	for name, line := range otherRepoLines(n.other) {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(line, n.root, "")
		v := n.evaluate(t, pe)
		if v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
			t.Fatalf("%s: verdict %+v (security %+v), want S-794 ask", name, v, pe.Security)
		}
		if pe.Security == nil || pe.Security.Posture != policy.SecurityPostureUnknown {
			t.Fatalf("%s: security %+v, want unknown", name, pe.Security)
		}
		if em := guard.ResolveEmission(v, policy.Capabilities{CanBlock: true}); em.Permission != "deny" {
			t.Fatalf("%s: on a host that cannot ask the emission is %+v, want deny", name, em)
		}
	}
	// The managed floor's cell for unknown is deny (section 4.8), which
	// the org bundle raises S-794 to; the state fed to it is the one above.
	if got := secposture.Gate(policy.SecurityPostureUnknown, secposture.GateManagedFloor); got != secposture.GateDeny {
		t.Fatalf("managed floor unknown cell = %s, want deny", got)
	}
}

// TestSecurityOtherRepoCommitReadsItsOwnPosture: with the other repository
// signed, its own state decides when it is stricter. A clean record there
// reads dirty, because the line may change files there before it commits
// and only the event's own project's counter was raised (the otherCheckout
// rule): S-793 asks on the opaque quick scan. A blocking one gates as
// blocking (S-791, which enforce denies), never as dirty.
func TestSecurityOtherRepoCommitReadsItsOwnPosture(t *testing.T) {
	n := newGate5Repos(t)
	line := "cd " + shPath(n.other) + " && git commit -m wip"
	before, _ := secposture.ReadDirty(n.layout, secposture.ProjectRootHash(n.other))

	n.writePostureFor(t, n.root, nil)
	n.writePostureFor(t, n.other, nil)
	pe := shellCommit(line, n.root, "")
	if v := n.evaluate(t, pe); v.RuleID != "S-793" || pe.Security.QuickScan != policy.QuickScanUnknown {
		t.Fatalf("other repository clean: verdict %+v (security %+v), want S-793 on an unknown quick scan", v, pe.Security)
	}
	if after, _ := secposture.ReadDirty(n.layout, secposture.ProjectRootHash(n.other)); after <= before {
		t.Fatalf("the other repository's dirty counter was not raised: %d -> %d", before, after)
	}

	n.writePostureFor(t, n.root, nil)
	n.writePostureFor(t, n.other, func(f *secposture.File) { f.Blocking = []string{"k1"} })
	pe = shellCommit(line, n.root, "")
	if v := n.evaluate(t, pe); v.RuleID != "S-791" {
		t.Fatalf("other repository blocking: verdict %+v (security %+v), want S-791", v, pe.Security)
	}
	if pe.Security.DefaultPushRemote != "" || pe.Security.BlockingHistoryOnlyOn != nil {
		t.Fatalf("a line reaching another repository credits a remote: %+v", pe.Security)
	}

	// The event's own project blocking stays blocking when the other
	// repository is clean (the stricter state decides).
	n.writePostureFor(t, n.other, nil)
	n.writePostureFor(t, n.root, func(f *secposture.File) { f.Blocking = []string{"k2"} })
	pe = shellCommit(line, n.root, "")
	if v := n.evaluate(t, pe); v.RuleID != "S-791" {
		t.Fatalf("own project blocking: verdict %+v (security %+v), want S-791", v, pe.Security)
	}
}

// TestSecurityUnplacedCommitAnswersUnknown: a write the line does not let
// the hook place (a variable, `cd -`) reads unknown under a clean posture.
func TestSecurityUnplacedCommitAnswersUnknown(t *testing.T) {
	n := newGate5Repos(t)
	for _, line := range []string{
		"cd $REPO && git commit -m wip",
		"cd - && git commit -m wip",
		"git -C \"$D\" commit -m wip",
	} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(line, n.root, "")
		if v := n.evaluate(t, pe); v.RuleID != "S-794" {
			t.Fatalf("%q: verdict %+v (security %+v), want S-794", line, v, pe.Security)
		}
	}
}

// TestSecurityOwnRepoCommitGolden: the spellings that stay inside the
// event's own repository read exactly as before (one quick-scan request,
// no other repository, the clean posture lets the commit through).
func TestSecurityOwnRepoCommitGolden(t *testing.T) {
	n := newGate5Repos(t)
	sub := filepath.Join(n.root, "pkg")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ line, cwd string }{
		{"git commit -m wip", n.root},
		{"git commit -m wip", sub},
		{"cd pkg && git commit -m wip", n.root},
		{"cd " + shPath(n.root) + " && git commit -m wip", sub},
		{"git -C " + shPath(n.root) + " commit -m wip", sub},
		{"(cd pkg && git commit -m wip)", n.root},
		{"git commit -m wip && cd " + shPath(n.other), n.root},
	} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(tc.line, tc.cwd, "")
		p := securityQuickScanPlanFor(pe, n.root, nil)
		if p.elsewhere() || p.otherCheckout {
			t.Fatalf("%q in %s: plan %+v reads another repository", tc.line, tc.cwd, p)
		}
		if v := n.evaluate(t, pe); v.RuleID == "S-793" || v.RuleID == "S-794" {
			t.Fatalf("%q in %s: verdict %+v (security %+v), want it to proceed", tc.line, tc.cwd, v, pe.Security)
		}
		if pe.Security == nil || pe.Security.Posture != policy.SecurityPostureClean {
			t.Fatalf("%q in %s: security %+v, want clean", tc.line, tc.cwd, pe.Security)
		}
	}
}

// TestSecurityOtherCheckoutStaysWorktreeCase: a `-C` or GIT_DIR into a
// linked worktree of the same project is the otherCheckout case (dirty
// with an unknown quick scan, S-793), not another repository.
func TestSecurityOtherCheckoutStaysWorktreeCase(t *testing.T) {
	n := newWorktreeGateNode(t)
	for _, line := range []string{
		"git -C " + shPath(n.wt) + " commit -m wip",
		"cd " + shPath(n.wt) + " && git commit -m wip",
	} {
		n.clean(t)
		pe := shellCommit(line, n.root, "")
		if p := securityQuickScanPlanFor(pe, n.root, nil); !p.otherCheckout || p.elsewhere() {
			t.Fatalf("%q: plan %+v, want the otherCheckout case only", line, p)
		}
		wantWorktreeAsk(t, line, n.evaluate(t, pe), pe)
	}
}

// TestHookDropStalePushDefault (lane SEC-GATE5 milestone 2): the hook keeps
// a signed default push remote only while every checkout's HEAD was
// written before the posture was signed.
func TestHookDropStalePushDefault(t *testing.T) {
	issued := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	reading := secposture.Reading{File: &secposture.File{IssuedAt: issued}}
	for _, tc := range []struct {
		name string
		head time.Time
		ok   bool
		r    secposture.Reading
		want string
	}{
		{"HEAD written before the posture", issued.Add(-time.Second), true, reading, "origin"},
		{"HEAD written after the posture", issued.Add(time.Second), true, reading, ""},
		{"HEAD written at the same instant", issued, true, reading, ""},
		{"HEADs unreadable", time.Time{}, false, reading, ""},
		{"no posture file", issued.Add(-time.Second), true, secposture.Reading{}, ""},
	} {
		old := hookHeadWrite
		hookHeadWrite = func(string) (time.Time, bool) { return tc.head, tc.ok }
		got := hookDropStalePushDefault(policy.Security{DefaultPushRemote: "origin"}, tc.r, "/r").DefaultPushRemote
		hookHeadWrite = old
		if got != tc.want {
			t.Errorf("%s: default %q, want %q", tc.name, got, tc.want)
		}
	}
}
