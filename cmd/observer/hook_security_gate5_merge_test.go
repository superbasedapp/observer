//go:build !sbo_omit_security

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// TestSecurityAltDialectOtherRepoCommit (merge finding F1 of lane
// SEC-GATE5): on a host that states no shell and gets the PowerShell
// reading too (Codex, Copilot CLI on Windows), a PowerShell directory move
// to another repository is placed there, so the clean posture of the
// event's own project does not let the commit through: S-794 asks (the
// other repository has no posture). The plain own-repository commit still
// proceeds on the clean posture.
func TestSecurityAltDialectOtherRepoCommit(t *testing.T) {
	n := newGate5Repos(t)
	for _, line := range []string{
		"Set-Location " + n.other + "; git commit -m wip",
		"sl " + n.other + "; git commit -m wip",
		"cd " + n.other + "; git commit -m wip",
		"Push-Location " + n.other + "; git commit -m wip",
		"Set-Location -Path " + n.other + "; git commit -m wip",
	} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(line, n.root, "")
		pe.AltDialect = policy.DialectPowerShell
		if p := securityQuickScanPlanFor(pe, n.root, nil); !p.elsewhere() {
			t.Fatalf("%q: plan %+v, want the other repository read", line, p)
		}
		if v := n.evaluate(t, pe); v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
			t.Fatalf("%q: verdict %+v (security %+v), want S-794 ask", line, v, pe.Security)
		}
	}
	sub := filepath.Join(n.root, "pkg")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"git commit -m wip", "cd pkg && git commit -m wip", "git push"} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(line, n.root, "")
		pe.AltDialect = policy.DialectPowerShell
		if p := securityQuickScanPlanFor(pe, n.root, nil); p.elsewhere() || p.otherCheckout {
			t.Fatalf("own repository %q: plan %+v reads another repository", line, p)
		}
	}
	n.writePostureFor(t, n.root, nil)
	pe := shellCommit("git commit -m wip", n.root, "")
	pe.AltDialect = policy.DialectPowerShell
	if v := n.evaluate(t, pe); v.RuleID == "S-793" || v.RuleID == "S-794" || pe.Security == nil || pe.Security.Posture != policy.SecurityPostureClean {
		t.Fatalf("own repository commit: verdict %+v (security %+v), want it to proceed on clean", v, pe.Security)
	}
}

// TestSecurityRedirectAndNetworkCommitAnswerUnknown (merge findings F5 and
// F9): another index or work tree, and a `-C` or GIT_DIR on a network
// path, read unknown under a clean posture (S-794).
func TestSecurityRedirectAndNetworkCommitAnswerUnknown(t *testing.T) {
	n := newGate5Repos(t)
	for _, line := range []string{
		"GIT_INDEX_FILE=/tmp/other-index git commit -m wip",
		"git -c core.worktree=" + n.other + " commit -m wip",
		"git --git-dir=" + filepath.Join(n.root, ".git", "worktrees", "wt") + " commit -m wip",
		"git -C //host/share/repo commit -m wip",
		"GIT_DIR=//host/share/repo/.git git commit -m wip",
		"git -C /net/host/repo commit -m wip",
	} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(line, n.root, "")
		if v := n.evaluate(t, pe); v.RuleID != "S-794" {
			t.Fatalf("%q: verdict %+v (security %+v), want S-794", line, v, pe.Security)
		}
	}
}

// TestSecurityWritesUnplaced (merge finding F3): a gating write the placer
// did not place reads unknown, never as the event's own repository.
func TestSecurityWritesUnplaced(t *testing.T) {
	placed := policy.GitWriteLocation{Dirs: []string{"/r"}}
	for _, tc := range []struct {
		name   string
		gating int
		locs   []policy.GitWriteLocation
		want   bool
	}{
		{"every write placed", 2, []policy.GitWriteLocation{placed, placed}, false},
		{"no gating write", 0, nil, false},
		{"fewer locations than gating writes", 2, []policy.GitWriteLocation{placed}, true},
		{"no location at all", 1, nil, true},
		{"a location with no directory", 1, []policy.GitWriteLocation{{}}, true},
		{"an unknown location", 1, []policy.GitWriteLocation{{Dirs: []string{"/r"}, Unknown: true}}, true},
	} {
		if got := securityWritesUnplaced(tc.gating, tc.locs); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestPushDefaultHeadInFuture (merge finding F7): a HEAD write in the
// future (clock skew, DrvFs, a network file system) is clamped, so the
// entry is not stale on every look and the HEAD watch does not re-resolve
// and re-sign it every few seconds; a later switch still makes it stale,
// and a HEAD written just after the resolution (not in the future) still
// does too.
func TestPushDefaultHeadInFuture(t *testing.T) {
	future := time.Now().Add(time.Hour)
	heads := map[string]time.Time{"/f": future}
	old := pushDefaultHeadWrite
	pushDefaultHeadWrite = func(root string) (time.Time, bool) { at, ok := heads[root]; return at, ok }
	t.Cleanup(func() { pushDefaultHeadWrite = old })
	var tab pushDefaultTable
	tab.set("hf", "/f", "origin", true, time.Now())
	if got := tab.get("hf"); got != "origin" {
		t.Fatalf("future HEAD: get = %q, want origin", got)
	}
	if st := tab.stale(8); len(st) != 0 {
		t.Fatalf("future HEAD: stale %v, want none", st)
	}
	heads["/f"] = future.Add(time.Minute)
	if got := tab.get("hf"); got != "" {
		t.Fatalf("a later switch: get = %q, want none", got)
	}
	if st := tab.stale(8); st["hf"] != "/f" {
		t.Fatalf("a later switch: stale %v, want hf", st)
	}

	at := time.Now()
	heads["/n"] = at.Add(500 * time.Millisecond)
	tab.set("hn", "/n", "origin", true, at)
	if got := tab.get("hn"); got != "" {
		t.Fatalf("HEAD written just after the resolution: get = %q, want none", got)
	}
}
