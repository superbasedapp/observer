//go:build !sbo_omit_security

package main

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestSecurityAltDialectEscapedWrite (SEC-GATE5 follow-up): a commit or
// push only the PowerShell reading sees (`\;` escapes the separator for
// POSIX) is classified by the commit gate, so under a clean posture of the
// session's own project it is not let through: its place is unknown and
// S-794 asks. The own-repository commit is one quick-scan request, not
// two.
func TestSecurityAltDialectEscapedWrite(t *testing.T) {
	n := newGate5Repos(t)
	for _, line := range []string{
		"cd " + n.other + `\; git commit -m wip`,
		"cd " + n.other + `\; git push origin main`,
	} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(line, n.root, "")
		if p := securityQuickScanPlanFor(pe, n.root, nil); p.opaque || len(p.reqs) != 0 {
			t.Fatalf("%q, POSIX reading alone: plan %+v, want no write (the case the second reading covers)", line, p)
		}
		pe.AltDialect = policy.DialectPowerShell
		if p := securityQuickScanPlanFor(pe, n.root, nil); !p.elsewhere() {
			t.Fatalf("%q: plan %+v, want the write unplaced", line, p)
		}
		if v := n.evaluate(t, pe); v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
			t.Fatalf("%q: verdict %+v (security %+v), want S-794 ask", line, v, pe.Security)
		}
	}
	n.writePostureFor(t, n.root, nil)
	pe := shellCommit("git commit -m wip", n.root, "")
	pe.AltDialect = policy.DialectPowerShell
	if p := securityQuickScanPlanFor(pe, n.root, nil); p.opaque || len(p.reqs) != 1 {
		t.Fatalf("own repository commit: plan %+v, want one quick-scan request", p)
	}
}

// TestSecurityLineDirsNetwork (SEC-GATE5 follow-up): a cd, Set-Location or
// pushd target on a UNC path or under a network or automount root is never
// returned (so the hook never stats it) and reads unresolved, and a line
// moving there reads unknown; a target inside the event's own directory on
// such a root, and an ordinary path, are unchanged.
func TestSecurityLineDirsNetwork(t *testing.T) {
	// A POSIX-dialect line on Windows runs in Git Bash (HOOK-MSYS-1): the
	// network roots are unresolved there too, a drive mount (/c/x) is
	// C:\x, and any other rooted path is under the Git install folder,
	// which the hook does not know, so the walk stops there, unresolved.
	// win* hold the Windows expectation where it differs.
	for _, tc := range []struct {
		line, cwd     string
		dialect       policy.Dialect
		unresolved    bool
		dirs          int
		winUnresolved bool
		winDirs       int
	}{
		{"cd //host/share/r && git commit -m x", "/repo", policy.DialectPosix, true, 0, true, 0},
		{`Set-Location \\host\share\r; git commit -m x`, `C:\repo`, policy.DialectPowerShell, true, 0, true, 0},
		{"pushd /net/host/r && git commit -m x", "/repo", policy.DialectPosix, true, 0, true, 0},
		{"cd /misc/r && git commit -m x", "/repo", policy.DialectPosix, true, 0, true, 0},
		{"cd /afs/cell/r && git push", "/repo", policy.DialectPosix, true, 0, true, 0},
		{"cd /Network/Servers/h/r && git commit -m x", "/repo", policy.DialectPosix, true, 0, true, 0},
		{"cd /tmp/a && cd //host/share && git commit -m x", "/repo", policy.DialectPosix, true, 1, true, 0},
		{"cd sub && git commit -m x", "/net/h/repo", policy.DialectPosix, false, 1, false, 1},
		{"cd /mnt/c/other && git commit -m x", "/repo", policy.DialectPosix, false, 1, true, 0},
		{"cd /c/other && git commit -m x", "/repo", policy.DialectPosix, false, 1, false, 1},
	} {
		wantUnresolved, wantDirs := tc.unresolved, tc.dirs
		if runtime.GOOS == "windows" {
			wantUnresolved, wantDirs = tc.winUnresolved, tc.winDirs
		}
		pe := &policy.Event{Kind: policy.KindShellExec, Target: tc.line, Cwd: tc.cwd, Dialect: tc.dialect}
		dirs, unresolved := securityLineDirs(pe, tc.cwd)
		if unresolved != wantUnresolved || len(dirs) != wantDirs {
			t.Errorf("%q: dirs %q unresolved %v, want %d dirs unresolved %v", tc.line, dirs, unresolved, wantDirs, wantUnresolved)
		}
		for _, d := range dirs {
			if strings.Contains(d, "host") && !strings.HasPrefix(tc.cwd, "/net") {
				t.Errorf("%q: network dir %q returned", tc.line, d)
			}
		}
	}
	n := newGate5Repos(t)
	for _, line := range []string{
		"cd //host/share/repo && git commit -m wip",
		"cd /net/host/repo && git commit -m wip",
		"pushd /afs/cell/repo && git push origin main",
	} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(line, n.root, "")
		others, unplaced, _ := securityWriteRepos(pe, n.root, nil)
		if !unplaced || len(others) != 0 {
			t.Fatalf("%q: others %q unplaced %v, want unplaced and no repository read", line, others, unplaced)
		}
		if v := n.evaluate(t, pe); v.RuleID != "S-794" {
			t.Fatalf("%q: verdict %+v (security %+v), want S-794", line, v, pe.Security)
		}
	}
}

// TestHookKeepsPushDefaultOnFutureHead (SEC-GATE5 follow-up to merge
// finding F7): a HEAD write in the future is clamped the way the daemon
// clamps it, so the hook keeps the signed default push remote; a HEAD
// written after the posture but not in the future still drops it.
func TestHookKeepsPushDefaultOnFutureHead(t *testing.T) {
	issued := time.Now().Add(-time.Minute)
	reading := secposture.Reading{File: &secposture.File{IssuedAt: issued}}
	for _, tc := range []struct {
		name string
		head time.Time
		want string
	}{
		{"HEAD written an hour in the future", time.Now().Add(time.Hour), "origin"},
		{"HEAD written after the posture, not in the future", issued.Add(time.Second), ""},
		{"HEAD written before the posture", issued.Add(-time.Second), "origin"},
	} {
		old := hookHeadWrite
		hookHeadWrite = func(string) (time.Time, bool) { return tc.head, true }
		got := hookDropStalePushDefault(policy.Security{DefaultPushRemote: "origin"}, reading, "/r").DefaultPushRemote
		hookHeadWrite = old
		if got != tc.want {
			t.Errorf("%s: default %q, want %q", tc.name, got, tc.want)
		}
	}
	// The one clamp both sides share.
	now := time.Now()
	future := now.Add(time.Hour)
	if got := clampFutureHeadWrite(future, now, now); !got.After(future) {
		t.Fatalf("clamp of a future write: %v, want just after %v", got, future)
	}
	if got := clampFutureHeadWrite(now.Add(time.Second), now, now); !got.Equal(now) {
		t.Fatalf("a write within the margin: %v, want %v unchanged", got, now)
	}
}
