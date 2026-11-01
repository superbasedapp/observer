package policy

import (
	"reflect"
	"testing"
)

// TestGitWriteLocationsAltDialect (merge finding F1 of lane SEC-GATE5): a
// host that states no shell on a Windows working directory (Codex, Copilot
// CLI) gets the PowerShell reading as well, so a directory move only
// PowerShell sees places the write in the other repository; the plain
// commit in the session's own repository is unchanged.
func TestGitWriteLocationsAltDialect(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"Set-Location", `Set-Location C:\elsewhere; git commit -m x`},
		{"sl", `sl C:\elsewhere; git commit -m x`},
		{"cd", `cd C:\elsewhere; git commit -m x`},
		{"Push-Location", `Push-Location C:\elsewhere; git commit -m x`},
		{"Set-Location -Path", `Set-Location -Path C:\elsewhere; git commit -m x`},
		{"Push-Location -Path", `Push-Location -Path C:\elsewhere; git push`},
	} {
		ev := &Event{Kind: KindShellExec, Target: tc.line, Cwd: `C:\work\repo`, AltDialect: DialectPowerShell}
		got := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
		if len(got) != 1 {
			t.Fatalf("%s: %d writes %+v, want 1", tc.name, len(got), got)
		}
		if !got[0].Unknown && !containsString(got[0].Dirs, "c:/elsewhere") {
			t.Errorf("%s: dirs %q, want c:/elsewhere among them", tc.name, got[0].Dirs)
		}
	}
	// A line only the PowerShell reading splits (`\;` escapes the
	// separator for POSIX, so the POSIX reading finds no write at all): the
	// write is found, and since the readings disagree it reads unknown.
	esc := &Event{Kind: KindShellExec, Target: `cd C:\elsewhere\; git commit -m x`, Cwd: `C:\work\repo`}
	if got := GitWriteLocations(&MatchContext{Event: esc, Cfg: &Config{}}); len(got) != 0 {
		t.Fatalf("POSIX reading alone: %+v, want no write (the case the second reading covers)", got)
	}
	esc.AltDialect = DialectPowerShell
	if got := GitWriteLocations(&MatchContext{Event: esc, Cfg: &Config{}}); len(got) != 1 || !got[0].Unknown {
		t.Fatalf("both readings: %+v, want one unknown write", got)
	}
	// A form the POSIX reading cannot place but PowerShell can stays
	// unknown (most restrictive), with the PowerShell place listed.
	path := &Event{Kind: KindShellExec, Target: `Set-Location -Path C:\elsewhere; git commit -m x`, Cwd: `C:\work\repo`, AltDialect: DialectPowerShell}
	if got := GitWriteLocations(&MatchContext{Event: path, Cfg: &Config{}}); len(got) != 1 || !got[0].Unknown || !containsString(got[0].Dirs, "c:/elsewhere") {
		t.Fatalf("-Path: %+v, want unknown with c:/elsewhere listed", got)
	}
	for _, line := range []string{"git commit -m x", "git push"} {
		ev := &Event{Kind: KindShellExec, Target: line, Cwd: `C:\work\repo`, AltDialect: DialectPowerShell}
		got := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
		if len(got) != 1 || got[0].Unknown || !reflect.DeepEqual(got[0].Dirs, []string{"c:/work/repo"}) {
			t.Fatalf("own repository %q: %+v, want one placed write in c:/work/repo", line, got)
		}
	}
}

// TestMergeGitWriteReadings: the union of both readings' places, unknown
// when either is, and every write unknown when the readings disagree on
// how many writes the line holds.
func TestMergeGitWriteReadings(t *testing.T) {
	a := []GitWriteLocation{{Dirs: []string{"/r"}}}
	b := []GitWriteLocation{{Dirs: []string{"/o", "/r"}}}
	got := mergeGitWriteReadings(a, b)
	if len(got) != 1 || got[0].Unknown || !reflect.DeepEqual(got[0].Dirs, []string{"/r", "/o"}) {
		t.Fatalf("union: %+v", got)
	}
	got = mergeGitWriteReadings(a, []GitWriteLocation{{Unknown: true, UnknownVia: "x"}})
	if len(got) != 1 || !got[0].Unknown || !reflect.DeepEqual(got[0].Dirs, []string{"/r"}) {
		t.Fatalf("unknown in one reading: %+v", got)
	}
	got = mergeGitWriteReadings(a, append(b, GitWriteLocation{Dirs: []string{"/r"}}))
	if len(got) != 3 {
		t.Fatalf("disagreeing readings: %+v, want all three", got)
	}
	for _, l := range got {
		if !l.Unknown {
			t.Fatalf("disagreeing readings: %+v placed", l)
		}
	}
	if a[0].Dirs[0] != "/r" || len(a[0].Dirs) != 1 || a[0].Unknown {
		t.Fatalf("the input was modified: %+v", a)
	}
}

// TestGitWriteLocationsRedirects (merge finding F5): another index, common
// directory or work tree, or a linked worktree's own git directory, makes
// the write unknown; an unrelated `-c` does not.
func TestGitWriteLocationsRedirects(t *testing.T) {
	for _, tc := range []struct {
		line    string
		unknown bool
	}{
		{"GIT_INDEX_FILE=/tmp/idx git commit -m x", true},
		{"export GIT_INDEX_FILE=/tmp/idx; git commit -m x", true},
		{"GIT_COMMON_DIR=/o/.git git commit -m x", true},
		{"git -c core.worktree=/o commit -m x", true},
		{"git -c CORE.WORKTREE=/o commit -m x", true},
		{"git --config-env=core.worktree=WT commit -m x", true},
		{"git --git-dir=/o/.git/worktrees/wt commit -m x", true},
		{"git --git-dir /srv/bare.git/worktrees/wt commit -m x", true},
		{"GIT_DIR=/o/.git/worktrees/wt git commit -m x", true},
		{"git -c user.name=x commit -m x", false},
		{"git --git-dir=/o/.git commit -m x", false},
		{"git commit -m x", false},
	} {
		ev := &Event{Kind: KindShellExec, Target: tc.line, Cwd: "/repo", Dialect: DialectPosix}
		got := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
		if len(got) != 1 || got[0].Unknown != tc.unknown {
			t.Errorf("%q: %+v, want one write with unknown=%v", tc.line, got, tc.unknown)
		}
	}
}

// TestGitWriteLocationsNetworkPaths (merge finding F9): a `-C`, git
// directory or work tree the agent names on a UNC path or under a network
// or automount root is never listed (so the hook never stats it) and reads
// unknown; a place inside the event's own anchor on such a root, and an
// ordinary absolute path, are unchanged.
func TestGitWriteLocationsNetworkPaths(t *testing.T) {
	for _, tc := range []struct {
		line, cwd string
		dialect   Dialect
		unknown   bool
		dirs      []string
	}{
		{"git -C //host/share/r commit -m x", "/repo", DialectPosix, true, nil},
		{`git -C \\host\share\r commit -m x`, `C:\repo`, DialectPowerShell, true, nil},
		{"GIT_DIR=//host/share/r/.git git commit -m x", "/repo", DialectPosix, true, nil},
		{"git --git-dir=//host/share/r/.git commit -m x", "/repo", DialectPosix, true, nil},
		{"git --work-tree=//host/share/r commit -m x", "/repo", DialectPosix, true, []string{"/repo"}},
		{"git -C /net/host/r commit -m x", "/repo", DialectPosix, true, nil},
		{"git --git-dir=/afs/cell/r/.git commit -m x", "/repo", DialectPosix, true, nil},
		{"git -C /Network/Servers/h/r commit -m x", "/repo", DialectPosix, true, nil},
		{"git -C /misc/r push", "/repo", DialectPosix, true, nil},
		{"git -C sub commit -m x", "/net/h/repo", DialectPosix, false, []string{"/net/h/repo/sub"}},
		{"git -C /mnt/c/other commit -m x", "/repo", DialectPosix, false, []string{"/mnt/c/other"}},
	} {
		ev := &Event{Kind: KindShellExec, Target: tc.line, Cwd: tc.cwd, Dialect: tc.dialect}
		got := GitWriteLocations(&MatchContext{Event: ev, Cfg: &Config{}})
		if len(got) != 1 || got[0].Unknown != tc.unknown || !reflect.DeepEqual(got[0].Dirs, tc.dirs) {
			t.Errorf("%q in %s: %+v, want unknown=%v dirs %q", tc.line, tc.cwd, got, tc.unknown, tc.dirs)
		}
	}
}
