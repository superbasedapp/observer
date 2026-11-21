package policy

import (
	"testing"
	"time"
)

// TestRepoRootDestructiveArms is surface-gap FU-101 (built as
// 833a533406, re-scoped onto Event.RepoRoot by the 2026-11-08 operator
// ruling): a pre-tool hook carries only cwd, so its event has no
// ProjectRoot, and the hook stamps the git checkout around cwd as RepoRoot
// (D-MU10). R-101's outside-the-project arms already read it; R-102 and
// R-141's chown arm now read it too, through deleteProjectRoot, and the
// bridge case (the IBM Bob IDE on Windows, whose PreToolUse hook runs on a
// WSL daemon through the wsl.exe bridge, deleting `C:\x` from `d:\sbo-lc`)
// compares the Windows target with the `/mnt/d/...` checkout through the
// drvfs fold.
//
// Each row runs three ways: with the root as RepoRoot (the hook path), with
// the same root as ProjectRoot (the watcher path), which must agree, and
// with neither, which must keep the no-root hook verdict.
func TestRepoRootDestructiveArms(t *testing.T) {
	t.Parallel()
	const (
		bridgeHome = "/home/u"    // the Linux receiver's own home on the bridge
		winHome    = `C:\Users\u` // a native Windows receiver
	)
	cases := []struct {
		name         string
		cmd          string
		dialect      Dialect
		altDialect   Dialect // the second reading of an unstated shell
		home, cwd    string
		root         string
		wantRule     string   // "" = no hit
		wantEnforce  Decision // checked when wantRule != ""
		withoutRoot  string   // the rule hit with no root at all ("" = none)
		writeEvent   bool     // a file write event instead of a shell command
		writeTarget  string
		otherProject string // ProjectRoot set beside RepoRoot
	}{
		// --- the bridge: Windows cwd, the root in the WSL store spelling ---
		{
			name: "bridge: Windows target outside the project denies", cmd: `Remove-Item -Recurse -Force C:\sbo-x`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "bridge: other directory on the same drive denies", cmd: `Remove-Item -Recurse -Force D:\sbo-other`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "bridge: Windows target inside the project", cmd: `Remove-Item -Recurse -Force D:\sbo-lc\x`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc",
		},
		{
			name: "bridge: drive letter case does not matter", cmd: `Remove-Item -Recurse -Force d:\SBO-LC\build`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `D:\sbo-lc`, root: "/mnt/d/sbo-lc",
		},
		{
			name: "bridge: relative target resolves inside", cmd: `Remove-Item -Recurse -Force build`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc\src`, root: "/mnt/d/sbo-lc",
		},
		{
			name: "bridge: relative escape leaves the project", cmd: `Remove-Item -Recurse -Force ..\..\sbo-other`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc\src`, root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "bridge: drvfs cwd and root, Windows target outside", cmd: `Remove-Item -Recurse -Force C:\x`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: "/mnt/d/sbo-lc", root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "bridge: drvfs root, Windows target inside", cmd: `Remove-Item -Recurse -Force D:\sbo-lc\x`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: "/mnt/d/sbo-lc", root: "/mnt/d/sbo-lc",
		},
		{
			name: "bridge: catastrophic arm unchanged", cmd: `Remove-Item -Recurse -Force C:\`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny, withoutRoot: "R-101",
		},
		{
			// A UNC share normalizes lexically to a POSIX-shaped path
			// (`/server/share/x`), which a drvfs root compares with: outside,
			// exactly as with ProjectRoot (the watcher's verdict).
			name: "bridge: UNC target against a drvfs root, as with ProjectRoot", cmd: `Remove-Item -Recurse -Force \\server\share\x`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			// Against a drive root a UNC share is outside the project too,
			// as with ProjectRoot (the release line's comparison; FU-101's
			// base still read this pair as unknown).
			name: "windows: UNC target against a drive root denies, as with ProjectRoot", cmd: `Remove-Item -Recurse -Force \\server\share\x`, dialect: DialectPowerShell,
			home: winHome, cwd: `d:\sbo-lc`, root: `D:\sbo-lc`, wantRule: "R-101", wantEnforce: DecisionDeny,
		},

		// --- an unstated Windows shell (Bob's execute_command): posix and
		// PowerShell readings, a hit in either counts. The posix reading
		// eats the backslashes (`d:\sbo-lc\build` -> `d:sbo-lcbuild`, a
		// drive-relative path), which is unknown, never outside. ---
		{
			name: "unstated shell: Windows target outside denies", cmd: `Remove-Item -Recurse -Force C:\sbo-x`, altDialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "unstated shell: absolute target inside passes", cmd: `Remove-Item -Recurse -Force d:\sbo-lc\build`, altDialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc",
		},
		{
			// Read once, the drive-relative leftover keeps the drive-rooted
			// best effort (the watcher's verdict too).
			name: "posix-only reading keeps the drive-rooted best effort", cmd: `rm -rf D:\sbo-lc\build`, dialect: DialectPosix,
			home: winHome, cwd: `d:\sbo-lc`, root: `D:\sbo-lc`, wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "bridge: drvfs cwd, unstated shell read once, Windows target outside", cmd: `Remove-Item -Recurse -Force C:\sbo-x`,
			home: bridgeHome, cwd: "/mnt/d/sbo-lc", root: "/mnt/d/sbo-lc", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "posix forward-slash drive path outside still denies", cmd: `rm -rf C:/sbo-x`, dialect: DialectPosix,
			home: winHome, cwd: `d:\sbo-lc`, root: `D:\sbo-lc`, wantRule: "R-101", wantEnforce: DecisionDeny,
		},

		// --- native Windows: both sides in the Windows flavor ---
		{
			name: "windows: target outside the project denies", cmd: `Remove-Item -Recurse -Force C:\sbo-x`, dialect: DialectPowerShell,
			home: winHome, cwd: `d:\sbo-lc`, root: `D:\sbo-lc`, wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "windows: target inside the project", cmd: `Remove-Item -Recurse -Force d:\sbo-lc\build`, dialect: DialectPowerShell,
			home: winHome, cwd: `d:\sbo-lc`, root: `D:\sbo-lc`,
		},
		{
			name: "windows: cmd rd inside, upper-case drive", cmd: `rd /s /q D:\SBO-LC\build`, dialect: DialectCmd,
			home: winHome, cwd: `d:\sbo-lc`, root: `D:\sbo-lc`,
		},
		{
			name: "windows: cmd rd outside", cmd: `rd /s /q C:\sbo-x`, dialect: DialectCmd,
			home: winHome, cwd: `d:\sbo-lc`, root: `D:\sbo-lc`, wantRule: "R-101", wantEnforce: DecisionDeny,
		},

		// --- native Linux ---
		{
			name: "linux: outside the project denies", cmd: "rm -rf /etc/nginx",
			home: "/home/u", cwd: "/home/u/proj/sub", root: "/home/u/proj", wantRule: "R-101", wantEnforce: DecisionDeny,
		},
		{
			name: "linux: subdirectory sibling stays inside the repository", cmd: "rm -rf ../other",
			home: "/home/u", cwd: "/home/u/proj/sub", root: "/home/u/proj",
		},
		{
			name: "linux: cross-flavor target is unknown", cmd: `rm -rf C:\x`,
			home: "/home/u", cwd: "/home/u/proj", root: "/home/u/proj",
		},

		// --- the other destructive arms that now read the root ---
		{
			name: "R-102: .git of the repository asks", cmd: "rm -rf ../.git",
			home: "/home/u", cwd: "/home/u/proj/sub", root: "/home/u/proj", wantRule: "R-102", wantEnforce: DecisionAsk,
		},
		{
			name: "R-102: bridge, the project root itself asks", cmd: `Remove-Item -Recurse -Force D:\sbo-lc`, dialect: DialectPowerShell,
			home: bridgeHome, cwd: `d:\sbo-lc`, root: "/mnt/d/sbo-lc", wantRule: "R-102", wantEnforce: DecisionAsk,
		},
		{
			name: "R-141: chown -R outside the project", cmd: "chown -R u /srv/data",
			home: "/home/u", cwd: "/home/u/proj", root: "/home/u/proj", wantRule: "R-141", wantEnforce: DecisionAsk,
		},
		{
			name: "R-141: chown -R inside the project", cmd: "chown -R u ./data",
			home: "/home/u", cwd: "/home/u/proj", root: "/home/u/proj",
		},
		{
			name: "same-command link arm reads the root", cmd: "ln -s /srv/data d && rm -rf d/x",
			home: "/home/u", cwd: "/home/u/proj", root: "/home/u/proj", wantRule: "R-101", wantEnforce: DecisionDeny,
		},

		// --- audit H1 stays closed: RepoRoot is the CHECKOUT, so in a
		// linked worktree that lives outside its main repository
		// (/home/u/wt over /home/u/main) the worktree is its own tree for
		// R-101, R-102 and R-141 alike. ---
		{
			name: "H1: linked worktree, delete inside the checkout passes", cmd: "rm -rf build",
			home: "/home/u", cwd: "/home/u/wt", root: "/home/u/wt",
		},
		{
			name: "H1: linked worktree, chown -R inside the checkout passes", cmd: "chown -R u ./build",
			home: "/home/u", cwd: "/home/u/wt", root: "/home/u/wt",
		},
		{
			name: "H1: linked worktree, the checkout's own root asks", cmd: "rm -rf /home/u/wt",
			home: "/home/u", cwd: "/home/u/wt", root: "/home/u/wt", wantRule: "R-102", wantEnforce: DecisionAsk, withoutRoot: "R-101",
		},
		{
			name: "H1: linked worktree, the main repository is outside the checkout", cmd: "rm -rf /home/u/main/.git",
			home: "/home/u", cwd: "/home/u/wt", root: "/home/u/wt", wantRule: "R-101", wantEnforce: DecisionDeny,
		},

		// --- the scope: the boundary rules never read RepoRoot ---
		{
			name: "R-150 stays inert on the repo root", writeEvent: true, writeTarget: "/srv/out.txt",
			home: "/home/u", cwd: "/home/u/proj", root: "/home/u/proj",
		},
		{
			name: "ProjectRoot wins over the repo root", cmd: "rm -rf /home/u/other/build",
			home: "/home/u", cwd: "/home/u/other", root: "/home/u/proj", otherProject: "/home/u/other",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			eng, err := New(Config{Mode: ModeEnforce, Home: tc.home})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			base := Event{
				Kind: KindShellExec, ActionType: "run_command", Target: tc.cmd, Dialect: tc.dialect, AltDialect: tc.altDialect,
				Cwd: tc.cwd, SessionID: "s1", Now: time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC),
			}
			if tc.writeEvent {
				base.Kind, base.ActionType, base.Target, base.Dialect = KindFileAccess, "write_file", tc.writeTarget, ""
			}
			gate := base
			gate.RepoRoot, gate.ProjectRoot = tc.root, tc.otherProject
			got := eng.Evaluate(gate)
			if tc.wantRule == "" {
				if got.RuleID != "" {
					t.Fatalf("repo root: want no hit, got %s/%s (%q)", got.RuleID, got.Decision, got.Reason)
				}
			} else if got.RuleID != tc.wantRule || got.Decision != tc.wantEnforce {
				t.Fatalf("repo root: got %s/%s (%q), want %s/%s", got.RuleID, got.Decision, got.Reason, tc.wantRule, tc.wantEnforce)
			}
			if tc.otherProject == "" && !tc.writeEvent {
				watcher := base
				watcher.ProjectRoot = tc.root
				if w := eng.Evaluate(watcher); w.RuleID != got.RuleID || w.Decision != got.Decision {
					t.Errorf("ProjectRoot verdict %s/%s differs from the repo root verdict %s/%s", w.RuleID, w.Decision, got.RuleID, got.Decision)
				}
			}
			if none := eng.Evaluate(base); none.RuleID != tc.withoutRoot {
				t.Errorf("no root: got %s/%s (%q), want rule %q (the no-root hook verdict)", none.RuleID, none.Decision, none.Reason, tc.withoutRoot)
			}
		})
	}
}

// TestIsDriveRelative pins the drive-relative shape the unstated-shell
// calibration skips (FU-101).
func TestIsDriveRelative(t *testing.T) {
	t.Parallel()
	for p, want := range map[string]bool{
		"d:foo": true, "C:": true, `d:sbo-lcbuild`: true,
		`d:\foo`: false, "d:/foo": false, "/mnt/d": false, "foo": false, "1:x": false, "": false,
	} {
		if got := isDriveRelative(p); got != want {
			t.Errorf("isDriveRelative(%q) = %v, want %v", p, got, want)
		}
	}
}
