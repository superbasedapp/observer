package main

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/diag"
)

// TestDecideMigrationDeferTable is one case per row of migrationDeferRules
// (U3): only the daemon that owns the database, the capture path, or a
// process with no other daemon migrates.
func TestDecideMigrationDeferTable(t *testing.T) {
	cases := []struct {
		name    string
		class   migrationCmdClass
		other   bool
		deferIt bool
		rule    string
	}{
		{"start migrates even beside another daemon", migrationCmdOwner, true, false, "owner"},
		{"a hook migrates (capture path)", migrationCmdCapture, true, false, "capture"},
		{"status with no daemon migrates", migrationCmdOther, false, false, "no-daemon"},
		{"status beside a running daemon defers", migrationCmdOther, true, true, "daemon-owns-db"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, r := decideMigrationDefer(c.class, c.other)
			if d != c.deferIt || r != c.rule {
				t.Fatalf("decideMigrationDefer = (%v, %s), want (%v, %s)", d, r, c.deferIt, c.rule)
			}
		})
	}
}

// TestMigrationCmdClassOfRealCommands pins which real commands are owners,
// capture paths and (by default) deferring readers.
func TestMigrationCmdClassOfRealCommands(t *testing.T) {
	root := newRootCmd()
	for argv, want := range map[string]string{
		"status":                     "status",
		"doctor":                     "doctor",
		"components status":          "components",
		"start":                      "start",
		"hook claude-code post-tool": "hook",
	} {
		if got := topLevelCommandName(root, strings.Fields(argv)); got != want {
			t.Errorf("topLevelCommandName(%q) = %q, want %q", argv, got, want)
		}
	}
	if migrationCmdClasses["status"] != migrationCmdOther || migrationCmdClasses["doctor"] != migrationCmdOther {
		t.Error("status and doctor must defer beside a running daemon")
	}
	if migrationCmdClasses["start"] != migrationCmdOwner || migrationCmdClasses["hook"] != migrationCmdCapture {
		t.Error("start owns the schema; hook is the capture path")
	}
	if !isLauncherVerb("claude") || isLauncherVerb("status") {
		t.Error("isLauncherVerb")
	}
}

// TestMigrationDeferNotice pins the message: it names the daemon's version
// (or that it is older), both schema versions and the restart advice.
func TestMigrationDeferNotice(t *testing.T) {
	got := migrationDeferNotice(diag.LockInfo{PID: 42}, 147, 161, []int{148, 161}, "1.36.0")
	for _, want := range []string{"an older build (pid 42)", "schema 147", "v1.36.0 (schema 161)", "Restart the daemon to finish the upgrade", "route off first"} {
		if !strings.Contains(got, want) {
			t.Errorf("notice %q lacks %q", got, want)
		}
	}
	if got := migrationDeferNotice(diag.LockInfo{PID: 7, Version: "1.35.0"}, 157, 161, []int{161}, "1.36.0"); !strings.Contains(got, "v1.35.0 (pid 7)") {
		t.Errorf("notice %q does not name the daemon version", got)
	}
}

// TestMigrationDeferNoticeNamesLateSteps pins the late-step wording (T-979):
// when every pending step sits at or below the daemon's schema version, the
// notice names the steps instead of printing "schema N ... schema N".
func TestMigrationDeferNoticeNamesLateSteps(t *testing.T) {
	got := migrationDeferNotice(diag.LockInfo{PID: 9, Version: "1.36.0"}, 176, 176, []int{170}, "1.37.0")
	for _, want := range []string{
		"this observer (v1.37.0) has 1 pending database step(s) (170)",
		"the running daemon, v1.36.0 (pid 9), has not run",
		"Restart the daemon to finish the upgrade",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("notice %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "schema 176") {
		t.Errorf("notice %q compares two equal schema versions", got)
	}
}
