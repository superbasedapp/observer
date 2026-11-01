package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/diag"
)

// migrationdefer.go: lane FIX-UPGRADE U3 (D-590). After `npm install -g` (or
// pip) replaces the binary, the CLI is the new version while the daemon is
// still the old one. Before this, `observer status` / `doctor` / `components
// status` migrated the database underneath that daemon. Now a CLI process
// leaves the schema alone while another observer process holds the database
// and says what to do instead; the daemon migrates at its next start.

// migrationCmdClass is how a top-level command relates to the database
// schema.
type migrationCmdClass int

const (
	// migrationCmdOther is every command not listed below: it defers.
	migrationCmdOther migrationCmdClass = iota
	// migrationCmdOwner runs (or replaces) the daemon that owns the DB.
	migrationCmdOwner
	// migrationCmdCapture is the hook path an AI tool spawns: it keeps
	// migrating as before, because a capture write must not fail against an
	// old schema and it has no terminal to explain itself on.
	migrationCmdCapture
)

// migrationCmdClasses maps a top-level command name to its class; a name
// that is absent is migrationCmdOther.
var migrationCmdClasses = map[string]migrationCmdClass{
	"start":   migrationCmdOwner,
	"watch":   migrationCmdOwner,
	"proxy":   migrationCmdOwner,
	"update":  migrationCmdOwner,
	"hook":    migrationCmdCapture,
	"browser": migrationCmdCapture,
	"serve":   migrationCmdCapture,
}

// migrationDeferRule is one row of the deferral table.
type migrationDeferRule struct {
	name    string
	deferIt bool
	match   func(class migrationCmdClass, otherDaemon bool) bool
}

// migrationDeferRules is walked top-down; the first match decides.
var migrationDeferRules = []migrationDeferRule{
	{name: "owner", deferIt: false, match: func(c migrationCmdClass, _ bool) bool { return c == migrationCmdOwner }},
	{name: "capture", deferIt: false, match: func(c migrationCmdClass, _ bool) bool { return c == migrationCmdCapture }},
	{name: "no-daemon", deferIt: false, match: func(_ migrationCmdClass, other bool) bool { return !other }},
	{name: "daemon-owns-db", deferIt: true, match: func(migrationCmdClass, bool) bool { return true }},
}

// decideMigrationDefer returns whether to defer and the deciding rule.
func decideMigrationDefer(class migrationCmdClass, otherDaemon bool) (bool, string) {
	for _, r := range migrationDeferRules {
		if r.match(class, otherDaemon) {
			return r.deferIt, r.name
		}
	}
	return false, ""
}

// topLevelCommandName is the root child the argv resolves to ("" for the
// bare root or an unknown command).
func topLevelCommandName(root *cobra.Command, args []string) string {
	c, _, err := root.Find(args)
	if err != nil || c == nil {
		return ""
	}
	for c.HasParent() && c.Parent() != root {
		c = c.Parent()
	}
	if c == root {
		return ""
	}
	return c.Name()
}

// installMigrationDeferral installs the process's db.MigrationDeferral for
// the command argv names. Notices go to w (stderr), once per database.
func installMigrationDeferral(root *cobra.Command, args []string, w io.Writer) {
	name := topLevelCommandName(root, args)
	class := migrationCmdClasses[name]
	if class == migrationCmdOther && (isLauncherVerb(name) || name == "ide") {
		// A launcher starts an AI session: like a hook it keeps migrating,
		// so a session never fails to start against an old schema.
		class = migrationCmdCapture
	}
	self := os.Getpid()
	var once sync.Map
	db.SetMigrationDeferral(func(path string, applied, latest int, pending []int) bool {
		locks, _ := diag.LiveLocks(filepath.Dir(path))
		var holder *diag.LockInfo
		for i := range locks {
			l := locks[i]
			if l.PID == self {
				continue
			}
			if l.DBPath != "" && filepath.Clean(l.DBPath) != filepath.Clean(path) {
				continue
			}
			holder = &l
			break
		}
		deferIt, _ := decideMigrationDefer(class, holder != nil)
		if !deferIt {
			return false
		}
		if _, seen := once.LoadOrStore(path, true); !seen {
			fmt.Fprint(w, migrationDeferNotice(*holder, applied, latest, pending, version))
		}
		return true
	})
}

// migrationDeferNotice is the one message a deferring command prints. When
// every pending step sits at or below the daemon's schema version (late
// steps, T-979), comparing the two versions would read "schema N ... schema
// N", so the first line names the pending steps instead.
func migrationDeferNotice(holder diag.LockInfo, applied, latest int, pending []int, cliVersion string) string {
	who := fmt.Sprintf("an older build (pid %d)", holder.PID)
	if holder.Version != "" {
		who = fmt.Sprintf("v%s (pid %d)", strings.TrimPrefix(holder.Version, "v"), holder.PID)
	}
	cli := strings.TrimPrefix(cliVersion, "v")
	first := fmt.Sprintf("observer: the running daemon is %s on schema %d; this observer is v%s (schema %d).\n", who, applied, cli, latest)
	if len(pending) > 0 && applied >= latest {
		steps := make([]string, len(pending))
		for i, v := range pending {
			steps[i] = strconv.Itoa(v)
		}
		first = fmt.Sprintf("observer: this observer (v%s) has %d pending database step(s) (%s) that the running daemon, %s, has not run.\n",
			cli, len(pending), strings.Join(steps, ", "), who)
	}
	return first +
		"  Restart the daemon to finish the upgrade: it migrates the database when it starts.\n" +
		"  Turn any proxy route off first if a live AI session uses it (docs/daemon-restart-runbook.md).\n" +
		"  This command read the database without migrating it, so newer fields may be missing.\n"
}

// isLauncherVerb reports whether name is one of the per-tool launcher verbs
// (launchers.go).
func isLauncherVerb(name string) bool {
	if name == "" {
		return false
	}
	for _, mk := range launcherCommands {
		if mk().Name() == name {
			return true
		}
	}
	return false
}
