// Package service renders the systemd unit that supervises
// `observer start` and builds the systemctl/journalctl argv that the
// `observer service` command runs.
//
// It is a pure-logic package per the CLAUDE.md module rules: string
// rendering + argv construction only — no exec, no file I/O, no
// database/sql, net/http, or fsnotify. The cmd layer
// (cmd/observer/service.go) performs systemd detection, unit-file
// writes, and process execution against these results, so the
// rendering and command-shape logic stays unit-testable in isolation.
package service

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Scope selects the systemd manager: per-user (no root, tied to a login
// session) or system-wide (survives logout, requires root).
type Scope string

const (
	// ScopeUser installs under the calling user's systemd --user
	// manager (~/.config/systemd/user/). Default for `observer service`.
	ScopeUser Scope = "user"
	// ScopeSystem installs a system unit (/etc/systemd/system/),
	// requires root, and survives logout — the right choice for a
	// headless worker box (e.g. a Vultr node running as root).
	ScopeSystem Scope = "system"
)

// UnitName is the canonical systemd unit name for the observer daemon.
const UnitName = "observer.service"

// UnitOptions describes how to render the unit file.
type UnitOptions struct {
	// ExecPath is the absolute path to the observer binary.
	ExecPath string
	// Args are appended after "start" in ExecStart (e.g. the
	// --config/--recipe/--port the operator installed with), so the
	// service uses the same configuration the install command saw.
	Args []string
	// Scope selects the [Install] WantedBy target.
	Scope Scope
	// WorkingDir, when set, becomes WorkingDirectory=.
	WorkingDir string
	// Env adds extra Environment= lines (rendered sorted for a
	// deterministic unit file). PATH is always set to a sane default.
	Env map[string]string
	// Path, when non-empty, becomes the unit's Environment=PATH= value —
	// normally the caller's merged (process + login-shell) PATH from
	// toolresolve.MergedPathDirs, joined with ":". A colon-joined string
	// rather than a []string keeps this package's only PATH-shaped
	// input symmetric with the systemd Environment= line it renders,
	// and lets a caller that has nothing to report (a failed capture)
	// pass "" and get DefaultPath instead of an empty/malformed line.
	Path string
}

// DefaultPath is systemd's own manager default and the fallback used when
// UnitOptions.Path is empty. It has no ~/.local/bin, no npm global-prefix
// bin dir, and no version-manager shims, so a daemon started under it
// cannot see the operator's npm-installed AI-tool binaries (the DI-04/
// DI-23 class of bug — see docs/plans/dashboard-install-gap-remediation-
// research-2026-09-02.md §4.4). Callers should prefer populating
// UnitOptions.Path from toolresolve.MergedPathDirs; this constant is only
// the last-resort fallback when that capture returns nothing.
const DefaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// RenderUnit renders the systemd service unit text for opts. The output
// is deterministic (Env keys are sorted) so a re-install with identical
// inputs produces a byte-identical unit and tests can golden it.
func RenderUnit(opts UnitOptions) string {
	wantedBy := "multi-user.target"
	if opts.Scope == ScopeUser {
		wantedBy = "default.target"
	}

	execStart := shellJoin(append([]string{opts.ExecPath, "start"}, opts.Args...))

	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=SuperBased Observer (proxy + watcher + dashboard)\n")
	b.WriteString("After=network.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + execStart + "\n")
	// on-failure, not always: systemd excludes SIGTERM from what counts as
	// a "failure" restart trigger (systemd.service(5)), so this unit does
	// NOT relaunch itself during scripts/restart-daemon.sh's deliberate
	// graceful `kill -TERM` down-window — the script's own relaunch owns
	// that transition. `always` fought the script: systemd would race it
	// back onto :8820 mid-restart, and the two relaunches collided.
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=3\n")
	path := opts.Path
	if path == "" {
		path = DefaultPath
	}
	// Quote the WHOLE assignment: systemd word-splits an unquoted Environment=
	// value, so a merged PATH carrying a spaced dir (WSL: /mnt/c/Program Files/...)
	// would be truncated at the space and reintroduce the exit-127 class this
	// line exists to close (review F2, 2026-09-03).
	b.WriteString("Environment=\"PATH=" + path + "\"\n")

	keys := make([]string, 0, len(opts.Env))
	for k := range opts.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("Environment=" + k + "=" + opts.Env[k] + "\n")
	}

	if opts.WorkingDir != "" {
		b.WriteString("WorkingDirectory=" + opts.WorkingDir + "\n")
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=" + wantedBy + "\n")
	return b.String()
}

// UnitPath returns the on-disk path for the unit at the given scope.
// home is required for user scope (the unit lands under
// ~/.config/systemd/user/); system scope is /etc/systemd/system/.
func UnitPath(scope Scope, home string) string {
	if scope == ScopeUser {
		return filepath.Join(home, ".config", "systemd", "user", UnitName)
	}
	return filepath.Join("/etc/systemd/system", UnitName)
}

// Command is a resolved external command (program + argv) for the cmd
// layer to exec.
type Command struct {
	Name string
	Args []string
}

// Systemctl builds a `systemctl [--user] <args...>` command, injecting
// --user for user scope so a single call site handles both managers.
func Systemctl(scope Scope, args ...string) Command {
	full := make([]string, 0, len(args)+1)
	if scope == ScopeUser {
		full = append(full, "--user")
	}
	full = append(full, args...)
	return Command{Name: "systemctl", Args: full}
}

// Journalctl builds a `journalctl [--user] -u observer.service` command.
// follow adds -f (live tail); otherwise, when lines > 0, it adds
// -n <lines>.
func Journalctl(scope Scope, follow bool, lines int) Command {
	args := make([]string, 0, 6)
	if scope == ScopeUser {
		args = append(args, "--user")
	}
	args = append(args, "-u", UnitName)
	switch {
	case follow:
		args = append(args, "-f")
	case lines > 0:
		args = append(args, "-n", strconv.Itoa(lines))
	}
	return Command{Name: "journalctl", Args: args}
}

// shellJoin joins argv into a systemd ExecStart string, double-quoting
// any element containing whitespace or a quote (systemd honors
// POSIX-style quoting in ExecStart). Internal double-quotes are
// backslash-escaped. This keeps a --config path with a space in it
// from splitting into two ExecStart arguments.
func shellJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		if strings.ContainsAny(a, " \t\"") {
			parts[i] = "\"" + strings.ReplaceAll(a, "\"", "\\\"") + "\""
		} else {
			parts[i] = a
		}
	}
	return strings.Join(parts, " ")
}
