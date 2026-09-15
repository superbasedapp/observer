package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// childpath.go is the ONE place the daemon widens a child process's PATH
// (audit DI-04b). It exists because resolution and execution used different
// PATH authorities: internal/toolresolve resolves a tool over the MERGED PATH
// (the daemon's process PATH plus the login shell's), while every spawn handed
// the child the daemon's own os.Environ() untouched. A binary found only via
// the login PATH therefore starts and then dies at runtime — an npm shim whose
// `#!/usr/bin/env node` interpreter is not on the daemon's PATH exits 127 with
// `env: 'node': No such file or directory`, which the daemon cannot see at
// Start().
//
// The widening is ADDITIVE (CLAUDE.md #6): every entry of the daemon's own PATH
// survives, in order, after the dirs we prepend. The precedent for a daemon
// layering env onto a child is applyAgentRuntimeEnv (cmd/observer/launch.go);
// like it, this helper is pure, injectable and no-ops when it has nothing
// grounded to add.

// childPATH composes the PATH value a daemon-spawned child gets, in priority
// order:
//
//  1. binDir — the directory of the resolved binary. A node shim's interpreter
//     usually sits NEXT TO it (`<npm prefix>/bin/node` beside
//     `<npm prefix>/bin/codex`), so this one dir fixes the common case with no
//     login-shell knowledge at all.
//  2. loginDirs — the login-only merged-PATH dirs
//     (toolresolve.Resolution.LoginOnlyDirs / MergedPathDirs). This is the
//     `npm install --prefix ~/.local` case, where the shim lands in
//     ~/.local/bin but node lives in the version manager's own dir.
//  3. processPath — the daemon's own PATH, unchanged and in order.
//
// Empty and RELATIVE entries are dropped from the composed value (absoluteness
// judged by the HOST's path rules — the only ones the child's exec will use): a relative
// PATH entry resolves against the child's working directory (which the daemon
// chose, not the operator), and an empty entry means "the current directory" on
// POSIX — neither is something the daemon should hand a child. Duplicates are
// dropped keeping the FIRST occurrence, so the prepended dirs win.
func childPATH(processPath, loginDirs []string, binDir string) string {
	return childPATHFor(runtime.GOOS, processPath, loginDirs, binDir)
}

// childPATHFor is childPATH with the OS injected so both dedup regimes are
// table-testable from either host. Branching on goos here is a PLATFORM
// CAPABILITY test (how the OS matches a PATH entry), not a tool or caller
// identity (CLAUDE.md #3): POSIX exec compares path bytes exactly, while
// Windows path matching is case-insensitive, so `C:\Node` and `c:\node` are one
// dir there and two dirs here.
func childPATHFor(goos string, processPath, loginDirs []string, binDir string) string {
	ordered := make([]string, 0, len(processPath)+len(loginDirs)+1)
	ordered = append(ordered, binDir)
	ordered = append(ordered, loginDirs...)
	ordered = append(ordered, processPath...)

	out := make([]string, 0, len(ordered))
	seen := make(map[string]bool, len(ordered))
	for _, dir := range ordered {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		key := dir
		if goos == "windows" {
			key = strings.ToLower(dir)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, dir)
	}
	return strings.Join(out, string(os.PathListSeparator))
}

// applyChildPATH returns env with its PATH entry replaced by childPATH's
// composition. It is the single seam every daemon spawn path funnels through
// (launchChildEnv, setupChildEnvFor, runEnvLauncher).
//
// binPath is a FILE path (the resolved binary); its directory is what gets
// prepended. An existing PATH entry is rewritten IN PLACE keeping its original
// key spelling — on Windows the daemon's block says `Path=`, and appending a
// second `PATH=` would create exactly the case-duplicate dedupEnvWindows exists
// to clean up. When env carries no PATH at all, one is appended.
//
// It is a strict no-op (env returned unchanged) when there is nothing grounded
// to add: no login-only dirs AND no binary directory. That keeps every launch
// on a daemon whose PATH is already complete byte-identical to before this
// helper existed.
func applyChildPATH(env []string, loginDirs []string, binPath string) []string {
	binDir := ""
	if b := strings.TrimSpace(binPath); b != "" {
		if d := filepath.Dir(b); d != "." && d != string(filepath.Separator) {
			binDir = d
		}
	}
	if binDir == "" && len(loginDirs) == 0 {
		return env
	}

	// Last-wins, matching exec's own resolution of a duplicated key.
	idx, key, cur := -1, "", ""
	for i, kv := range env {
		j := strings.IndexByte(kv, '=')
		if j <= 0 {
			continue
		}
		if isPathKey(kv[:j]) {
			idx, key, cur = i, kv[:j], kv[j+1:]
		}
	}

	next := childPATH(filepath.SplitList(cur), loginDirs, binDir)
	if next == "" {
		return env
	}
	out := make([]string, len(env), len(env)+1)
	copy(out, env)
	if idx >= 0 {
		out[idx] = key + "=" + next
		return out
	}
	return append(out, "PATH="+next)
}

// isPathKey reports whether an env key names the PATH variable. Windows env
// keys are case-insensitive (`Path`), POSIX ones are not — but a POSIX daemon
// never carries a `Path=` entry, so matching case-insensitively everywhere
// costs nothing and keeps the helper OS-independent.
func isPathKey(key string) bool { return strings.EqualFold(key, "PATH") }

// daemonLoginPathDirs returns the login-only merged-PATH dirs a daemon-spawned
// child should inherit — the same subset internal/toolresolve used to RESOLVE
// the binary, so resolution and execution finally agree on one PATH authority
// (DI-04).
//
// It is memoized for the life of the process (a package var so a test can
// substitute a fake and restore it in a defer). Deliberately NOT the dashboard's
// TTL-rebuilt env (dashResolveEnv): a rebuild pays a fresh login-shell capture
// (up to 3s per attempt, two attempts for bash/zsh), and a spawn must not
// inherit that stall. The login-only dirs are a property of the operator's shell
// profile, not of a moment in time; a dir that appears mid-process is the
// preflight's problem (which does rebuild), not the launcher's.
//
// It is empty on a Windows daemon, where toolresolve leaves Env.LoginPath nil
// (no POSIX login shell is the PATH authority) — so every Windows launch is a
// no-op unless a caller supplies a binary path.
var daemonLoginPathDirs = sync.OnceValue(func() []string {
	_, login := toolresolve.MergedPathDirs(resolveEnv())
	return login
})

// launchLoginPathDirs picks the login-only dirs for one launch: the ones the
// caller resolved for this specific tool when it has them (termsvc.
// LaunchRequest.LoginPathDirs, filled from the toolresolve Resolution at the
// launch decision point), else the daemon-wide set. Both are the same merge —
// the per-request value simply reflects the Env the resolution actually used.
func launchLoginPathDirs(reqDirs []string) []string {
	if len(reqDirs) > 0 {
		return reqDirs
	}
	return daemonLoginPathDirs()
}
