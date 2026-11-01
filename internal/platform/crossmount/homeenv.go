package crossmount

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// # The pinned-home environment rule (R-188 F1, plans ruling P-182)
//
// Every writer that resolves a tool's config file under a home also reads
// the relocation variables the tool honours (CLAUDE_CONFIG_DIR, CODEX_HOME,
// CLINE_DIR, XDG_CONFIG_HOME and the rest of agentconfig's relocation
// table). Those variables belong to the account's real home: a caller that
// pinned a home (a test, a sandboxed dashboard) or a process whose home is
// isolated from the real one (IsolationReason: `HOME=/tmp/x observer init`)
// must resolve every file under that home, or the hooks land in the
// developer's real settings.json while the proxy route goes under the
// scratch home (the LEFT2 rule, the Cline A2 precedent).
//
// This file is the one place that rule lives. hook.NewRegistry,
// mcpregister.NewRegistrar, clientwire.NewRemover, proxyroute.NewRegistrar,
// the doctor and the other home-resolving constructors apply HomeEnv to a
// nil Getenv, proxyroute's inspectors apply HomeEnvAt, and the cmd/observer
// callers pass nil, never os.Getenv.

// NoEnv reads no environment variable: every lookup is "".
func NoEnv(string) string { return "" }

// HomeEnv returns the environment lookup of a home-resolving constructor.
// getenv, when non-nil, is the caller's own injected lookup and is returned
// as is. A nil getenv is the process environment (os.Getenv) only when the
// home is not pinned and the process home is not isolated
// (IsolationReason() == ""), and NoEnv otherwise. pinnedHome is the home the
// caller named, verbatim, before any default: "" is not pinned, anything
// else is.
func HomeEnv(pinnedHome string, getenv func(string) string) func(string) string {
	return homeEnv(pinnedHome != "", getenv)
}

// HomeEnvAt is HomeEnv for a caller that always names the home it reads (a
// route inspector): home counts as pinned unless it is this process's own
// home (os.UserHomeDir), so an inspection of the own home reads the files a
// constructor with no pinned home writes.
func HomeEnvAt(home string, getenv func(string) string) func(string) string {
	own, err := os.UserHomeDir()
	if err != nil {
		own = ""
	}
	return homeEnv(namedHomePinned(home, own), getenv)
}

// homeEnv applies the rule to an already decided pinned flag.
func homeEnv(pinned bool, getenv func(string) string) func(string) string {
	if getenv != nil {
		return getenv
	}
	if homeEnvFollowsProcess(pinned, IsolationReason()) {
		return os.Getenv
	}
	return NoEnv
}

// homeEnvFollowsProcess is the pure decision behind HomeEnv, as an ordered
// rule table:
//
//  1. An isolated process (isolation != "") reads no variable.
//  2. A pinned home reads no variable.
//  3. Otherwise the process environment is read.
func homeEnvFollowsProcess(pinned bool, isolation string) bool {
	switch {
	case isolation != "":
		return false
	case pinned:
		return false
	}
	return true
}

// namedHomePinned is HomeEnvAt's pinned decision: a named home is pinned
// unless it is the process's own home; an unknown own home ("") pins every
// named home.
func namedHomePinned(home, ownHome string) bool {
	if ownHome == "" {
		return true
	}
	return !sameHomeDir(home, ownHome)
}

// sameHomeDir compares two directory paths after cleaning,
// case-insensitively on Windows.
func sameHomeDir(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
