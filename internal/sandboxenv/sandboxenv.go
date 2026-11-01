package sandboxenv

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// EnvAllow is the variable a sandboxed launch's PTY child carries: the
// comma-separated NAMES (never values) of the tool's provider variables and
// the user's pass_env, which the box helper adds to the base table. The
// daemon and the CLI launcher set it at the launch and strip any inherited
// value first, so the developer's own environment cannot widen a box through
// it.
const EnvAllow = "OBSERVER_SANDBOX_ENV_ALLOW"

// EnvPassed carries the [terminal.sandbox].pass_env names alone (a subset of
// EnvAllow), so the launcher inside the box can show them in the run's
// posture.
const EnvPassed = "OBSERVER_SANDBOX_ENV_PASSED"

// EnvSignInShared names the tool (a registry id, never a value) whose own
// state, sign-in included, a bound backend shares with the box (operator
// ruling P-183), so the launcher inside the box says so on the run's
// terminal. The daemon and the CLI launcher set it at the launch and strip
// any inherited value first.
const EnvSignInShared = "OBSERVER_SANDBOX_SIGNIN_SHARED"

// Scope is the operating systems a base row applies to.
type Scope string

// The scopes.
const (
	// ScopeAll applies on every operating system.
	ScopeAll Scope = "all"
	// ScopePOSIX applies on Linux and macOS.
	ScopePOSIX Scope = "posix"
	// ScopeWindows applies on Windows.
	ScopeWindows Scope = "windows"
)

// Row is one variable of the base table and why a box may carry it.
type Row struct {
	Name  string
	Scope Scope
	Why   string
}

// baseTable is THE base allow-list, one test case per row. Every row is a
// location, a locale, a terminal capability or the account's name: nothing
// here is a credential. The temp variables are pointed at the run's own
// folder by the backends that have one (TMPDIR on Landlock and Seatbelt,
// TEMP and TMP on mxc-process).
var baseTable = []Row{
	{"PATH", ScopeAll, "where the tool and its commands are found"},
	{"HOME", ScopeAll, "the home the tool reads its own state from"},
	{"TERM", ScopeAll, "the terminal type"},
	{"COLORTERM", ScopeAll, "the terminal's colour support (the dashboard terminal sets it)"},
	{"LANG", ScopeAll, "the locale"},
	{"LC_ALL", ScopeAll, "the locale"},
	{"LC_CTYPE", ScopeAll, "the character set (macOS terminals set only this one)"},
	{"TZ", ScopeAll, "the time zone"},
	{"TMPDIR", ScopePOSIX, "the temp folder (the run's own on Landlock and Seatbelt)"},
	{"USER", ScopePOSIX, "the account's name"},
	{"LOGNAME", ScopePOSIX, "the account's name"},
	{"SHELL", ScopePOSIX, "the shell the tool runs commands with"},
	{"SystemRoot", ScopeWindows, "the Windows folder (MXC requires it)"},
	{"SYSTEMDRIVE", ScopeWindows, "the system drive"},
	{"WINDIR", ScopeWindows, "the Windows folder"},
	{"COMSPEC", ScopeWindows, "cmd.exe"},
	{"PATHEXT", ScopeWindows, "which extensions run as programs"},
	{"USERPROFILE", ScopeWindows, "the profile (the home on Windows)"},
	{"APPDATA", ScopeWindows, "the roaming profile folder"},
	{"LOCALAPPDATA", ScopeWindows, "the local profile folder (the run's own on mxc-process)"},
	{"TEMP", ScopeWindows, "the temp folder (the run's own on mxc-process)"},
	{"TMP", ScopeWindows, "the temp folder (the run's own on mxc-process)"},
	{"PROGRAMDATA", ScopeWindows, "a system location (wxc-exec's own environment keeps it too)"},
	{"PROGRAMFILES", ScopeWindows, "a system location (tools look for Git Bash under it)"},
	{"PROGRAMFILES(X86)", ScopeWindows, "a system location"},
	{"PROGRAMW6432", ScopeWindows, "a system location"},
	{"COMMONPROGRAMFILES", ScopeWindows, "a system location"},
	{"NUMBER_OF_PROCESSORS", ScopeWindows, "the processor count"},
	{"PROCESSOR_ARCHITECTURE", ScopeWindows, "the processor type"},
	{"OS", ScopeWindows, "the operating system's name"},
	{"USERNAME", ScopeWindows, "the account's name"},
	{"USERDOMAIN", ScopeWindows, "the account's domain"},
}

// IsWindows reports whether goos names Windows, whose variable names
// compare case-insensitively.
func IsWindows(goos string) bool { return goos == "windows" }

// applies reports whether a row's scope covers goos.
func (r Row) applies(goos string) bool {
	switch r.Scope {
	case ScopeAll:
		return true
	case ScopeWindows:
		return IsWindows(goos)
	case ScopePOSIX:
		return !IsWindows(goos)
	}
	return false
}

// Base returns the base rows for goos, in table order.
func Base(goos string) []Row {
	var out []Row
	for _, r := range baseTable {
		if r.applies(goos) {
			out = append(out, r)
		}
	}
	return out
}

// Spec is one box's allow-list.
type Spec struct {
	// GOOS is the box's operating system ("windows", or a POSIX one: a
	// container or a VM is "linux" whatever the host is).
	GOOS string
	// Extra are the tool's provider names and the user's pass_env names
	// (Decode of EnvAllow).
	Extra []string
	// Observer are the variables Observer itself set for the run that the
	// backend hands on (its markers and the trusted launcher channel).
	Observer []string
	// Drop are names the box never gets, even when Extra names them: a
	// projected run drops the relocation variables of the tool's sign-in
	// files (CLAUDE_CONFIG_DIR, CODEX_HOME), so the tool reads its state,
	// the seeded sign-in included, at the default path inside the box, not
	// at a host path the box does not bind (lane BOXSIGNIN).
	Drop []string
}

// key is a name as the box's OS compares it.
func key(goos, name string) string {
	if IsWindows(goos) {
		return strings.ToUpper(name)
	}
	return name
}

// allowed is the spec's name set.
func (s Spec) allowed() map[string]bool {
	set := map[string]bool{}
	for _, r := range Base(s.GOOS) {
		set[key(s.GOOS, r.Name)] = true
	}
	for _, list := range [][]string{s.Extra, s.Observer} {
		for _, n := range list {
			if n = strings.TrimSpace(n); n != "" {
				set[key(s.GOOS, n)] = true
			}
		}
	}
	for _, n := range s.Drop {
		delete(set, key(s.GOOS, strings.TrimSpace(n)))
	}
	return set
}

// Filter returns the entries of environ whose name s allows, in their
// order. An entry that is not NAME=value (Windows' hidden "=C:" entries, a
// bare name) is dropped. Nothing is ever added: Observer sets its own
// variables after the filter.
func Filter(environ []string, s Spec) []string {
	set := s.allowed()
	out := make([]string, 0, len(environ))
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if set[key(s.GOOS, k)] {
			out = append(out, kv)
		}
	}
	return out
}

// Dropped returns the names Filter drops from environ, sorted and
// deduplicated (names only, for a count in the posture and for tests).
func Dropped(environ []string, s Spec) []string {
	set := s.allowed()
	seen := map[string]bool{}
	var out []string
	for _, kv := range environ {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || set[key(s.GOOS, k)] || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Lookup returns the value of name in environ, the last entry winning, with
// the box OS's comparison.
func Lookup(environ []string, goos, name string) (string, bool) {
	want := key(goos, name)
	val, found := "", false
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && key(goos, k) == want {
			val, found = v, true
		}
	}
	return val, found
}

// ErrName is returned for a variable name a pass_env or ProviderEnv list may
// not hold.
var ErrName = errors.New("sandboxenv: not a variable name")

// maxNameLen bounds one name.
const maxNameLen = 128

// ValidName checks one pass_env or ProviderEnv name: a letter or underscore,
// then letters, digits and underscores, at most 128 characters, and never an
// OBSERVER_ name (those are Observer's own and set by Observer).
func ValidName(name string) error {
	if name == "" || len(name) > maxNameLen {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	for i, r := range name {
		letter := r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z')
		if !letter && (i == 0 || r < '0' || r > '9') {
			return fmt.Errorf("%w: %q", ErrName, name)
		}
	}
	if strings.HasPrefix(strings.ToUpper(name), "OBSERVER_") {
		return fmt.Errorf("%w: %q is Observer's own variable, which Observer sets itself", ErrName, name)
	}
	return nil
}

// Encode is EnvAllow's (or EnvPassed's) value for names: the valid names,
// deduplicated and sorted, comma-separated. "" for none.
func Encode(names []string) string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if ValidName(n) != nil || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// Decode is Encode's inverse; an invalid name is dropped.
func Decode(v string) []string {
	var out []string
	for _, n := range strings.Split(v, ",") {
		if n = strings.TrimSpace(n); ValidName(n) == nil {
			out = append(out, n)
		}
	}
	return out
}
