package hook

import (
	"path/filepath"
	"strings"
)

// RewriteBash wraps a Bash command in `observer run --` when doing so is
// safe and likely to help. Returns (newCommand, true) on rewrite, or
// (original, false) when the command should pass through unchanged.
//
// Rewriting is skipped when:
//   - the command is empty
//   - the binary path is empty (nothing to prepend)
//   - the command contains unquoted shell operators (|, &, ;, <, >, (, ), `, $)
//     — those require the host shell's own interpretation, which `observer
//     run` bypasses
//   - the command spans multiple lines (an interior newline) — `observer run`
//     execs only the first line's argv, so the remaining lines would be
//     silently dropped (a trailing newline is fine; it is trimmed away)
//   - the first word is a shell builtin (cd, export, source, …) — those have
//     no external binary and/or mutate the parent shell, so exec'ing them
//     fails (127) or loses the side effect; wrapping `cd` in particular makes
//     the directory change vanish while later commands run in the wrong cwd
//   - the first word's basename is in excludeCommands
//   - the first word is already the tool's own command (`observer` or the
//     going-forward `superbased`) — the double-wrap guard
//
// The rewrite form is `<binary> run -- <original>`. The `--` is intentional
// so that flags embedded in the wrapped command (e.g. `git --no-pager log`)
// are never consumed by `observer run` itself. The binary is one POSIX shell
// word (shellWord): a path with a space, a backslash or another shell
// character is single-quoted, so `/home/a b/observer` is not split (FU-163).
// The caller passes a path the target shell can exec; a native Windows hook
// does not rewrite at all (decidePreToolRewrite, reason "windows-shell", or
// "wsl-interop" when a WSL shell runs it through interop).
func RewriteBash(binary, original string, excludeCommands []string) (string, bool) {
	trimmed := strings.TrimSpace(original)
	if trimmed == "" || binary == "" {
		return original, false
	}
	if !isShellSimple(trimmed) {
		return original, false
	}
	first := firstWord(trimmed)
	if first == "" {
		return original, false
	}
	base := filepath.Base(first)
	if isSelfCommand(base) {
		return original, false
	}
	if shellBuiltins[base] {
		return original, false
	}
	for _, ex := range excludeCommands {
		if ex == base {
			return original, false
		}
	}
	return shellWord(binary) + " run -- " + trimmed, true
}

// shellWord returns s as a single POSIX shell word. A string made only of
// characters every POSIX shell reads literally in a command word is returned
// as it is (so the usual `/usr/local/bin/observer` and
// `C:/Users/.../observer.exe` forms stay unchanged); anything else is
// single-quoted, with an embedded single quote written as '\”. `=` and `~`
// are quoted too: an unquoted `NAME=x` first word is an assignment and a
// leading `~` expands.
func shellWord(s string) string {
	literal := s != ""
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("/._-:+,@%", r):
		default:
			literal = false
		}
		if !literal {
			break
		}
	}
	if literal {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellBuiltins is the set of shell builtins that must never be wrapped in
// `observer run`: they either have no external binary (so exec returns 127) or
// they mutate the invoking shell's state (cwd, environment, aliases, function
// table), which is lost when the builtin runs in a child process instead of
// the shell. `cd` is the canonical hazard — wrapping it makes the directory
// change silently vanish. Commands like echo/pwd/test that ALSO exist as real
// binaries in /usr/bin are deliberately absent: exec finds the binary and the
// wrap is harmless.
var shellBuiltins = map[string]bool{
	"cd": true, "export": true, "unset": true, "set": true, "source": true,
	".": true, "eval": true, "exec": true, "alias": true, "unalias": true,
	"local": true, "declare": true, "typeset": true, "readonly": true,
	"let": true, "pushd": true, "popd": true, "dirs": true, "shift": true,
	"trap": true, "umask": true, "ulimit": true, "wait": true, "read": true,
	"hash": true, "jobs": true, "fg": true, "bg": true, "disown": true,
	"times": true, "caller": true, "mapfile": true, "readarray": true,
	"enable": true, "builtin": true, "command": true, "history": true,
	"bind": true, "logout": true, "return": true, "break": true,
	"continue": true, "suspend": true, "compgen": true, "complete": true,
	"compopt": true, "getopts": true, "shopt": true,
}

// isSelfCommand reports whether base names the tool's own binary — `observer`
// or the going-forward `superbased` (dual-name compatibility). Both must be
// recognized so `observer run …` AND `superbased run …` are left un-wrapped
// rather than double-wrapped. Case-insensitive and `.exe`-tolerant for Git Bash
// on Windows.
func isSelfCommand(base string) bool {
	b := strings.ToLower(base)
	b = strings.TrimSuffix(b, ".exe")
	return b == "observer" || b == "superbased"
}

// isShellSimple returns true when cmd contains no shell operators that
// require the host shell to interpret. A small state machine tracks
// single-quote, double-quote, and backslash escaping:
//
//   - outside quotes: any of | & ; < > ( ) ` $ disqualifies
//   - inside double quotes: $ and ` are still interpreted (so they disqualify)
//   - inside single quotes: everything is literal — no metachar checks
//
// Unbalanced quotes are treated as non-simple since the host shell would not
// execute them the same way argv-passing does.
func isShellSimple(cmd string) bool {
	var (
		inSingle bool
		inDouble bool
		escape   bool
	)
	for _, r := range cmd {
		if escape {
			escape = false
			continue
		}
		switch {
		case r == '\\' && !inSingle:
			escape = true
		case r == '\'' && !inDouble:
			inSingle = !inSingle
		case r == '"' && !inSingle:
			inDouble = !inDouble
		case inDouble:
			// Inside double quotes, only $ and ` still trigger shell
			// interpretation.
			if r == '$' || r == '`' {
				return false
			}
		case r == '\n' || r == '\r':
			// An interior newline means a multi-line command; `observer run`
			// would exec only the first line and silently drop the rest.
			// (A trailing newline never reaches here — trimmed by the caller.)
			return false
		case !inSingle && !inDouble:
			switch r {
			case '|', '&', ';', '<', '>', '(', ')', '`', '$':
				return false
			}
		}
	}
	return !inSingle && !inDouble
}

// firstWord returns the first whitespace-separated token of cmd, stripped.
// Quoting inside the first word is preserved; we only care about the token
// boundary for command-name classification.
func firstWord(cmd string) string {
	s := strings.TrimSpace(cmd)
	for i, r := range s {
		if r == ' ' || r == '\t' {
			return s[:i]
		}
	}
	return s
}
