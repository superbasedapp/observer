package crossmount

import (
	"os"
	"path/filepath"
	"strings"
)

// AutoDetectSuppressed reports whether foreign-OS (cross-mount) home
// resolution must be suppressed for a config writer whose LOCAL home was
// pinned by its caller.
//
// # INCIDENT 2026-07-31 — why this predicate exists
//
// A cmd/observer test called wireAIClients with WireAIClientsOptions.HomeDir
// pointed at a t.TempDir(), believing that sandboxed every write it could
// reach. It did not. The "claude-code-windows" hook target does not resolve
// through HomeDir at all — it walks crossmount.AllHomes() looking for a
// Windows-side `.claude/`. On the operator's WSL host that resolved the REAL
// /mnt/c/Users/<u>/.claude, and the test wrote 22 test-binary hook entries
// into the operator's own settings.json (repaired byte-exact the same day).
//
// The same exposure existed on every other cross-OS reader/writer that pairs
// a HomeDir option with crossmount detection: hook "cursor-windows", MCP
// "cline-windows", the proxy-route "claude-code-windows" / "codex-windows"
// writers, and the doctor's Windows-side plugin probe — and it was never
// test-only: ANY sandboxed caller (a sandbox-HOME generator, a benchmark
// provisioner) had the same hole.
//
// # The rule
//
// Stated as a capability of the OPTIONS SHAPE, never per tool name (CLAUDE.md
// #3/#5): pinning the local home declares "every path you resolve must derive
// from what I gave you". A foreign-OS home is not derived from it, so
// auto-detection is OFF. A caller re-enables a cross-OS target only by ALSO
// naming that target's foreign home explicitly (WindowsClaudeHome /
// WindowsCursorHome / WindowsClineHome / WindowsCodexHome) AND having that
// override live UNDER the pinned home.
//
// That containment requirement is the 2026-07-31 follow-up round: the first
// cut honoured ANY non-empty override, so `HomeDir=/tmp/sandbox` +
// `WindowsClaudeHome=/mnt/c/Users/operator` still wrote the operator's real
// config — the escape hatch re-opened the very hole the gate closed, and the
// "lands inside the sandbox by construction" claim was merely a hope about
// caller discipline. It is now enforced: PathUnder resolves symlinks on the
// nearest existing ancestor of both paths and requires lexical containment
// with no ".." escape. An uncontained override is treated exactly like no
// override — the target skips, and the caller is told which override escaped.
//
// # Why production is byte-identical
//
// Every production entry point (`observer init` — including its
// --windows-claude-home / --windows-codex-home / --windows-cursor-home flags,
// `observer start`'s auto-register, `observer enroll`'s auto-wire, `observer
// uninstall`, `observer doctor`) leaves the LOCAL home override EMPTY and lets
// the registrar resolve the real $HOME. localHomeOverride is then "" and this
// returns false on every real path — crossmount auto-detection AND bare
// Windows-home overrides behave exactly as before. Containment is required
// only of a caller that already declared a sandbox.
//
// Force deliberately does NOT lift the gate: a --force test would otherwise
// re-open precisely the hole this closes.
//
// # An isolated home counts as a pinned one (R-013, 2026-10-25)
//
// When the process itself is isolated (IsolationReason: HOME other than the
// real user home, --no-crossmount, a --config outside the real home, or
// EnvDisableForeignHomes) the resolved home stands in for the pin: no
// auto-detection, and a named foreign home is honoured only when it lives
// under that home. A process that is not isolated is unchanged.
func AutoDetectSuppressed(localHomeOverride, foreignHomeOverride string) bool {
	if localHomeOverride == "" && IsolationReason() != "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			localHomeOverride = home
		} else {
			return true // isolated with no resolvable home: write nothing foreign
		}
	}
	if localHomeOverride == "" {
		return false // production shape: nothing was pinned, nothing is suppressed
	}
	if foreignHomeOverride == "" {
		return true // pinned home, no named foreign home → no auto-detection
	}
	// Pinned home WITH a named foreign home: honour it only if it is provably
	// inside the sandbox the caller declared.
	return !PathUnder(localHomeOverride, foreignHomeOverride)
}

// PathUnder reports whether target resolves to base itself or a path beneath
// it. Both sides are made absolute and symlink-resolved as far as they exist
// on disk (a not-yet-created override still resolves through its existing
// ancestors), then compared LEXICALLY via filepath.Rel so no ".." escape and
// no symlink hop can smuggle a path out of base.
//
// Failure is closed: an unresolvable path reports false (not contained).
func PathUnder(base, target string) bool {
	rb, ok := resolveThroughExistingAncestor(base)
	if !ok {
		return false
	}
	rt, ok := resolveThroughExistingAncestor(target)
	if !ok {
		return false
	}
	rel, err := filepath.Rel(rb, rt)
	if err != nil || filepath.IsAbs(rel) {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolveThroughExistingAncestor absolutizes p and resolves symlinks on its
// deepest EXISTING ancestor, re-appending the not-yet-created tail. This
// matters because an override may legitimately name a directory the registrar
// will mkdir on first install, while the sandbox root above it is a symlink
// (macOS /var → /private/var, and any TMPDIR that is one).
func resolveThroughExistingAncestor(p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	cur := filepath.Clean(abs)
	tail := ""
	for {
		if resolved, err := filepath.EvalSymlinks(cur); err == nil {
			if tail == "" {
				return resolved, true
			}
			return filepath.Join(resolved, tail), true
		} else if !os.IsNotExist(err) {
			// Permission errors and friends: fail closed rather than
			// pretending we resolved something.
			return "", false
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			// Nothing along the path exists (or we hit the root): fall back to
			// the lexical form, which is still safe to compare.
			return filepath.Clean(abs), true
		}
		tail = filepath.Join(filepath.Base(cur), tail)
		cur = parent
	}
}
