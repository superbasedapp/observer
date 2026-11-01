package diag

import (
	"path/filepath"
	"strings"
)

// hook_binary.go - T-874: the ONE answer to "does this hook registration
// still run the observer that is running now?", shared by `observer doctor`
// (checkHookCommandsBinary) and the managed-integrity probe
// (InspectCaptureIntegrityWith, hook_binary_mismatch).
//
// A registration names the observer the way the install's own launcher does
// (installshape: the npm bin symlink or the pip console script, else the real
// path), and older registrations named the real binary itself. Before T-874
// doctor compared the registry's binary_path with that registration command
// while the daemon compared it with its own resolved Go binary under
// node_modules, so the daemon reported every npm-launcher registration as a
// mismatch: 21 standing hook_binary_mismatch items on demo node 1 against
// doctor's 1. One rule table, one input shape, both callers.

// HookBinaryIdentity is the running observer as a hook registration may name
// it.
type HookBinaryIdentity struct {
	// Command is the registration command this install writes (the package
	// manager's launcher when one resolves to this install, else the real
	// path).
	Command string
	// Real is the running binary with symlinks resolved. Empty when the
	// caller only knows the command.
	Real string
}

// hookBinaryRule is one row of hookBinaryRules: match reports whether the
// recorded path names the running observer by this rule.
type hookBinaryRule struct {
	name  string
	match func(recorded string, id HookBinaryIdentity, resolve func(string) (string, bool)) bool
}

// hookBinaryRules is walked top-down; the first matching row means "the same
// observer". No row matching is a mismatch: a different binary, or a recorded
// path that no longer exists (a stale install).
var hookBinaryRules = []hookBinaryRule{
	{
		name: "same-command",
		match: func(rec string, id HookBinaryIdentity, _ func(string) (string, bool)) bool {
			return samePath(rec, id.Command)
		},
	},
	{
		name: "same-real-binary",
		match: func(rec string, id HookBinaryIdentity, _ func(string) (string, bool)) bool {
			return samePath(rec, id.Real)
		},
	},
	{
		// The recorded path is a symlink (an npm bin link, a dotfile-managed
		// link) that resolves to the running binary or to the command.
		name: "resolves-to-running",
		match: func(rec string, id HookBinaryIdentity, resolve func(string) (string, bool)) bool {
			got, ok := resolve(rec)
			if !ok {
				return false
			}
			for _, p := range []string{id.Real, id.Command} {
				if strings.TrimSpace(p) == "" {
					continue
				}
				if want, ok := resolve(p); ok && samePath(got, want) {
					return true
				}
			}
			return false
		},
	},
}

// HookBinaryMatches reports whether recorded (a hook_checksums.json
// binary_path) names the running observer id. An empty recorded path never
// matches; callers report it as unknown.
func HookBinaryMatches(recorded string, id HookBinaryIdentity) bool {
	return hookBinaryMatchesWith(recorded, id, resolveExisting)
}

// hookBinaryMatchesWith is HookBinaryMatches with the path resolver injected
// (tests).
func hookBinaryMatchesWith(recorded string, id HookBinaryIdentity, resolve func(string) (string, bool)) bool {
	if strings.TrimSpace(recorded) == "" {
		return false
	}
	for _, row := range hookBinaryRules {
		if row.match(recorded, id, resolve) {
			return true
		}
	}
	return false
}

// samePath compares two paths after cleaning; an empty side never matches.
func samePath(a, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

// resolveExisting returns p with symlinks resolved; ok is false when p does
// not exist.
func resolveExisting(p string) (string, bool) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	return r, true
}
