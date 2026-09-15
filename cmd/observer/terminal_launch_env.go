package main

import (
	"os"
	"strings"
)

// terminal_launch_env.go hardens the environment block a terminal child gets on
// WINDOWS, where env keys are case-INSENSITIVE. os.Environ() yields `Path=…`
// while a caller's ExtraEnv (or observer's own routing vars) may add `PATH=…`;
// an explicit CreateProcess environment block keeps BOTH, and which one the
// child's loader honours is not the "last wins" the layering in launchChildEnv
// documents. os/exec solves this for its own children (dedupEnvCase +
// addCriticalEnv); the terminal spawner builds its block by hand, so it has to
// do the same. Pure + injectable, so the table test runs on any host.

// dedupEnvWindows applies the Windows environment-block hardening using the
// daemon's own process environment for the SYSTEMROOT backstop.
func dedupEnvWindows(env []string) []string {
	return dedupEnvWindowsFor(env, os.Getenv)
}

// dedupEnvWindowsFor collapses case-insensitively duplicate keys (KEEPING THE
// LAST occurrence, at its own position — so the documented last-wins layering
// becomes true) and adds a SYSTEMROOT backstop when the block has none.
//
// Two Windows-specific parsing rules, both mirrored from os/exec:
//   - An entry starting with '=' is one of the per-drive working-directory
//     variables (`=C:=C:\some\dir`); its key runs to the SECOND '=', so those
//     entries dedup per drive instead of all colliding on the empty key.
//   - An entry containing a NUL can never be encoded into an environment block,
//     so it is dropped rather than carried to a guaranteed failure.
//
// An entry with no '=' at all is kept verbatim (it names no key to collide on).
// Order is otherwise preserved; the block is not sorted (neither does os/exec).
func dedupEnvWindowsFor(env []string, getenv func(string) string) []string {
	out := make([]string, 0, len(env)+1)
	seen := make(map[string]bool, len(env))
	// Walk backwards so the LAST occurrence of a key is the one kept, then
	// restore the original order — the same trick os/exec's dedupEnvCase uses.
	for i := len(env) - 1; i >= 0; i-- {
		kv := env[i]
		if kv == "" || strings.IndexByte(kv, 0) >= 0 {
			continue
		}
		k, ok := envKeyWindows(kv)
		if !ok {
			out = append(out, kv)
			continue
		}
		lk := strings.ToLower(k)
		if seen[lk] {
			continue
		}
		seen[lk] = true
		out = append(out, kv)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	// SYSTEMROOT backstop: a child that inherits no %SystemRoot% cannot load
	// most of the Windows API surface. Only added when the daemon actually has
	// one — an empty SYSTEMROOT= would be a worse lie than its absence.
	if !seen["systemroot"] {
		if root := getenv("SYSTEMROOT"); root != "" {
			out = append(out, "SYSTEMROOT="+root)
		}
	}
	return out
}

// envKeyWindows returns the KEY of a KEY=VALUE entry, honouring the leading-'='
// per-drive form (`=C:=C:\dir` → key `=C:`). ok is false when the entry has no
// '=' at all.
func envKeyWindows(kv string) (string, bool) {
	i := strings.IndexByte(kv, '=')
	if i == 0 {
		// Per-drive entry: the real separator is the SECOND '='.
		if j := strings.IndexByte(kv[1:], '='); j >= 0 {
			return kv[:j+1], true
		}
		return "", false
	}
	if i < 0 {
		return "", false
	}
	return kv[:i], true
}
