package adapter

import (
	"os"
	"path/filepath"
	"strings"
)

// DedupRootsByIdentity collapses watch roots that name the SAME
// directory on disk down to one entry, preserving input order (first
// occurrence wins). It is the one owner of watch-root identity: the
// watcher applies it to every adapter's WatchPaths before iterating
// them to register, scan, or map roots.
//
// Three layers, cheapest first:
//
//  1. String identity — empty entries are dropped, every survivor is
//     filepath.Clean'd (so `.`/`..` segments and trailing separators
//     fold), and the cleaned strings are compared case-insensitively
//     on Windows + macOS (the same caseInsensitiveFS rule
//     HasPathPrefix uses) and case-sensitively on Linux.
//
//  2. filepath.EvalSymlinks — for roots that EXIST as directories, a
//     root whose resolved target equals an already-kept root's
//     resolved target is dropped. This catches a plain symlinked
//     alias of a watch root.
//
//  3. os.SameFile — same-directory identity by (device, inode) /
//     (volume, file index), checked against every kept existing
//     directory. This catches the cases EvalSymlinks does NOT fold:
//     Windows directory junctions and, the reason this helper exists,
//     the MSIX redirect on a packaged Claude Desktop install, where
//     `%APPDATA%\Claude` is a reparse point onto
//     `%LOCALAPPDATA%\Packages\Claude_<hash>\LocalCache\Roaming\Claude`.
//     Both spellings are legitimate candidate roots (the MSIX one is
//     the only spelling reachable from a WSL daemon over DrvFs), so
//     the cowork adapter returns both; without identity folding the
//     watcher registers two roots over ONE tree and every audit.jsonl
//     is ingested twice under two distinct source_file values
//     (audit finding IDE-01: an exact 2x action-row inflation).
//
// Roots that do NOT exist are RETAINED verbatim (after cleaning):
// adapters return their canonical roots regardless of install state
// (Invariant #48), and the watcher drops missing ones later. Roots
// that exist but are not directories (aider's per-repo transcript
// FILE roots) get layer 1 only — hard-linked distinct transcripts are
// not the aliasing class this helper folds.
//
// Never panics; stat / EvalSymlinks errors degrade to the cheaper
// layer. Always returns a fresh slice — the input is never aliased or
// mutated.
func DedupRootsByIdentity(roots []string) []string {
	if len(roots) == 0 {
		return nil
	}
	out := make([]string, 0, len(roots))
	seen := make(map[string]struct{}, len(roots))     // cleaned spelling
	resolved := make(map[string]struct{}, len(roots)) // EvalSymlinks target
	kept := make([]os.FileInfo, 0, len(roots))        // existing dirs, for os.SameFile

	for _, r := range roots {
		if r == "" {
			continue
		}
		clean := filepath.Clean(r)
		key := rootIdentityKey(clean)
		if _, dup := seen[key]; dup {
			continue
		}

		fi, err := os.Stat(clean)
		if err != nil || !fi.IsDir() {
			// Non-existent (or non-directory) root: string identity only.
			seen[key] = struct{}{}
			out = append(out, clean)
			continue
		}

		real := clean
		if rp, err := filepath.EvalSymlinks(clean); err == nil {
			real = filepath.Clean(rp)
		}
		realKey := rootIdentityKey(real)
		if _, dup := resolved[realKey]; dup {
			continue
		}
		if sameAsAny(kept, fi) {
			continue
		}

		seen[key] = struct{}{}
		resolved[realKey] = struct{}{}
		kept = append(kept, fi)
		out = append(out, clean)
	}
	return out
}

// sameAsAny reports whether fi describes the same directory as any
// already-kept root. os.SameFile is the only check that sees through a
// Windows junction / MSIX reparse point, which EvalSymlinks may report
// unchanged.
func sameAsAny(kept []os.FileInfo, fi os.FileInfo) bool {
	for _, k := range kept {
		if os.SameFile(k, fi) {
			return true
		}
	}
	return false
}

// AbsEnvRoot reads a storage-root environment variable and returns it
// as an ABSOLUTE path, or "" when it is unset, blank, or cannot be
// absolutized.
//
// A watch root must be absolute: UnderAnyWatchRoot compares the
// watcher's absolute trigger path against it as a prefix, and fsnotify
// resolves a relative root against the daemon's working directory —
// which is not the operator's shell cwd and can change between runs.
// So a relative override (e.g. `JUNIE_HOME=./junie`) must never travel
// into WatchPaths verbatim; filepath.Abs anchors it once, at
// root-construction time, and an error (only possible when the process
// cwd is unavailable) DROPS the candidate rather than emitting the
// relative form.
//
// This is the ONE fold of four call sites that used to hand-roll the
// identical TrimSpace/Abs/""-on-failure sequence: internal/adapter/junie,
// internal/adapter/qwencode, internal/adapter/kimicode, and
// internal/adapter/kirocrew each had their own copy. A per-package
// helper stays local only when its semantics actually differ (see
// each caller's history for why these four did not).
func AbsEnvRoot(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return ""
	}
	abs, err := filepath.Abs(v)
	if err != nil {
		return ""
	}
	return abs
}

// rootIdentityKey normalizes a cleaned path for map-key comparison,
// case-folding on the platforms whose filesystems are case-insensitive
// by default. Mirrors HasPathPrefix's caseInsensitiveFS rule so root
// identity and prefix matching never disagree.
func rootIdentityKey(clean string) string {
	if caseInsensitiveFS {
		return strings.ToLower(clean)
	}
	return clean
}
