package loc

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// RelativeProjectPath normalizes a tool-reported path into the
// project-relative form whose sha256 is file_path_hash.
//
// It is exported because a human save and an AI edit must hash the SAME
// way — otherwise a human save and the agent edit it echoes could never
// join, and callers outside this package (the editor-change endpoint, the
// commit-log path-hash join in internal/commitlog) could not reproduce
// file_changes.file_path_hash for the same file.
//
// Normalization, in order:
//
//  1. Both separators become "/", so a Windows session's
//     `C:\repo\src\a.go` and a WSL session's `/repo/src/a.go` reduce the
//     same way. (The corpus really does mix them: 3 sessions here span
//     Windows and Linux roots.)
//  2. The project root prefix is stripped when present, case-insensitively
//     — Windows paths are case-insensitive in practice and a drive-letter
//     case difference must not fork the hash.
//  3. A leading "./" and any leading "/" are stripped.
//
// A path that is NOT under the root (an absolute path in another tree, an
// "[external]/…" pseudo-path) is returned normalized but unstripped, so it
// hashes distinctly and never collides with a project file.
func RelativeProjectPath(projectRoot, path string) string {
	p := strings.ReplaceAll(strings.TrimSpace(path), `\`, "/")
	if p == "" {
		return ""
	}
	root := strings.TrimSuffix(strings.ReplaceAll(strings.TrimSpace(projectRoot), `\`, "/"), "/")
	if root != "" && len(p) > len(root) &&
		strings.EqualFold(p[:len(root)], root) &&
		(p[len(root)] == '/') {
		p = p[len(root)+1:]
	}
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimLeft(p, "/")
	return p
}

// PathHash is the sha256 hex digest of RelativeProjectPath(projectRoot,
// path) — the value stored as file_changes.file_path_hash. An empty input
// path (after RelativeProjectPath's own trimming) yields an empty hash,
// never a hash of the empty string, so callers can tell "no path" apart
// from "path hashed to nothing worth joining on".
func PathHash(projectRoot, path string) string {
	rel := RelativeProjectPath(projectRoot, path)
	if rel == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(rel))
	return hex.EncodeToString(sum[:])
}
