package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// guestoneshot.go plans the guest helper's one-shot commands (sandbox plan
// section 5.4 and section 6, M7): short invocations of `observer
// sandbox-guest <command>` that run inside the box and print one bounded
// answer, with no channel streams of their own. P2 ships staged-diff; db-copy
// lands with the first backend that projects a tool's SQLite store (the
// oci-runsc row, lane SBX-P3B).

// GuestStagedDiff is the one-shot that prints what the box's next commit
// would record (security plan section 4.8 "Copy workspaces"): the staged
// diff, or with StagedDiffAll the tracked working-tree diff a `git commit
// -a` records. Its output is untrusted input to the host (SBX-BE-10).
const GuestStagedDiff = "staged-diff"

// StagedDiffAll is the staged-diff flag for the `-a` form.
const StagedDiffAll = "--all"

// MaxStagedDiff caps the diff the one-shot prints; a larger diff is cut at
// the cap and the one-shot exits StagedDiffTruncatedExit, so the host never
// mistakes a cut diff for the whole one.
const MaxStagedDiff = 4 << 20

// StagedDiffTruncatedExit is the one-shot's exit code for a cut diff.
const StagedDiffTruncatedExit = 3

// StagedDiffArgv is the git argv of the one-shot: no external diff driver,
// no textconv filter, no pager, no color, binary hunks as patches. all
// selects the tracked working-tree diff against HEAD.
func StagedDiffArgv(all bool) []string {
	argv := []string{"git", "--no-pager", "diff", "--no-ext-diff", "--no-textconv", "--no-color", "--binary"}
	if all {
		return append(argv, "HEAD")
	}
	return append(argv, "--cached")
}

// ParseStagedDiffArgs parses the one-shot's own arguments: none, or
// StagedDiffAll. ok=false refuses anything else.
func ParseStagedDiffArgs(args []string) (all, ok bool) {
	switch {
	case len(args) == 0:
		return false, true
	case len(args) == 1 && args[0] == StagedDiffAll:
		return true, true
	}
	return false, false
}

// GuestDBCopy is the one-shot that makes consistent copies of the SQLite
// stores a tool wrote in a projected state directory (sandbox plan section
// 5.4, ledger SBX-BE-10): inside the guest, where the store's own locks
// hold, each SQLite file under --root is copied with VACUUM INTO into --out
// under a fixed name, and a manifest names what was copied. The host never
// opens a guest-written store live: it reads only these copies, no-follow,
// size-capped, read-only with trusted_schema off.
const GuestDBCopy = "db-copy"

// The db-copy flags.
const (
	DBCopyRootFlag = "--root"
	DBCopyOutFlag  = "--out"
)

// SQLiteHeader is the first 16 bytes of every SQLite database file: the
// one-shot copies only files that start with it (whatever the tool calls
// them), so it needs no per-tool list.
const SQLiteHeader = "SQLite format 3\x00"

// DB-copy bounds: files copied per run, bytes per copy (the guest skips a
// larger store; the host refuses a larger copy), the manifest's size, and
// how deep the walk goes.
const (
	DBCopyMaxFiles    = 64
	DBCopyMaxBytes    = 256 << 20
	DBCopyMaxManifest = 64 << 10
	DBCopyMaxDepth    = 8
)

// DBCopyManifestName is the manifest the one-shot writes into --out.
const DBCopyManifestName = "manifest.json"

// DBCopyEntry is one copied store: Rel is its path under --root (data from
// the guest, never a host path), Name the copy's file name in --out.
type DBCopyEntry struct {
	Rel  string `json:"rel"`
	Name string `json:"name"`
}

// DBCopyManifest is the one-shot's manifest.
type DBCopyManifest struct {
	Files []DBCopyEntry `json:"files"`
}

// DBCopyRequest is the parsed one-shot.
type DBCopyRequest struct {
	Root string
	Out  string
}

// ParseDBCopyArgs parses `--root <dir> --out <dir>` (both absolute, clean,
// different, and --out not above --root); ok=false refuses anything else.
func ParseDBCopyArgs(args []string) (DBCopyRequest, bool) {
	if len(args) != 4 || args[0] != DBCopyRootFlag || args[2] != DBCopyOutFlag {
		return DBCopyRequest{}, false
	}
	r := DBCopyRequest{Root: args[1], Out: args[3]}
	if !path.IsAbs(r.Root) || !path.IsAbs(r.Out) || path.Clean(r.Root) != r.Root || path.Clean(r.Out) != r.Out ||
		r.Root == "/" || r.Root == r.Out || strings.HasPrefix(r.Root+"/", r.Out+"/") {
		return DBCopyRequest{}, false
	}
	return r, true
}

// DBCopyName is the copy's file name for a store's relative path: a digest,
// so no name the guest chose reaches the host side.
func DBCopyName(rel string) string {
	sum := sha256.Sum256([]byte(rel))
	return hex.EncodeToString(sum[:]) + ".db"
}

// ValidDBCopyName reports whether name is a copy name DBCopyName could
// have produced (64 lowercase hex and ".db"); the host reads nothing else.
func ValidDBCopyName(name string) bool {
	if len(name) != 67 || !strings.HasSuffix(name, ".db") {
		return false
	}
	for _, c := range name[:64] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// DBCopyArgv is the guest argv of the one-shot.
func DBCopyArgv(observer, root, out string) []string {
	return []string{observer, GuestVerb, GuestDBCopy, DBCopyRootFlag, root, DBCopyOutFlag, out}
}

// ParseDBCopyManifest decodes a db-copy manifest (at most DBCopyMaxManifest
// bytes; the entries still need ValidDBCopyName and DBCopyName checks).
func ParseDBCopyManifest(b []byte) (DBCopyManifest, error) {
	var m DBCopyManifest
	if len(b) > DBCopyMaxManifest {
		return m, fmt.Errorf("sandbox: the db-copy manifest is over %d bytes", DBCopyMaxManifest)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, fmt.Errorf("sandbox: the db-copy manifest: %w", err)
	}
	return m, nil
}
