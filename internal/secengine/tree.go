package secengine

import (
	"path"
	"sort"
	"strings"
	"time"
)

// tree.go is the companion tree record (security plan section 4.4
// `Processes`, threat T3, case X9; JSP-8): Opengrep is a self-extracting
// bundle that unpacks 102 files (246 MB on linux amd64) into
// $XDG_CACHE_HOME/opengrep/<version> and runs from there. The driver gives
// it an Observer-owned XDG_CACHE_HOME, so that directory is known; after the
// first verified run the digests of every file in it are recorded, bound to
// the binary digest that unpacked them, and every later run re-checks them
// before Opengrep starts (Opengrep rewrites a changed file at its own start,
// so the check must come first).

// MaxTreeFiles caps the files a recorded tree may hold (JSP-8 counted 102).
const MaxTreeFiles = 1000

// TreeRecord is one recorded tree. It is node-local state.
type TreeRecord struct {
	// BinaryDigest is the binary the tree belongs to; a record for another
	// binary is not used.
	BinaryDigest string `json:"binary_digest"`
	Version      string `json:"version"`
	// Files maps each file's path relative to the version directory (forward
	// slashes) to its sha256.
	Files      map[string]string `json:"files"`
	RecordedAt time.Time         `json:"recorded_at"`
}

// TreeState is a tree check's outcome.
type TreeState string

// The TreeState values.
const (
	// TreeNone: no record for this binary yet (the first verified run
	// records one).
	TreeNone TreeState = "none"
	// TreeSame: every recorded file is present and no file was added; the
	// digests are then compared by the runner before the start.
	TreeSame TreeState = "same"
	// TreeChanged: a file was added, removed or changed.
	TreeChanged TreeState = "changed"
	// TreeUnreadable: the directory could not be listed or hashed.
	TreeUnreadable TreeState = "unreadable"
	// TreeRecordUnreadable: the driver's own record could not be read, so
	// nothing says what the tree should hold. It is never read as "no
	// record", which would let the next verified run record the current
	// tree as the new baseline.
	TreeRecordUnreadable TreeState = "record_unreadable"
)

// TreeListing is what the caller found in the version directory: every
// regular file's relative path, and whether anything that is not a regular
// file (a symlink, a device) was there.
type TreeListing struct {
	Files []string
	// Irregular is true when an entry was neither a directory nor a
	// regular file.
	Irregular bool
	// Missing is true when the directory does not exist (never unpacked,
	// or removed): the next verified run unpacks it again from the
	// verified binary and records it anew.
	Missing bool
	// Err is non-empty when the directory could not be read.
	Err string
}

// CheckTree compares a listing with the record of the same binary. It
// compares names only; the digests of the recorded files are handed to the
// runner (extrun.Program.Companions with Expect), which hashes and refuses
// on a mismatch before it starts anything.
func CheckTree(rec *TreeRecord, binaryDigest string, l TreeListing) (TreeState, []string) {
	switch {
	case rec == nil || rec.BinaryDigest != binaryDigest || l.Missing:
		return TreeNone, nil
	case l.Err != "":
		return TreeUnreadable, nil
	}
	var diff []string
	seen := map[string]bool{}
	for _, f := range l.Files {
		seen[f] = true
		if _, ok := rec.Files[f]; !ok {
			diff = append(diff, "added "+f)
		}
	}
	for f := range rec.Files {
		if !seen[f] {
			diff = append(diff, "missing "+f)
		}
	}
	if l.Irregular {
		diff = append(diff, "an entry that is not a regular file")
	}
	sort.Strings(diff)
	if len(diff) > 0 {
		return TreeChanged, diff
	}
	return TreeSame, nil
}

// ValidTreePath is a relative, forward-slash path with no "." or ".."
// element and no leading slash.
func ValidTreePath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.Contains(p, `\`) || path.Clean(p) != p {
		return false
	}
	for _, el := range strings.Split(p, "/") {
		if el == "." || el == ".." || el == "" {
			return false
		}
	}
	return true
}

// NewTreeRecord builds a record from the digests the caller computed
// after a verified run; ok is false when the tree is empty, too large or
// holds a bad path (nothing is recorded then, and the next run records
// again).
func NewTreeRecord(binaryDigest, version string, digests map[string]string, now time.Time) (TreeRecord, bool) {
	if len(digests) == 0 || len(digests) > MaxTreeFiles {
		return TreeRecord{}, false
	}
	files := make(map[string]string, len(digests))
	for p, d := range digests {
		if !ValidTreePath(p) || len(d) != 64 {
			return TreeRecord{}, false
		}
		files[p] = strings.ToLower(d)
	}
	return TreeRecord{BinaryDigest: binaryDigest, Version: version, Files: files, RecordedAt: now.UTC()}, true
}

// TreeDir is the version directory under an engine-owned XDG_CACHE_HOME,
// in forward slashes (JSP-8: $XDG_CACHE_HOME/opengrep/v<version>).
func TreeDir(xdgCache, version string) string {
	return strings.TrimRight(strings.ReplaceAll(xdgCache, `\`, "/"), "/") + "/opengrep/v" + version
}
