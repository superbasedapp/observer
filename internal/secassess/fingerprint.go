package secassess

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// The content fingerprint of the boundary audit (review finding M3). A status
// line says only that a path is changed, so a second edit of a file that was
// already dirty reads exactly like the first. Each changed path therefore also
// carries a short fingerprint of its content, taken by the host with
// `git hash-object` (read-only without -w, run with --no-filters so no clean
// filter program of the repository can run), and the audit compares status,
// path and fingerprint. This file is the pure part: the table that decides what
// to do with a path, the batching, and the reading of the output. The host does
// the I/O.

// FpLen is how many hex characters of a hash a stored fingerprint keeps (80
// bits: change detection, not identity).
const FpLen = 20

// FpAbsent is the fingerprint of a path whose file is gone and that git reports
// as deleted. It is stable, so a file that stays deleted compares equal.
const FpAbsent = "absent"

// ShortFingerprint returns the stored fingerprint for a full hash printed by
// git: the first FpLen characters, lower-cased. It returns "" for anything that
// is not a plausible hexadecimal hash.
func ShortFingerprint(hash string) string {
	if len(hash) < FpLen {
		return ""
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		isHex := c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
		if !isHex {
			return ""
		}
	}
	return strings.ToLower(hash[:FpLen])
}

// LinkFingerprint is the fingerprint of a symbolic link: its target text, not
// the file it points at (git itself records a link as its target).
func LinkFingerprint(target string) string {
	sum := sha256.Sum256([]byte("symlink\x00" + target))
	return hex.EncodeToString(sum[:])[:FpLen]
}

// FileKind is what the host found at a status path.
type FileKind string

// The file kinds.
const (
	// FileAbsent: nothing is at the path.
	FileAbsent FileKind = "absent"
	// FileRegular: an ordinary file.
	FileRegular FileKind = "regular"
	// FileSymlink: a symbolic link.
	FileSymlink FileKind = "symlink"
	// FileOther: a directory (a nested repository or a submodule), a device, a
	// pipe, or anything that could not be examined.
	FileOther FileKind = "other"
)

// FpMaxFileBytes is the largest file the check reads. A larger one is not
// compared (hashing it could outlast the check's time budget).
const FpMaxFileBytes = 32 << 20

// FpAction is what the host does with one status path.
type FpAction string

// The fingerprint actions.
const (
	// FpSkip: no fingerprint is taken; the entry reads as not compared.
	FpSkip FpAction = "skip"
	// FpSetAbsent: the stable "absent" fingerprint.
	FpSetAbsent FpAction = "absent"
	// FpSetLink: a fingerprint of the link target.
	FpSetLink FpAction = "link"
	// FpHash: hash the file with git hash-object.
	FpHash FpAction = "hash"
)

// Deleted reports whether git's status says the path is deleted (in the index,
// the working tree or both).
func (e TreeEntry) Deleted() bool {
	return e.Status != "" && (e.Status[0] == 'D' || (len(e.Status) > 1 && e.Status[1] == 'D'))
}

// delRule is the "git says deleted" column of the fingerprint action table.
type delRule int8

const (
	delAny delRule = iota
	delYes
	delNo
)

func (d delRule) matches(deleted bool) bool {
	return d == delAny || (d == delYes) == deleted
}

// fpRow is one row of the fingerprint action table. Rows are walked top-down;
// the first that matches wins.
type fpRow struct {
	kind    FileKind
	deleted delRule
	action  FpAction
}

var fpTable = []fpRow{
	// A deleted path with no file is the one case where "absent" is the truth.
	{FileAbsent, delYes, FpSetAbsent},
	// A path git says exists but that is not there (a race, a path the host
	// cannot resolve) is never read as deleted: it is not compared.
	{FileAbsent, delNo, FpSkip},
	{FileSymlink, delAny, FpSetLink},
	{FileRegular, delAny, FpHash},
	{FileOther, delAny, FpSkip},
}

// FingerprintAction decides what to do for one entry whose path was examined as
// kind (size is the file's length). One row of the table per rule; a regular
// file over FpMaxFileBytes is skipped.
func FingerprintAction(e TreeEntry, kind FileKind, size int64) FpAction {
	for _, r := range fpTable {
		if r.kind != kind || !r.deleted.matches(e.Deleted()) {
			continue
		}
		if r.action == FpHash && size > FpMaxFileBytes {
			return FpSkip
		}
		return r.action
	}
	return FpSkip
}

// The limits of one hash-object command: how many paths, how many bytes of
// command line (Windows keeps a command line under 32 KiB) and how many bytes
// of file content.
const (
	HashBatchPaths        = 80
	HashBatchArgBytes     = 6000
	HashBatchContentBytes = 64 << 20
)

// HashItem is one regular file to hash: its path relative to the repository
// top level and its length.
type HashItem struct {
	Path string
	Size int64
}

// PlanHashBatches groups the items, in order, into batches (slices of indexes
// into items) that each stay under the three limits. An item over a limit by
// itself gets a batch of its own.
func PlanHashBatches(items []HashItem) [][]int {
	var batches [][]int
	var cur []int
	args, content := 0, int64(0)
	for i, it := range items {
		need := len(it.Path) + 1
		over := len(cur) >= HashBatchPaths || args+need > HashBatchArgBytes || content+it.Size > HashBatchContentBytes
		if len(cur) > 0 && over {
			batches = append(batches, cur)
			cur, args, content = nil, 0, 0
		}
		cur = append(cur, i)
		args += need
		content += it.Size
	}
	if len(cur) > 0 {
		batches = append(batches, cur)
	}
	return batches
}

// HashObjectArgs are the git arguments that hash the given paths (relative to
// the directory git runs in). --no-filters hashes the bytes as they are, so no
// clean filter or end-of-line conversion of the repository runs; without -w
// nothing is written.
func HashObjectArgs(paths []string) []string {
	return append([]string{"hash-object", "--no-filters", "--"}, paths...)
}

// ParseHashOutput reads the output of HashObjectArgs for want paths: one hash
// per line, in order. It returns the fingerprints, or ok false when the output
// does not have exactly want valid hashes (the host then treats the batch as
// failed).
func ParseHashOutput(out []byte, want int) (fps []string, ok bool) {
	for _, line := range bytes.Split(out, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		fp := ShortFingerprint(string(line))
		if fp == "" {
			return nil, false
		}
		fps = append(fps, fp)
	}
	if len(fps) != want {
		return nil, false
	}
	return fps, true
}
