package orgclient

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// The org policy bundle cache path when a read of it fails (D-704, guard
// tamper re-test shape 3: the bundle file deleted and a read-only DIRECTORY
// planted at the same path).
//
// Before this, every read failure other than "does not exist" was treated as
// a genuine I/O error: the on-disk check returned an error, the guard
// policy-state reader failed, and the reporter skipped the whole snapshot,
// so the organization kept showing the last good report for as long as the
// path stayed blocked. The fetch could not repair it either: its baseline
// read failed the same way, and the atomic write cannot rename a file over a
// directory.

// cacheReadClass is how one failed read of the bundle cache path is treated.
type cacheReadClass int

const (
	// cacheReadIOError is a genuine I/O fault (a disk error, a transient
	// failure). The caller returns it; nothing is inferred about the bundle,
	// so a hiccup is never reported as a tamper.
	cacheReadIOError cacheReadClass = iota
	// cacheReadAbsent: nothing is at the path.
	cacheReadAbsent
	// cacheReadUnusable: the path holds something the node cannot read as the
	// bundle file (a directory or other non-regular entry, or a file this
	// user may not read). The hooks cannot read it either, so to the guard it
	// is the same as no file: the on-disk check reports it like a deletion
	// and the fetch treats it as "no reliable baseline", exactly like a
	// corrupt cache.
	cacheReadUnusable
)

// cacheReadRule is one row of the ordered classification table: the first
// row whose match holds decides the class (CLAUDE.md rule 5). info and
// statErr are a Stat of the path taken after the failed read.
type cacheReadRule struct {
	class cacheReadClass
	match func(readErr error, info fs.FileInfo, statErr error) bool
}

// cacheReadRules is the classification table; no match is cacheReadIOError.
var cacheReadRules = []cacheReadRule{
	{cacheReadAbsent, func(readErr error, _ fs.FileInfo, _ error) bool {
		return errors.Is(readErr, fs.ErrNotExist)
	}},
	{cacheReadUnusable, func(_ error, info fs.FileInfo, statErr error) bool {
		return statErr == nil && !info.Mode().IsRegular()
	}},
	{cacheReadUnusable, func(readErr error, _ fs.FileInfo, _ error) bool {
		return errors.Is(readErr, fs.ErrPermission)
	}},
}

// classifyCacheReadError classifies a failed read of the cache at path.
func classifyCacheReadError(path string, readErr error) cacheReadClass {
	info, statErr := os.Stat(path)
	for _, rule := range cacheReadRules {
		if rule.match(readErr, info, statErr) {
			return rule.class
		}
	}
	return cacheReadIOError
}

// displaceForeignCacheEntry is the repair for a non-regular entry planted at
// the bundle cache path. The path is the org client's own file (the policy
// fetch is its one writer), so anything else occupying it blocks the
// organization's policy from reaching the hooks. The entry is MOVED ASIDE in
// the same directory, never deleted: whatever was put there (a directory and
// its contents, a link) is kept intact for the developer to inspect, and the
// fetch can then write the bundle. A regular file needs nothing here (the
// atomic replace overwrites it, as it does an edited bundle), and neither does
// an empty path. Following a link on the Stat is deliberate: a link to a
// directory is as unusable as the directory, and the rename moves the link
// itself, never its target.
//
// It returns the path the entry was moved to ("" when nothing was moved).
func displaceForeignCacheEntry(path string, now time.Time) (string, error) {
	info, err := os.Stat(path)
	if err != nil || info.Mode().IsRegular() {
		return "", nil
	}
	aside := fsatomic.DisplacedName(path, now)
	if _, lerr := os.Lstat(aside); lerr == nil {
		return "", fmt.Errorf("orgclient.displaceForeignCacheEntry: %s already exists", aside)
	}
	if err := os.Rename(path, aside); err != nil {
		return "", fmt.Errorf("orgclient.displaceForeignCacheEntry: %w", err)
	}
	return aside, nil
}
