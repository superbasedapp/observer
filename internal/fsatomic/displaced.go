package fsatomic

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Displaced copies: the one owner of the ".displaced-<UTC>" naming convention
// (T-884). Two writers keep something Observer is about to replace next to
// the original instead of deleting it:
//
//   - the org client moves a non-regular entry planted at the bundle cache
//     path aside (internal/orgclient displaceForeignCacheEntry), and
//   - a managed node's hook repair pass keeps the bytes of a neutralised
//     Observer artifact before it rewrites it (internal/hook keepRepairCopy).
//
// Both name the aside entry DisplacedName(path, now), so an operator looking
// for "what did Observer move out of the way" searches for one suffix.

// displacedInfix separates the original path from the stamp.
const displacedInfix = ".displaced-"

// DisplacedLayout is the UTC stamp of a displaced name. It is fixed-width
// (nanoseconds always nine digits), so names of one path sort by time, and it
// holds no ':' (a valid Windows file name).
const DisplacedLayout = "20060102T150405.000000000Z"

// DisplacedName is the name an entry moved or copied aside from path takes at
// now: path + ".displaced-" + the UTC stamp.
func DisplacedName(path string, now time.Time) string {
	return path + displacedInfix + now.UTC().Format(DisplacedLayout)
}

// displacedStamp returns the time a sibling name of base carries when name is
// exactly base's displaced name (base + ".displaced-" + a stamp that parses
// under DisplacedLayout and formats back to itself), and false otherwise.
func displacedStamp(base, name string) (time.Time, bool) {
	stamp, ok := strings.CutPrefix(name, base+displacedInfix)
	if !ok || len(stamp) != len(DisplacedLayout) {
		return time.Time{}, false
	}
	at, err := time.Parse(DisplacedLayout, stamp)
	if err != nil || at.UTC().Format(DisplacedLayout) != stamp {
		return time.Time{}, false
	}
	return at, true
}

// maxDisplacedNameTries bounds how far KeepDisplacedCopy advances the stamp
// when a copy with the same stamp already exists.
const maxDisplacedNameTries = 16

// KeepDisplacedCopy keeps data, the bytes Observer is about to replace at
// path, in a NEW file DisplacedName(path, now) with mode 0600 and returns its
// path. It never overwrites anything: the copy is created exclusively, and
// when a file of that name already exists the stamp advances by a
// nanosecond, a bounded number of times.
//
// keep bounds the copies of path that accumulate: after the write, the oldest
// displaced copies of path beyond keep are removed (keep <= 0 removes
// nothing). Only regular files whose name is exactly path's displaced name are
// candidates, so a user's own path+".bak", a displaced DIRECTORY (what the
// bundle cache moves aside) and any other neighbour are never touched. A
// failed prune is not an error: the copy is written and the next call prunes
// again.
func KeepDisplacedCopy(path string, data []byte, now time.Time, keep int) (string, error) {
	var aside string
	var f *os.File
	for i := 0; i < maxDisplacedNameTries; i++ {
		aside = DisplacedName(path, now.Add(time.Duration(i)))
		var err error
		f, err = os.OpenFile(aside, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a sibling of Observer's own artifact
		if err == nil {
			break
		}
		f = nil
		if !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("fsatomic.KeepDisplacedCopy: create %s: %w", aside, err)
		}
	}
	if f == nil {
		return "", fmt.Errorf("fsatomic.KeepDisplacedCopy: no free displaced name for %s", path)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(aside)
		return "", fmt.Errorf("fsatomic.KeepDisplacedCopy: write %s: %w", aside, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(aside)
		return "", fmt.Errorf("fsatomic.KeepDisplacedCopy: close %s: %w", aside, err)
	}
	// The umask can only narrow 0600; the explicit chmod keeps it exact.
	if err := os.Chmod(aside, 0o600); err != nil {
		return "", fmt.Errorf("fsatomic.KeepDisplacedCopy: chmod %s: %w", aside, err)
	}
	if keep > 0 {
		pruneDisplacedCopies(path, keep)
	}
	return aside, nil
}

// DisplacedCopies lists the displaced copies of path (regular files named
// exactly DisplacedName(path, t) for some t), oldest first.
func DisplacedCopies(path string) []string {
	dir, base := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	type copyAt struct {
		path string
		at   time.Time
	}
	var found []copyAt
	for _, e := range entries {
		at, ok := displacedStamp(base, e.Name())
		if !ok || !e.Type().IsRegular() {
			continue
		}
		found = append(found, copyAt{filepath.Join(dir, e.Name()), at})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].at.Before(found[j].at) })
	out := make([]string, 0, len(found))
	for _, c := range found {
		out = append(out, c.path)
	}
	return out
}

// pruneDisplacedCopies removes the oldest displaced copies of path until at
// most keep remain.
func pruneDisplacedCopies(path string, keep int) {
	copies := DisplacedCopies(path)
	for len(copies) > keep {
		_ = os.Remove(copies[0])
		copies = copies[1:]
	}
}
