package git

import (
	"os"
	"path/filepath"
	"time"
)

// maxHeadWorktrees bounds the linked worktrees LatestHeadWrite looks at; a
// repository with more cannot be answered.
const maxHeadWorktrees = 32

// LatestHeadWrite returns when a checkout of the repository containing dir
// last wrote its HEAD: the newest modification time of the common git
// directory's HEAD and of every linked worktree's HEAD under it. A branch
// switch, a detached checkout or a worktree's switch moves it. ok is false
// when dir is not in a repository with a readable git directory, a HEAD
// cannot be read, or there are more than maxHeadWorktrees worktrees. Reads
// file metadata only, no git process (the commit gate's signed default push
// remote is checked against it on the hook path; lane SEC-GATE5, SECP-18).
func LatestHeadWrite(dir string) (time.Time, bool) {
	abs, err := absResolveSymlinks(dir)
	if err != nil {
		return time.Time{}, false
	}
	loc := locateGit(abs)
	if !loc.ok || !isDir(loc.commonDir) {
		return time.Time{}, false
	}
	fi, err := os.Stat(filepath.Join(loc.commonDir, "HEAD"))
	if err != nil {
		return time.Time{}, false
	}
	latest := fi.ModTime()
	entries, err := os.ReadDir(filepath.Join(loc.commonDir, "worktrees"))
	if err != nil {
		if os.IsNotExist(err) {
			return latest, true
		}
		return time.Time{}, false
	}
	if len(entries) > maxHeadWorktrees {
		return time.Time{}, false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		wfi, err := os.Stat(filepath.Join(loc.commonDir, "worktrees", e.Name(), "HEAD"))
		if err != nil {
			if os.IsNotExist(err) {
				continue // a worktree being added or pruned has no HEAD yet
			}
			return time.Time{}, false
		}
		if wfi.ModTime().After(latest) {
			latest = wfi.ModTime()
		}
	}
	return latest, true
}

// HeadWriteBefore reports whether a HEAD write at latest (LatestHeadWrite)
// happened before a resolution at at. A write with no sub-second part
// comes from a file system that keeps whole seconds (DrvFs on WSL2, some
// network file systems): its true time is anywhere in that second, so it
// is compared at one-second granularity, and a write in the resolution's
// own second reads as at or after it (stale; lane SEC-P4 decision 6). The
// HEAD watch re-resolves such an entry on its next look, which settles it.
func HeadWriteBefore(latest, at time.Time) bool {
	if latest.Nanosecond() == 0 {
		return latest.Before(at.Truncate(time.Second))
	}
	return latest.Before(at)
}
