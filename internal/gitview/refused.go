package gitview

import (
	"errors"
	"os"
	"path/filepath"
)

// refused.go is the one place a host git run learns that a directory must
// never see host git again (lane SBX-P3C audit fixes, Linux live re-check 4
// DEFECT D4): a sandbox run's copy whose git config failed the return scan
// is kept for the developer to inspect, and the return step writes
// HostGitRefusedStamp into it. Every git invocation of this package (the
// dashboard's views, the commit scanner) refuses a root at or under a
// stamped directory before it starts git, and the sandbox return step
// checks the same stamp, so Observer never runs host git in that copy again.

// HostGitRefusedStamp is the stamp file's name, written at the top of a
// refused copy.
const HostGitRefusedStamp = ".observer-host-git-refused"

// hostGitRefusedDepth bounds the parents HostGitRefused looks at.
const hostGitRefusedDepth = 64

// ErrHostGitRefused is returned for a root at or under a stamped directory.
var ErrHostGitRefused = errors.New("gitview: Observer does not run git here: a sandbox run's copy whose git config could run a program the box chose")

// HostGitRefused returns the stamped directory at or above root, if any. It
// only stats (a stamp of any file type counts, a link is never followed).
func HostGitRefused(root string) (string, bool) {
	dir, err := filepath.Abs(root)
	if err != nil {
		return "", false
	}
	for i := 0; i < hostGitRefusedDepth; i++ {
		if _, err := os.Lstat(filepath.Join(dir, HostGitRefusedStamp)); err == nil {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}
