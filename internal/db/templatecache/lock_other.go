//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package templatecache

import (
	"errors"
	"time"
)

// privateDir refuses the shared directory where this package cannot check
// ownership or take a lock; every build is then private.
func privateDir(string) error {
	return errors.New("templatecache: shared templates are not supported on this platform")
}

// lockPath is never reached: privateDir refuses first.
func lockPath(string, time.Duration) (func(), error) {
	return nil, errors.New("templatecache: no file lock on this platform")
}
