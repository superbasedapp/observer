//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package templatecache

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

// privateDir creates dir if needed and refuses one this user does not own or
// that others may write: a planted template in a shared temp directory would
// otherwise reach every test binary.
func privateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("templatecache: %s is not a directory", dir)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("templatecache: %s is not a private directory of this user", dir)
	}
	return nil
}

// lockPath takes an exclusive flock on path, waiting at most wait, and
// returns the function that releases it.
func lockPath(path string, wait time.Duration) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) //nolint:gosec // G115: a descriptor number
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			_ = f.Close()
			return nil, fmt.Errorf("templatecache: lock %s: %w", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
