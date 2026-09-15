//go:build unix

package cloudcred

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

func withCredentialLock(dir string, fn func() error) error {
	s := &fileStore{dir: dir}
	if err := s.ensureDir(); err != nil {
		return err
	}
	path := s.path("coordination-lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|openNoFollow, credFileMode)
	if err != nil {
		return fmt.Errorf("cloudcred: open coordination lock: %w", err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != credFileMode {
		return errors.New("cloudcred: insecure coordination lock")
	}
	if err := checkOwnerFile(path, f, info); err != nil {
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			return fmt.Errorf("cloudcred: acquire coordination lock: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) }()
	return fn()
}
