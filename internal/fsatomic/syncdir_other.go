//go:build !windows

package fsatomic

import (
	"fmt"
	"os"
)

// syncDir flushes the directory entry for a rename so the new name survives
// a crash. POSIX file systems need the directory itself fsynced for that.
func syncDir(dir string) error {
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("fsatomic.WriteFile: open dir for fsync: %w", err)
	}
	defer func() { _ = dirHandle.Close() }()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("fsatomic.WriteFile: fsync dir: %w", err)
	}
	return nil
}
