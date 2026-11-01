//go:build windows

package hook

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// TestSettingsLockReleaseOutlastsAContenderHandle (Windows 11 Pro live run,
// PT-02): a waiting writer that has the lock file open for a moment made
// the holder's delete fail with a sharing violation, so the lock stayed and
// every other writer timed out after 5 s. The release now retries.
func TestSettingsLockReleaseOutlastsAContenderHandle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook_checksums.json")
	release, err := lockSettingsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := path + settingsLockSuffix
	f, err := os.Open(lockPath)
	if err != nil {
		t.Fatalf("the lock file is not there: %v", err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = f.Close()
	}()
	release()
	if _, err := os.Lstat(lockPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the released lock file is still there (%v): the next writer would time out", err)
	}
}

// TestSettingsLockWaitsForALockBeingDeleted: a create of a name whose file
// is still being deleted fails with access denied on Windows; that is the
// lock being released, so the writer waits for it instead of writing
// without the lock (the fail-open branch lost entries under concurrent
// writers).
func TestSettingsLockWaitsForALockBeingDeleted(t *testing.T) {
	if !lockCreateHeld(windows.ERROR_ACCESS_DENIED) || !lockCreateHeld(windows.ERROR_SHARING_VIOLATION) || !lockCreateHeld(os.ErrExist) {
		t.Fatal("access denied, a sharing violation and exists must all mean the lock is held")
	}
	if lockCreateHeld(windows.ERROR_PATH_NOT_FOUND) {
		t.Fatal("a missing directory is not a held lock")
	}
	path := filepath.Join(t.TempDir(), "hook_checksums.json")
	lockPath := path + settingsLockSuffix
	if err := os.WriteFile(lockPath, []byte("pid=1 old holder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(lockPath); err != nil {
		_ = windows.CloseHandle(h)
		t.Fatal(err)
	}
	if f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil || errors.Is(err, os.ErrExist) {
		// Close both handles first, or the temp dir cannot be removed.
		if f != nil {
			_ = f.Close()
		}
		_ = windows.CloseHandle(h)
		t.Skipf("this file system frees the name at once (create: %v); nothing to wait for", err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = windows.CloseHandle(h)
	}()
	release, err := lockSettingsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := os.Lstat(lockPath); err != nil {
		t.Fatalf("the writer went on without a lock file (%v): it took the fail-open branch", err)
	}
}
