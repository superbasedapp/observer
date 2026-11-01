//go:build windows

package fsatomic

// syncDir is a no-op on Windows. A directory handle there cannot be flushed
// (FlushFileBuffers on it fails with "Access is denied"), and NTFS journals
// the rename's metadata itself, so the file flush before the rename is the
// whole durability step. Failing here made every Fsync write fail on a native
// Windows node (Windows 11 Pro live run, 2026-10-24).
func syncDir(string) error { return nil }
