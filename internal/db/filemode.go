package db

import (
	"fmt"
	"os"
	"runtime"
)

// privateFileMode is the mode every SQLite file holding captured content is
// kept at: owner read/write only.
const privateFileMode os.FileMode = 0o600

// RestrictFileMode makes the SQLite database at path - and its -wal / -shm
// siblings when present - owner-only (security review 2026-09-27, SR27-A4).
// SQLite creates its files with the process umask (commonly 0644), and the
// agent DB holds prompts, tool inputs and captured network bodies, so on a
// multi-user host every other local account could read them. Only group/other
// bits are removed; a file already at 0600 (or stricter) is left untouched.
// It is a no-op on Windows (ACL-governed, not mode bits), for ":memory:", and
// for a path that does not exist.
func RestrictFileMode(path string) error {
	if runtime.GOOS == "windows" || path == "" || path == ":memory:" {
		return nil
	}
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("db.RestrictFileMode: %w", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 == 0 {
			continue
		}
		if err := os.Chmod(p, info.Mode().Perm()&^0o077); err != nil {
			return fmt.Errorf("db.RestrictFileMode: %w", err)
		}
	}
	return nil
}
