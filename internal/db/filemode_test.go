//go:build !windows

package db

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestDatabaseFilesAreOwnerOnly is the SR27-A4 regression (security review
// 2026-09-27). Under the common 022 umask SQLite created the agent DB, its WAL
// sidecars and every VACUUM INTO snapshot 0644, so any local account could
// read captured prompts, tool inputs and network bodies - and `observer
// archive reclaim` swapped a 0644 snapshot over an operator's chmod-600 DB.
// The DB (and its sidecars) and a BackupInto snapshot must be owner-only.
func TestDatabaseFilesAreOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)

	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.db")
	database, err := Open(ctx, Options{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = database.Close() }()
	if _, err := database.ExecContext(ctx, "CREATE TABLE IF NOT EXISTS sr27_probe(x INTEGER)"); err != nil {
		t.Fatalf("write: %v", err)
	}

	assertPrivate := func(p string) {
		t.Helper()
		info, err := os.Stat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return
			}
			t.Fatalf("stat %s: %v", p, err)
		}
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			t.Errorf("%s mode = %o, want owner-only (no group/other bits)", filepath.Base(p), perm)
		}
	}
	assertPrivate(path)
	assertPrivate(path + "-wal")
	assertPrivate(path + "-shm")

	dest := filepath.Join(dir, "snap", "copy.db")
	if err := BackupInto(ctx, database, dest); err != nil {
		t.Fatalf("BackupInto: %v", err)
	}
	assertPrivate(dest)
}
