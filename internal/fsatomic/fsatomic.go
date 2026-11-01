// Package fsatomic writes a file atomically: a same-directory temp file,
// 0600, an optional fsync, then a rename.
//
// It exists because three copies of this sequence had already accumulated
// (internal/orgclient/policy.go, internal/orgclient/policyresource.go,
// internal/intelligence/dashboard/guardpolicy.go) and Phase 1b's governance
// sidecar would have been the fourth. The two orgclient copies were NOT the
// same function — one fsyncs and one does not (review m3) — so the switch is
// EXPLICIT here rather than assumed.
//
// A deliberate non-goal: this package carries no doc comment about
// transaction fences. policyresource.go's fsyncing copy ties its ordering
// guarantee to being called inside store.WithPolicyResourceFence; that is a
// property of THAT CALL SITE, not of the write, and carrying the claim onto
// a daemon-loop caller that holds no fence would be a false guarantee.
package fsatomic

import (
	"fmt"
	"os"
	"path/filepath"
)

// Options parameterizes WriteFile.
type Options struct {
	// TempPattern is the os.CreateTemp pattern for the same-directory temp
	// file. Empty means ".fsatomic-*.tmp".
	TempPattern string
	// Fsync durably flushes the file AND (where the OS allows it, not on
	// Windows) the containing directory before returning. Callers that need crash-consistency set it; callers writing
	// a cache that a restart can rebuild do not.
	Fsync bool
	// DirPerm is the permission for a directory this call has to create.
	// Zero means 0700.
	DirPerm os.FileMode
	// FilePerm is the permission of the written file. Zero means 0600.
	FilePerm os.FileMode
	// OwnerOnly creates the temp file with CreateTempOwnerOnly, so the
	// written file is readable by this user only on Windows too (a
	// protected DACL; ownerfile.go). For credentials.
	OwnerOnly bool
}

// WriteFile writes data to path atomically. On any failure the temp file is
// removed, so a failed write never leaves a partial artifact behind.
func WriteFile(path string, data []byte, opts Options) error {
	if opts.TempPattern == "" {
		opts.TempPattern = ".fsatomic-*.tmp"
	}
	if opts.DirPerm == 0 {
		opts.DirPerm = 0o700
	}
	if opts.FilePerm == 0 {
		opts.FilePerm = 0o600
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, opts.DirPerm); err != nil {
		return fmt.Errorf("fsatomic.WriteFile: mkdir %s: %w", dir, err)
	}
	createTemp := os.CreateTemp
	if opts.OwnerOnly {
		createTemp = CreateTempOwnerOnly
	}
	tmp, err := createTemp(dir, opts.TempPattern)
	if err != nil {
		return fmt.Errorf("fsatomic.WriteFile: create temp in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func(e error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return e
	}
	if _, err := tmp.Write(data); err != nil {
		return cleanup(fmt.Errorf("fsatomic.WriteFile: write: %w", err))
	}
	if opts.Fsync {
		if err := tmp.Sync(); err != nil {
			return cleanup(fmt.Errorf("fsatomic.WriteFile: fsync: %w", err))
		}
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("fsatomic.WriteFile: close: %w", err)
	}
	if err := os.Chmod(tmpName, opts.FilePerm); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("fsatomic.WriteFile: chmod: %w", err)
	}
	// os.Rename over an existing file works on Windows
	// (MOVEFILE_REPLACE_EXISTING) and Go opens files with full share mode,
	// so a concurrent reader is normally fine — but the write can still fail
	// ERROR_ACCESS_DENIED against an AV scanner or the search indexer
	// holding the destination. Callers that must tolerate that retry briefly
	// (see cmd/observer's sidecar writer); this function does not retry, so
	// the policy stays with the caller that knows its own latency budget.
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("fsatomic.WriteFile: rename: %w", err)
	}
	if !opts.Fsync {
		return nil
	}
	// The directory flush is per OS (syncdir_*.go): POSIX needs it for the
	// rename to be durable; Windows cannot flush a directory handle.
	return syncDir(dir)
}
