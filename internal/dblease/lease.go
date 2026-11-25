package dblease

import (
	"fmt"
	"os"
	"path/filepath"
)

// TryAcquire attempts to take a non-blocking, exclusive, cross-process
// advisory lease named name, backed by a lock file at
// filepath.Join(dir, name+".lock"). dir is typically the DB directory
// (filepath.Dir(cfg.Observer.DBPath)): callers share one dir across
// however many differently-named leases they take (e.g. "db-maintenance",
// "retention", "codeintel-index"), each getting its own lock file so they
// don't contend with one another.
//
// On unix this is a real syscall.Flock(LOCK_EX|LOCK_NB): a second
// TryAcquire for the same name (in this process or another) returns
// acquired=false while the first holder has it, and succeeds again once
// the first is released. Releasing is also automatic if the holding
// process exits or crashes (flock is held per open file description and
// the kernel drops it when the fd closes), so a lease can never be
// stranded held by a dead process. On windows it is LockFileEx with
// LOCKFILE_EXCLUSIVE_LOCK|LOCKFILE_FAIL_IMMEDIATELY on the file's first
// byte, with the same per-handle semantics. Elsewhere (plan9, js, wasip1)
// there is no non-blocking advisory-lock syscall wired here, so this
// degrades to always acquired=true (no cross-process coordination
// happens, but nothing is silently broken either; see [Available]).
//
// Fail-open by design: an error acquiring the lease (e.g. the lock
// directory can't be created) returns acquired=false with err set. It is
// NOT the same as "another process holds it": callers must check err
// first and proceed with their own work on any error, never skip it. Only
// acquired=false with err==nil means "skip, someone else has this."
func TryAcquire(dir, name string) (release func(), acquired bool, err error) {
	if name == "" {
		return noop, false, fmt.Errorf("dblease.TryAcquire: name is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return noop, false, fmt.Errorf("dblease.TryAcquire: ensure lock dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, name+".lock")
	return tryAcquireFile(path)
}

// Available reports whether TryAcquire provides real cross-process
// mutual exclusion on this platform (true on unix and windows). Elsewhere
// it is false (acquire degrades to a no-op success): informational
// only; callers are fail-open regardless and don't need to branch on
// this to behave correctly.
func Available() bool { return available }

func noop() {}
