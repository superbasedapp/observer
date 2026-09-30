package db

import "os"

// IntegrityCheckSkipForSize is THE size gate for the whole-database
// `PRAGMA quick_check` ([observer.db].integrity_check_max_gb, T2.2 of the
// 2026-08-26 disk/compute remediation plan): skip when the file is larger
// than maxGB GiB. maxGB <= 0 disables the gate (never skip). quick_check
// reads every page of the file, so its cost scales with the database rather
// than with the work the caller came to do.
//
// ONE owner of that decision: the daemon's automatic startup pass
// (cmd/observer/diag.go::runStartupDBMaintenance) and `observer doctor`
// (internal/diag's db.integrity check) both ask this, so the two can never
// disagree about when the probe is too expensive to run unasked.
func IntegrityCheckSkipForSize(sizeBytes int64, maxGB int) bool {
	if maxGB <= 0 {
		return false
	}
	return sizeBytes > int64(maxGB)<<30
}

// IntegrityCheckShouldSkip applies IntegrityCheckSkipForSize to the database
// file at path. A stat failure fails OPEN (never skip): an unreadable size
// must not silently disable the probe. sizeBytes is 0 when the gate is
// disabled (maxGB <= 0, no stat is taken) or the stat failed.
func IntegrityCheckShouldSkip(path string, maxGB int) (skip bool, sizeBytes int64) {
	if maxGB <= 0 {
		return false, 0
	}
	fi, err := os.Stat(path)
	if err != nil {
		return false, 0
	}
	sizeBytes = fi.Size()
	return IntegrityCheckSkipForSize(sizeBytes, maxGB), sizeBytes
}
