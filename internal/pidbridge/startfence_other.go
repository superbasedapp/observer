//go:build !linux

package pidbridge

import "time"

// ProcessStartTime always reports ok=false on non-Linux builds: without
// /proc there is no cheap, reliable way to read a live process's start
// time. Callers fencing pid reuse (LookupSessionPID) treat that as
// "cannot verify" and refuse the row, the same fail-closed posture
// ValidateLocalProcess documents for its own non-Linux case.
func ProcessStartTime(int) (time.Time, bool) {
	return time.Time{}, false
}
