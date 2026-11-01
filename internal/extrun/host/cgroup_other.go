//go:build unix && !linux

package host

import (
	"errors"
	"os"
)

// rlimitDataHolds: macOS and the BSDs do not hold a memory cap through
// RLIMIT_DATA (their allocators map memory outside the data segment), so
// the memory cap stays not enforced there.
const rlimitDataHolds = false

// selfPath is the running executable.
func selfPath(bool) (string, error) { return os.Executable() }

// joinCgroup: there are no cgroups here.
func joinCgroup(string) error { return errors.New("cgroups are Linux only") }

// cgroupCarries: nothing is carried by a cgroup here.
func cgroupCarries(int64, int64) (rel, memory, pids string) { return "", "", "" }
