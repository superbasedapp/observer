//go:build linux

package pidbridge

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// userHZ is the Linux ABI clock-tick rate (USER_HZ): /proc/<pid>/stat's
// starttime field is reported in 1/userHZ-second ticks since boot. It is
// fixed at 100 across all real Linux targets regardless of the kernel's
// CONFIG_HZ — the userspace ABI constant sysconf(_SC_CLK_TCK) returns — so
// this is hardcoded rather than taking a cgo/sysconf dependency, mirroring
// internal/processobs/poll/enum_linux.go's identical constant (duplicated,
// not imported: pidbridge stays independent of processobs, CLAUDE.md module
// boundary rule #1).
const userHZ = 100

// ProcessStartTime returns the wall-clock time pid's current occupant
// actually started, derived from /proc/<pid>/stat's starttime (ticks since
// boot) plus /proc/stat's btime (boot epoch seconds) — both read fresh, so
// this reflects whatever process holds pid RIGHT NOW, never a cached or
// stale value. ok=false whenever either read or parse fails; a caller
// fencing pid-reuse (Lookup) must treat that as "cannot verify" and refuse
// the row, never fall back to trusting it (see LookupSessionPID's own
// doc comment).
func ProcessStartTime(pid int) (time.Time, bool) {
	return processStartTime("/proc", pid)
}

// processStartTime is the testable core of ProcessStartTime; procDir is
// injected so tests can point it at a synthetic /proc tree.
func processStartTime(procDir string, pid int) (time.Time, bool) {
	if pid <= 0 {
		return time.Time{}, false
	}
	//nolint:gosec // procDir is either the real /proc or a test-injected tree.
	raw, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "stat"))
	if err != nil {
		return time.Time{}, false
	}
	startTicks, ok := parseStatStartTicks(string(raw))
	if !ok {
		return time.Time{}, false
	}
	bootEpoch, ok := readBootEpoch(procDir)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(bootEpoch+startTicks/userHZ, 0).UTC(), true
}

// parseStatStartTicks extracts starttime (field 22) from a /proc/<pid>/stat
// line's contents. The comm field is parenthesized and may itself contain
// spaces or ')', so this splits on the LAST ')' exactly like
// internal/processobs/poll/enum_linux.go's parseStat.
func parseStatStartTicks(s string) (int64, bool) {
	closeIdx := strings.LastIndexByte(s, ')')
	if closeIdx < 0 || closeIdx+2 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[closeIdx+2:])
	// After comm, fields are: state(0) ppid(1) ... starttime(19).
	if len(fields) < 20 {
		return 0, false
	}
	start, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil || start < 0 {
		return 0, false
	}
	return start, true
}

// readBootEpoch reads the "btime" line of /proc/stat: the kernel's boot
// time as a Unix epoch in whole seconds. It is independent of BootID (an
// opaque, unreversible random token) and of any particular process — the
// same value applies to every pid on this host at read time.
func readBootEpoch(procDir string) (int64, bool) {
	//nolint:gosec // procDir is either the real /proc or a test-injected tree.
	f, err := os.Open(filepath.Join(procDir, "stat"))
	if err != nil {
		return 0, false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		value, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		epoch, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil {
			return 0, false
		}
		return epoch, true
	}
	return 0, false
}
