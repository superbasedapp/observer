//go:build linux

package pidbridge

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// writeFenceStat lays down a synthetic /proc/<pid>/stat whose starttime
// field (ticks since boot) is startTicks, and a synthetic /proc/stat whose
// btime (boot epoch seconds) is bootEpoch — enough for processStartTime to
// be exercised without a real process table or a real boot.
func writeFenceStat(t *testing.T, dir string, pid int, startTicks int64) {
	t.Helper()
	pd := filepath.Join(dir, strconv.Itoa(pid))
	if err := os.MkdirAll(pd, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", pd, err)
	}
	// 20 fields after "(comm)": state ppid pgrp session tty_nr tpgid flags
	// minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
	// num_threads itrealvalue starttime — starttime is the 20th (index 19).
	line := fmt.Sprintf("%d (bash) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 %d\n", pid, startTicks)
	if err := os.WriteFile(filepath.Join(pd, "stat"), []byte(line), 0o644); err != nil {
		t.Fatalf("write stat: %v", err)
	}
}

func writeFenceBootEpoch(t *testing.T, dir string, bootEpoch int64) {
	t.Helper()
	content := fmt.Sprintf("cpu  0 0 0 0 0 0 0 0 0 0\nbtime %d\nprocesses 1\n", bootEpoch)
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(content), 0o644); err != nil {
		t.Fatalf("write /proc/stat: %v", err)
	}
}

func TestProcessStartTime(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	const bootEpoch = int64(1_700_000_000)
	writeFenceBootEpoch(t, dir, bootEpoch)
	// 500 * userHZ ticks = 500 seconds after boot.
	writeFenceStat(t, dir, 4242, 500*userHZ)

	got, ok := processStartTime(dir, 4242)
	if !ok {
		t.Fatal("processStartTime: want ok=true")
	}
	want := time.Unix(bootEpoch+500, 0).UTC()
	if !got.Equal(want) {
		t.Fatalf("processStartTime = %v, want %v", got, want)
	}

	t.Run("missing pid stat is unavailable", func(t *testing.T) {
		if _, ok := processStartTime(dir, 9999); ok {
			t.Fatal("want ok=false for a pid with no stat file")
		}
	})

	t.Run("missing boot stat is unavailable", func(t *testing.T) {
		empty := t.TempDir()
		writeFenceStat(t, empty, 4242, 500*userHZ)
		if _, ok := processStartTime(empty, 4242); ok {
			t.Fatal("want ok=false when /proc/stat has no btime")
		}
	})

	t.Run("non-positive pid is unavailable", func(t *testing.T) {
		if _, ok := processStartTime(dir, 0); ok {
			t.Fatal("want ok=false for pid<=0")
		}
	})

	t.Run("malformed stat line is unavailable", func(t *testing.T) {
		bad := t.TempDir()
		writeFenceBootEpoch(t, bad, bootEpoch)
		pd := filepath.Join(bad, "5150")
		if err := os.MkdirAll(pd, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(pd, "stat"), []byte("not a stat line\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, ok := processStartTime(bad, 5150); ok {
			t.Fatal("want ok=false for a malformed stat line")
		}
	})
}

func TestProcessStartTimePublicWrapper(t *testing.T) {
	// ProcessStartTime itself just delegates to /proc; a nonexistent pid
	// (vanishingly unlikely to exist on the test host) must degrade to
	// ok=false rather than panic.
	if _, ok := ProcessStartTime(1<<30 + 1); ok {
		t.Fatal("want ok=false for an implausible pid")
	}
}
