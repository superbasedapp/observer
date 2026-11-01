//go:build linux

package termsession

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestRealSpawnerKillEscalatesToSIGKILL pins the second rung of the unix
// teardown ladder (unixPTY.Kill: SIGTERM to the group, then SIGKILL to the
// group after a bound): a group member that ignores SIGTERM, as a bwrap
// namespace init does for a signal sent from outside its namespace, is still
// gone after the bound. The sandboxed-terminal teardown tests in cmd/observer
// signal the group themselves; this is the product ladder they rely on.
func TestRealSpawnerKillEscalatesToSIGKILL(t *testing.T) {
	const marker = "300.41"
	sp := NewOSSpawner()
	p, err := sp.Spawn(Spec{Kind: SpecSetup, SetupArgv: []string{"/bin/sh", "-c", "trap '' TERM; sleep " + marker + " & wait"}})
	if err != nil {
		t.Fatalf("real spawn: %v", err)
	}
	t.Cleanup(func() { _ = p.Kill() })
	go func() { // drain the master so the child never blocks on output
		buf := make([]byte, 4096)
		for {
			if _, rerr := p.Read(buf); rerr != nil {
				return
			}
		}
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !markerSleepRunning(marker) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if !markerSleepRunning(marker) {
		t.Fatal("the SIGTERM-ignoring group member never started")
	}

	waited := make(chan struct{})
	go func() { _, _ = p.Wait(); close(waited) }()
	start := time.Now()
	if err := p.Kill(); err != nil {
		t.Fatalf("Kill: %v", err)
	}
	// The ladder's bound is 2 s; allow generous slack for a loaded host.
	bound := 2*time.Second + 15*time.Second
	select {
	case <-waited:
	case <-time.After(bound):
		t.Fatalf("group leader that ignores SIGTERM still running %s after Kill", bound)
	}
	for markerSleepRunning(marker) {
		if time.Since(start) > bound {
			t.Fatalf("group member that ignores SIGTERM survived Kill for %s", bound)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// markerSleepRunning scans /proc for a live `sleep <marker>` process (a
// zombie has an empty cmdline and does not count).
func markerSleepRunning(marker string) bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if err != nil {
			continue
		}
		parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		if len(parts) == 2 && filepath.Base(parts[0]) == "sleep" && parts[1] == marker {
			return true
		}
	}
	return false
}
