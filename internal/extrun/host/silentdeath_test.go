package host

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/extrun"
)

// TestSilentDeathTable: only a trampoline that started inside a capped
// cgroup rung and then died is a cap failure; a launcher that failed with
// its own words, and every uncapped or non-cgroup start, is a rung error
// (decision log P-023).
func TestSilentDeathTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		rung     extrun.Rung
		children int
		started  bool
		stderr   string
		want     deathKind
	}{
		{"launcher failed with its own stderr, cap at the floor", extrun.RungCgroup, trampolineMinTasks, false, "Failed to start transient scope unit: Access denied", deathRung},
		{"launcher failed, cap above the floor", extrun.RungCgroup, 64, false, "Failed to connect to bus: No medium found", deathRung},
		{"launcher failed with nothing said", extrun.RungCgroup, 64, false, "", deathRung},
		{"trampoline started then died, capped cgroup", extrun.RungCgroup, 64, true, "", deathCap},
		{"trampoline's Go runtime could not make a thread", extrun.RungCgroup, 64, false, "runtime: failed to create new OS thread (have 7 already; errno=11)", deathCap},
		{"cgo thread refused", extrun.RungCgroup, 32, false, "runtime/cgo: pthread_create failed: Resource temporarily unavailable", deathCap},
		{"trampoline started then died, no cap", extrun.RungCgroup, 0, true, "", deathRung},
		{"trampoline started then died, pid namespace rung", extrun.RungPIDNamespace, 64, true, "", deathRung},
		{"process group rung", extrun.RungProcessGroup, 64, true, "runtime: failed to create new OS thread", deathRung},
	}
	for _, tc := range cases {
		if got := silentDeath(tc.rung, tc.children, tc.started, []byte(tc.stderr)); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
