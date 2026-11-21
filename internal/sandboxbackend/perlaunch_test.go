package sandboxbackend

import "testing"

// TestPerLaunchDisclosures (lane HOOKS, SBXD-6): no_hook_gating is the one
// disclosure said per launch; every other one stays row-wide.
func TestPerLaunchDisclosures(t *testing.T) {
	for _, id := range IDs() {
		row, _ := Get(id)
		for _, d := range row.Discloses {
			if want := d == DiscloseNoHookGating; d.PerLaunch() != want {
				t.Errorf("%s: %s.PerLaunch() = %v, want %v", id, d, d.PerLaunch(), want)
			}
		}
	}
}
