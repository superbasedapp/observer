package componentsvc

import (
	"strings"
	"testing"
)

// TestServiceTeardownWordedPerOS pins N4 (live Mac 2026-10-29): the
// integration.service teardown names the host's own service manager, never
// the systemd unit on macOS.
func TestServiceTeardownWordedPerOS(t *testing.T) {
	prev := teardownGOOS
	t.Cleanup(func() { teardownGOOS = prev })
	for goos, want := range map[string]string{
		"linux":   "systemd unit",
		"darwin":  "LaunchAgent",
		"windows": "autostart off",
		"freebsd": "service unit",
	} {
		teardownGOOS = goos
		steps := TeardownFor("integration.service")
		if len(steps) != 1 {
			t.Fatalf("%s: steps = %+v", goos, steps)
		}
		if !strings.Contains(steps[0].What, want) {
			t.Errorf("%s: %q, want it to name %q", goos, steps[0].What, want)
		}
		if goos != "linux" && strings.Contains(steps[0].What, "systemd") {
			t.Errorf("%s: %q names systemd", goos, steps[0].What)
		}
	}
}
