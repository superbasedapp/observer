//go:build linux

package powerstate

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReadSysfs reads a planted sysfs tree (not t.Parallel: it swaps the
// package's root).
func TestReadSysfs(t *testing.T) {
	saved := sysfsRoot
	t.Cleanup(func() { sysfsRoot = saved })
	root := t.TempDir()
	write := func(dev, name, v string) {
		d := filepath.Join(root, dev)
		_ = os.MkdirAll(d, 0o755)
		if err := os.WriteFile(filepath.Join(d, name), []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sysfsRoot = filepath.Join(root, "missing")
	if got := Read(); got != AC {
		t.Fatalf("no sysfs: %s", got)
	}
	sysfsRoot = root
	write("AC", "type", "Mains")
	write("AC", "online", "0")
	write("BAT0", "type", "Battery")
	write("BAT0", "status", "Discharging")
	if got := Read(); got != Battery {
		t.Fatalf("on battery: %s", got)
	}
	write("AC", "online", "1")
	if got := Read(); got != AC {
		t.Fatalf("on mains: %s", got)
	}

	// A desktop whose only battery is a wireless mouse (scope=Device).
	sysfsRoot = filepath.Join(root, "desktop")
	root = sysfsRoot
	write("hidpp_battery_0", "type", "Battery")
	write("hidpp_battery_0", "status", "Discharging")
	write("hidpp_battery_0", "scope", "Device")
	if got := Read(); got != AC {
		t.Fatalf("a mouse battery read as %s, want ac", got)
	}
}
