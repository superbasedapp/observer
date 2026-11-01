//go:build linux

package powerstate

import (
	"os"
	"path/filepath"
	"strings"
)

// sysfsRoot is where Linux lists its power supplies (a var for tests).
var sysfsRoot = "/sys/class/power_supply"

// Read returns the machine's power state from sysfs. A host that lists no
// supplies at all (a desktop, a container, WSL2 without a battery) is on
// mains.
func Read() State {
	entries, err := os.ReadDir(sysfsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return AC
		}
		return Unknown
	}
	var ss []Supply
	for _, e := range entries {
		dir := filepath.Join(sysfsRoot, e.Name())
		ss = append(ss, Supply{
			Type:   readAttr(dir, "type"),
			Online: readAttr(dir, "online"),
			Status: readAttr(dir, "status"),
			Scope:  readAttr(dir, "scope"),
		})
	}
	return Classify(ss)
}

func readAttr(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // G304: a fixed sysfs attribute under /sys/class/power_supply
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
