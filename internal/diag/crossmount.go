package diag

import (
	"fmt"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// crossmountHostFn reports whether this host has a foreign-OS side at all
// (a WSL distro, or Windows with WSL). Production reads the host; tests
// inject it so the row's presence never depends on the test machine.
var crossmountHostFn = func() bool { return runtime.GOOS == "windows" || crossmount.IsWSL() }

// checkCrossmountRow is the doctor's crossmount row (R-013): whether foreign-OS
// profiles are detected and written, and when they are not, the reason
// (crossmount.DetectionOffReason). It is present only on a host with a
// foreign side, so a plain Linux or macOS report is unchanged.
func checkCrossmountRow() (Check, bool) {
	if !crossmountHostFn() {
		return Check{}, false
	}
	return crossmountCheck(crossmount.DetectionOffReason(), len(crossmount.ExtraHomes())), true
}

// crossmountCheck renders the row from its two facts.
func crossmountCheck(offReason string, foreignHomes int) Check {
	if offReason != "" {
		return Check{
			Name:    "crossmount",
			Status:  StatusOK,
			Message: "foreign-OS profiles are not detected or written: " + offReason,
		}
	}
	return Check{
		Name:    "crossmount",
		Status:  StatusOK,
		Message: fmt.Sprintf("foreign-OS profile detection on (%d foreign home(s) found)", foreignHomes),
	}
}
