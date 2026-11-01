//go:build !windows

package sandboxmxcdll

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// HostEnv is the real I/O; off Windows the ladder stops at its platform
// row, so nothing here opens a file or loads a library.
func HostEnv(dir string, active bool, probeDoc, checkDoc []byte) Env {
	return Env{Windows: false, Active: active, Dir: dir, ProbeDoc: probeDoc, CheckDoc: checkDoc}
}

// InsideAppContainer reports whether this process runs with an AppContainer
// token (the box-side relay decision); never true off Windows.
func InsideAppContainer() bool { return false }

// AppContainerSID is the Windows token's AppContainer SID; never an
// AppContainer off Windows.
func AppContainerSID() (string, bool) { return "", false }

// AppContainerProfileSID derives an AppContainer profile's SID on Windows
// only.
func AppContainerProfileSID(string) (string, error) {
	return "", errors.New("sandboxmxcdll: AppContainer profiles exist on Windows only")
}

// ProcessTree reads a process tree on Windows only.
func ProcessTree(uint32) (sandboxmxc.BoxProcess, []sandboxmxc.BoxProcess, error) {
	return sandboxmxc.BoxProcess{}, nil, errors.New("sandboxmxcdll: process tokens are read on Windows only")
}
