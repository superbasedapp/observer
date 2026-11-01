//go:build !windows && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"syscall"

	"github.com/marmutapp/superbased-observer/internal/sandboxmxc"
)

// terminal_sandbox_mxc_other.go: the mxc-process row runs on native Windows
// only. Here the probe answers its platform row and the host verb refuses;
// nothing loads, opens or starts an MXC file.

func runMXCProbe([]string) int {
	res := sandboxmxc.Probe(sandboxmxc.HostFacts{Windows: false, Active: true}, sandboxmxc.ManifestX64)
	if err := json.NewEncoder(os.Stdout).Encode(res); err != nil {
		return 1
	}
	return 0
}

func runMXCHost([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (mxc-process): runs on native Windows 11 only")
	return 125
}

// createOwnerOnly creates path fresh, mode 0600, never through a link (the
// Windows twin sets a protected owner-only DACL).
func createOwnerOnly(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600) //nolint:gosec // G304: the run's config path under the observer dir
}
