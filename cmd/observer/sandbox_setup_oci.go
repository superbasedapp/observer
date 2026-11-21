//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// sandbox_setup_oci.go gives sandbox setup's passive engine-socket fact the
// oci driver's own candidate list, so the setup plan and the probe look at
// the same paths and a build without the oci driver does not link it.

func init() {
	sandboxSetupEngineSocket = sandboxSetupOCIEngineSocket
}

// sandboxSetupOCIEngineSocket is the first container engine socket that
// exists: [terminal.sandbox.oci].socket when set, else the probe's candidate
// paths (sandboxoci.Candidates). A stat only, never a dial.
func sandboxSetupOCIEngineSocket(cfg config.Config) string {
	cands := []string{}
	if s := strings.TrimSpace(cfg.Terminal.Sandbox.OCI.Socket); s != "" {
		cands = append(cands, strings.TrimPrefix(s, "unix://"))
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" && runtime.GOOS != "windows" {
		runtimeDir = "/run/user/" + strconv.Itoa(os.Getuid())
	}
	cands = append(cands, sandboxoci.Candidates(runtimeDir)...)
	for _, c := range cands {
		if fi, err := os.Stat(c); err == nil && fi.Mode()&os.ModeSocket != 0 { //nolint:gosec // G703: a metadata read of the engine's own socket paths; never a dial
			return c
		}
	}
	return ""
}
