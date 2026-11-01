//go:build !linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// terminal_sandbox_oci_other.go: the oci-runc row runs on Linux and WSL2
// only. Here the probe ladder stops at its platform row
// (unsupported_platform), and the helper verbs refuse.

func ociHost() sandboxoci.Host { return sandboxoci.HostOther }

func ociProbeEnv(context.Context, config.TerminalSandboxOCIConfig, string) sandboxoci.ProbeEnv {
	return sandboxoci.ProbeEnv{Host: sandboxoci.HostOther}
}

func readOwnedNoFollow(p string, limit int64) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > limit {
		return nil, fmt.Errorf("terminal_sandbox: %s is not a small regular file", p)
	}
	return os.ReadFile(p) //nolint:gosec // G304: a fixed path under the observer dir
}

func ociCreateExcl(p string) (*os.File, error) {
	return os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: a fixed path under the observer dir
}

func runOCIHost([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox (oci-runc): runs on Linux and WSL2 only")
	return 125
}

func runOCIInstallGuest([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox-oci-install: runs inside a Linux container only")
	return 127
}

func runOCIInit([]string) int {
	fmt.Fprintln(os.Stderr, "observer sandbox-oci-init: runs inside a Linux container only")
	return 127
}
