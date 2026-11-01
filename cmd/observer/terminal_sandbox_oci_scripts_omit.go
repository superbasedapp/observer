//go:build sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// sandboxManagedInstallScriptsFloor sets nothing in a build without the
// container driver: no first-start install exists to floor.
func sandboxManagedInstallScriptsFloor(*config.TerminalSandboxConfig, orgcontract.SandboxManagedInstallScriptsV1) bool {
	return false
}

// sandboxInstallScriptsDoctorChecks says nothing in a build without the
// container driver.
func sandboxInstallScriptsDoctorChecks(config.TerminalSandboxConfig) []diag.Check { return nil }
