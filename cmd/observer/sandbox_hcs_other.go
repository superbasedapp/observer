//go:build !windows && !sbo_omit_terminals_sandbox_hcs && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxhcs"
)

// hcsGather off Windows gathers nothing: the ladder stops at its platform
// row.
func hcsGather(config.TerminalSandboxHCSConfig) sandboxhcs.Facts { return sandboxhcs.Facts{} }
