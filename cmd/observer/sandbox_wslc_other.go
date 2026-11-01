//go:build !windows && !sbo_omit_terminals_sandbox_wslc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxwslc"
)

// wslcGather off Windows gathers nothing: the ladder stops at its platform
// row.
func wslcGather(context.Context, config.TerminalSandboxWSLCConfig) sandboxwslc.Facts {
	return sandboxwslc.Facts{}
}
