//go:build windows && !sbo_omit_terminals_sandbox_wslc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxwslc"
)

// wslcGather reads the wslc facts: the build, WSL, the CLI, its version
// and its run help (each bounded; nothing is created).
func wslcGather(ctx context.Context, cfg config.TerminalSandboxWSLCConfig) sandboxwslc.Facts {
	f := sandboxwslc.Facts{Windows: true, Build: int(windows.RtlGetVersion().BuildNumber), Image: strings.TrimSpace(cfg.Image)}
	run := func(name string, args ...string) (string, bool) {
		cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		b, err := exec.CommandContext(cctx, name, args...).Output() //nolint:gosec // G204: fixed argv, the resolved wsl and wslc binaries
		return string(b), err == nil
	}
	if p, err := exec.LookPath("wsl.exe"); err == nil {
		_, f.WSL = run(p, "--version")
	}
	path := strings.TrimSpace(cfg.Path)
	if path == "" {
		path, _ = exec.LookPath("wslc.exe")
	}
	if path == "" {
		return f
	}
	f.Path = path
	if out, ok := run(path, "--version"); ok {
		f.Version = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "wslc"))
	}
	f.Help, _ = run(path, "run", "--help")
	return f
}
