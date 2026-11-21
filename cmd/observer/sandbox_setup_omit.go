//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// sandbox_setup_omit.go is the omit twin of sandbox_setup.go and
// sandbox_setup_download.go: a build without the sandbox module (or without
// terminals) has no sandbox setup, so newSandboxSetup is nil (the routes
// answer 501) and nothing downloads.

// sandboxSetupOptions mirrors the module build's options. Ledger is any here
// because a build without terminals has no install ledger type.
type sandboxSetupOptions struct {
	ConfigPath string
	Surface    string
	Spawn      func(ctx context.Context, argv []string, label string) (handle string, exitCode int, err error)
	Ledger     any
	Logger     *slog.Logger
	Now        func() time.Time
}

// newSandboxSetup is nil in this build.
func newSandboxSetup(sandboxSetupOptions) dashapi.SandboxSetup { return nil }

// sandboxDownloadRequest mirrors the module build's request.
type sandboxDownloadRequest struct {
	Pin      string
	FromFile string
	Managed  bool
	Progress func(done, total int64)
}

// sandboxDownloadResult mirrors the module build's result.
type sandboxDownloadResult struct {
	Path, SHA256, Source, Version string
	Bytes                         int64
}

// sandboxSetupDownload places nothing in this build.
func sandboxSetupDownload(context.Context, sandboxDownloadRequest) (sandboxDownloadResult, error) {
	return sandboxDownloadResult{}, errors.New("sandbox setup is not in this build")
}

// Referenced until lane daemon wires them.
var (
	_ = newSandboxSetup
	_ = sandboxSetupDownload
)
