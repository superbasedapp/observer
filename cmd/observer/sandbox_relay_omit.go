//go:build (sbo_omit_terminals_sandbox || sbo_omit_isolation) && !sbo_omit_terminals

package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// startSandboxRelay serves nothing in a build without the sandbox module:
// no box is ever planned, so no relay endpoint is needed.
func startSandboxRelay(context.Context, config.Config, string, *slog.Logger, sandboxRelayDeps) {
}

// sandboxRelayDeps mirrors the full build's wiring facts.
type sandboxRelayDeps struct {
	SessionOwner func(context.Context, string) (string, error)
	ManagedRoot  string
	LowerCapture func(ctx context.Context, terminalRunID string, h store.TerminalRunCaptureHealth) error
	EndRun       func(terminalRunID, endReason, notice string) bool
	// StampEndReason mirrors the full build's field.
	StampEndReason func(ctx context.Context, runID, reason string) error
	// EndGoneRun mirrors the full build's field.
	EndGoneRun func(ctx context.Context, runID, reason string) (bool, error)
	// Refusals mirrors the full build's field.
	Refusals any
}

// bindSandboxRelayRun binds nothing: no box is ever planned.
func bindSandboxRelayRun([]string, string) {}

// sandboxOOBSourceFor has no driver to ask: no run is ever relayed.
func sandboxOOBSourceFor([]string) (io.ReadCloser, bool) { return nil, false }

// relayPillHealth adds nothing: no run is ever relayed.
func relayPillHealth(*dashapi.LaunchIsolation, string) {}
