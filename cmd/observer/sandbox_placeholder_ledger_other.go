//go:build !linux && !darwin && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "log/slog"

// sweepStaleSandboxPlaceholders has nothing to sweep off Linux and macOS: the
// host helper's placeholder ledger (sandbox_placeholder_ledger_unix.go) is
// written only by the Linux and macOS host helpers.
func sweepStaleSandboxPlaceholders(string, *slog.Logger) {}
