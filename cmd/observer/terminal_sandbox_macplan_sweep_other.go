//go:build !unix && !sbo_omit_terminals_sandbox_seatbelt && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "log/slog"

// sweepStaleSeatbeltPlans has nothing to sweep off unix: the Seatbelt helper
// runs only on macOS.
func sweepStaleSeatbeltPlans(string, *slog.Logger) {}
