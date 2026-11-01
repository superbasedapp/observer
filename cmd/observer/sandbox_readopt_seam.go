//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
)

// sandbox_readopt_seam.go holds the two call-site seams of local
// re-adoption (lane GATES-SBX, gap G50): nil unless the re-adoption files
// are compiled (sandbox_readopt_linux.go sets them from init), and each
// returns at once while terminals.sandbox.oci.readopt is not selected, so
// the oci driver's compose and the reaper's sweep behave as before.

// ociReadoptBeforeSweep runs first in the oci reaper's sweep, before the
// records of dead helpers are pruned: a run that can be re-adopted is kept
// (its record re-keyed) and offered; one past its bound is ended.
var ociReadoptBeforeSweep func(ctx context.Context, c *sandboxengine.Client, installID, observerDir string)

// ociReadoptKeep runs in the oci driver's compose once the plan file is
// written: it keeps a copy of the plan and the host services' argv, so a
// run whose helper dies can be re-adopted (the helper removes the plan file
// when it reads it). cfg and tier are the settings and the network tier the
// run was launched under, kept so a re-adoption or a restore can refuse a
// plan wider than today's (audit F4).
var ociReadoptKeep func(observerDir, runID, planPath string, wrap []string, cfg config.TerminalSandboxConfig, tier string)
