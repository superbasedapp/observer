//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

var budgetLaunchInterventionCandidates = nodeInterventionCandidates

// nodeProcessCutoffCoversLaunch admits a direct vendor process only when the
// live daemon attests process cutoff over the exact current install inventory
// and the launch resolves to that inventory's declared CLI surface. This is
// observed-process coverage; it does not claim request admission.
//
// COVERAGE IS PER SURFACE, NOT NODE-WIDE. The report's process_cutoff cell
// drops to "degraded" for a node-wide reason — one uninspectable same-UID
// process anywhere on the machine leaves the inventory incomplete — and gating
// on it made direct-launch recovery unreachable on any real workstation: every
// launch of every tool was refused because something unrelated could not be
// read. The question this function asks is narrower and answerable: is THIS
// surface bound, ready and controlled under the fingerprint the daemon is
// currently reconciling? ControlledSurfaces is exactly that per-surface
// witness, and the fingerprint check keeps it tied to this inventory.
func nodeProcessCutoffCoversLaunch(ctx context.Context, cfg config.Config, st *store.Store, tool string, evidence budgetLaunchEvidence) bool {
	if ctx == nil || st == nil || evidence.Executable == "" || evidence.Route == budgetLaunchRouteMaintenance {
		return false
	}
	// State "partial" is the live-reconciliation claim, and it is what holds
	// the report to the fast freshness bound (nodeInterventionStatusMaxAge).
	status, err := readNodeInterventionStatus(ctx, st, cfg.Observer.DBPath)
	if err != nil || status.State != "partial" || status.ManifestFingerprint == "" {
		return false
	}

	candidates := budgetLaunchInterventionCandidates()
	manifest, err := intervention.BuildInstallManifest(ctx, candidates)
	if err != nil || intervention.InstallManifestFingerprint(manifest) != status.ManifestFingerprint {
		return false
	}
	surfaceID := tool + "/cli"
	if !sortedStringContains(status.ControlledSurfaces, surfaceID) ||
		!resolvedLaunchCandidate(candidates, tool, surfaceID, evidence.Executable) {
		return false
	}
	surface, ok := manifest.Surface(surfaceID)
	if !ok || surface.Spec.Tool != tool || surface.State != intervention.BindingReady ||
		!surface.Spec.NativeUsage.Available() || !surfaceHasCurrentTarget(surface) {
		return false
	}
	leading, present := "", false
	if len(evidence.Arguments) > 0 {
		leading, present = evidence.Arguments[0], true
	}
	return intervention.ClassifyInvocation(surface.Spec.Binding.Invocation, leading, present) == intervention.InvocationCLI
}

func resolvedLaunchCandidate(candidates []intervention.InstalledCandidate, tool, surfaceID, executable string) bool {
	if !filepath.IsAbs(executable) {
		return false
	}
	launched, err := os.Stat(executable)
	if err != nil {
		return false
	}
	for _, candidate := range candidates {
		if candidate.Tool != tool || (candidate.SurfaceID != "" && candidate.SurfaceID != surfaceID) {
			continue
		}
		installed, err := os.Stat(candidate.LauncherPath)
		if err == nil && os.SameFile(launched, installed) {
			return true
		}
	}
	return false
}

func surfaceHasCurrentTarget(surface intervention.SurfaceManifest) bool {
	for _, target := range surface.Targets {
		if target.BoundProcess == nil {
			return true
		}
	}
	return false
}

func sortedStringContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
		if candidate > value {
			return false
		}
	}
	return false
}
