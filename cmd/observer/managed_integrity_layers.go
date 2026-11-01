package main

import (
	"context"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// managed_integrity_layers.go adds the settings-layer reading to the
// managed-integrity report (surface-gap arc decision DEC-7, lane w4-wire;
// findings CLI-5 and OBS-9): the tools whose Observer hooks a vendor
// settings layer switches off (the hook-off table internal/hookdisable,
// through diag.HookSwitchInputs, the same inputs as the doctor's
// hooks.disabled row and the daemon's hook-off watch), and what the
// effective-layer evaluator (agentconfigsvc.EffectiveLayers, the doctor's
// config.layers row) finds that weakens capture or routing. Both read the
// user, system, managed and environment layers plus the project layers of
// the most recently active projects the store knows. Only closed tool ids
// and "tool/finding" labels cross the wire: no path, project, key or value.

// configLayerSource reads the node-local inputs of the step. Roots must be
// set (a node that cannot list its projects does not report); Switches and
// Layers may be nil (that half reads nothing).
type configLayerSource struct {
	// Roots lists the project directories to read, most recent first.
	Roots func(ctx context.Context) ([]string, error)
	// Switches returns the hook-off switches currently set at the user,
	// managed, environment and roots' project layers.
	Switches func(roots []string) []hookdisable.Finding
	// Layers returns the effective-layer evaluator's findings over the same
	// layers.
	Layers func(ctx context.Context, roots []string) ([]agentconfig.LayerFinding, error)
}

// storeConfigLayerSource is the production source: the project roots come
// from the node store (the same bounded, most-recent-first list as the
// doctor). The environment goes through the pinned-home rule
// (crossmount.HomeEnvAt for the home it reads, R-188 F1, FU-129): the
// daemon's own environment, except under an isolated home (HOME=/tmp/x
// observer start) or a home that is not the process's own,
// where no variable is read, so CLAUDE_CONFIG_DIR and the other relocation
// variables move the files this reads exactly as they move the settings
// editor's and the hook registration's (FU-140 audit follow-up 1).
func storeConfigLayerSource(st projectRootLister, home string) *configLayerSource {
	return newConfigLayerSource(st, configLayerHost{Home: home, GOOS: runtime.GOOS, Getenv: crossmount.HomeEnvAt(home, nil), PolicyDomains: hook.PolicyDomainLayers})
}

// configLayerHost is where the source reads: the home, the GOOS whose
// system and managed files are read, the environment, and (tests only) a
// SystemRoot that re-roots the evaluator's system paths. GOOS "" reads no
// managed or system file, the doctor's sandboxed reading. PolicyDomains
// reads the OS preferences domains under a home (hook.PolicyDomainLayers in
// production, FU-105: IBM Bob's macOS user domain, key names only); its
// second argument is whether managed (system) domains are read too. Nil
// reads none.
type configLayerHost struct {
	Home          string
	GOOS          string
	Getenv        func(string) string
	SystemRoot    string
	PolicyDomains func(home string, system bool) []agentconfig.RuntimeTree
}

// newConfigLayerSource is storeConfigLayerSource with the host injected.
func newConfigLayerSource(st projectRootLister, h configLayerHost) *configLayerSource {
	if st == nil || h.Home == "" {
		return nil
	}
	svcOpts := agentconfigsvc.Options{Home: h.Home, GOOS: h.GOOS, Getenv: h.Getenv, SystemRoot: h.SystemRoot}
	return &configLayerSource{
		Roots: func(ctx context.Context) ([]string, error) {
			return st.RecentProjectRoots(ctx, hookdisable.MaxProjectRoots)
		},
		Switches: func(roots []string) []hookdisable.Finding {
			return hookdisable.Detect(diag.HookSwitchInputs(hookdisable.Options{
				Home: h.Home, GOOS: h.GOOS, ProjectRoots: roots, Getenv: h.Getenv, ReadFile: diag.ReadHookSwitchFile,
			}))
		},
		Layers: func(ctx context.Context, roots []string) ([]agentconfig.LayerFinding, error) {
			var trees []agentconfig.RuntimeTree
			if h.PolicyDomains != nil {
				trees = h.PolicyDomains(h.Home, h.GOOS != "")
			}
			rep, err := agentconfigsvc.New(svcOpts).
				EffectiveLayers(ctx, agentconfigsvc.LayerOptions{Projects: roots, OwnHookCommand: hook.IsObserverHookCommand, Runtime: trees})
			if err != nil {
				return nil, err
			}
			return rep.Findings, nil
		},
	}
}

// addConfigLayers fills report.ConfigLayerVersion, HookDisabledTools and
// ConfigLayerRisks, and their derived capture-risk labels. With no source,
// or a read that fails, the version stays 0: the organization reads "not
// reported", never "clean".
//
// A switch that only stops a host replaying another tool's hooks
// (hookdisable ReplayOnly) is not counted: Observer's own hooks for that
// tool keep running. An informational evaluator finding has no wire label
// and is left out. A tool or finding that should cross but has no wire
// label (the pin tests diag.TestConfigLayerToolsAreWireLabels and
// TestConfigLayerRiskCodesMatchTheDoctor keep that from happening) is not
// dropped silently: when nothing labelled is left, the reading is not
// reported at all, so it can never read as clean.
func addConfigLayers(ctx context.Context, src *configLayerSource, report *orgcontract.ManagedIntegrityReport) {
	if report == nil || src == nil || src.Roots == nil {
		return
	}
	roots, err := src.Roots(ctx)
	if err != nil {
		return
	}
	var switches []hookdisable.Finding
	if src.Switches != nil {
		switches = src.Switches(roots)
	}
	var layers []agentconfig.LayerFinding
	if src.Layers != nil {
		fs, err := src.Layers(ctx, roots)
		if err != nil {
			return
		}
		layers = fs
	}
	var hookTools, risks []string
	unlabelled := false
	for _, f := range switches {
		if f.ReplayOnly {
			continue
		}
		for _, tool := range f.Tools {
			if !orgcontract.ValidConfigLayerTool(tool) {
				unlabelled = true
				continue
			}
			hookTools = appendLabel(hookTools, tool)
		}
	}
	for _, f := range layers {
		label, ok := orgcontract.ConfigLayerRiskLabel(f.Tool, string(f.Code))
		if !ok {
			// An informational code is not a risk; any other miss is a
			// tool or code the wire vocabulary lacks.
			if diag.LayerFindingWarns(f.Code) {
				unlabelled = true
			}
			continue
		}
		risks = appendLabel(risks, label)
	}
	if unlabelled && len(hookTools) == 0 && len(risks) == 0 {
		return
	}
	report.ConfigLayerVersion = orgcontract.ManagedConfigLayerVersion
	report.HookDisabledTools = hookTools
	report.ConfigLayerRisks = risks
	if len(hookTools) > 0 {
		report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskHookSwitchedOff)
	}
	if len(risks) > 0 {
		report.CaptureRisks = appendLabel(report.CaptureRisks, orgcontract.CaptureRiskConfigLayerOverride)
	}
}
