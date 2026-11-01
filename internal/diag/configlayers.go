package diag

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// checkConfigLayers runs the effective-layer evaluator (surface-gap Wave 4,
// lane w4-layers) over the AI tools' own config layers: the user, system and
// managed files, and the project files of the most recently active projects
// the store knows (at most agentconfigsvc.LayerMaxProjects, OBS-9). It reports
// a layer that decides against Observer: a project or local settings file,
// an IDE setting or the launch environment that shadows Observer's route
// (CC-4, CLI-2, IDE-3, CLI-7), a hook switch or a replaced hook array that
// silences Observer's hooks (CLI-5, W-6), a saved sign-in mode that pins the
// vendor host (CLI-6), an active provider Observer's route does not cover
// (CLI-3), a first-file-wins MCP search (S-22), and a tool policy key the
// user's own OS preferences domain sets (IBM Bob on macOS, FU-105).
//
// Report only: nothing is written. No value is shown, only the file, the
// key and a coarse class. getenv is DoctorOptions.Getenv (the launch
// environment and relocation variables; nothing on a sandboxed run unless
// the caller injected it). A sandboxed run (homeOverride set) reads no
// system file, so it stays inside the override home.
//
// Named "config.layers" so `observer doctor config` scopes to it.
func checkConfigLayers(ctx context.Context, homeDir, homeOverride string, roots []string, getenv func(string) string) Check {
	const name = "config.layers"
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	o := agentconfigsvc.Options{Home: homeDir, GOOS: runtime.GOOS, Getenv: getenv}
	if homeOverride != "" {
		o.SystemRoot = filepath.Join(homeOverride, ".observer-doctor-no-system")
	}
	// The OS preferences domains (IBM Bob's on macOS, FU-105), by key name;
	// a sandboxed run reads the override home's user domain and no managed
	// one.
	runtimeTrees := hook.PolicyDomainLayers(homeDir, homeOverride == "")
	rep, err := agentconfigsvc.New(o).EffectiveLayers(ctx, agentconfigsvc.LayerOptions{Projects: roots, OwnHookCommand: hook.IsObserverHookCommand, Runtime: runtimeTrees})
	if err != nil {
		return Check{Name: name, Status: StatusWarn, Message: "the effective-layer evaluator could not run: " + err.Error()}
	}
	return configLayersCheck(name, rep, len(roots), runtime.GOOS)
}

// layerAdvice is the per-code doctor wording, and whether the code warns.
// One row per agentconfig.FindingCode (TestLayerAdviceCoversEveryCode).
var layerAdvice = map[agentconfig.FindingCode]struct {
	warn   bool
	advice string
}{
	agentconfig.FindingProjectRouteOverride: {true, "this project's file decides the route, so the tool bypasses Observer's proxy here; remove the key or point it at the proxy"},
	agentconfig.FindingRouteShadowed:        {true, "a higher layer outranks Observer's route, so turns bypass the proxy"},
	agentconfig.FindingIDERouteOverride:     {true, "the IDE hands the agent this base URL when it runs inside the IDE (whether it beats the settings file is live check 3)"},
	agentconfig.FindingProjectHooksDisabled: {true, "this project's file turns the tool's hooks off, so Observer's gates do not run here"},
	agentconfig.FindingHooksDisabled:        {true, "the tool's hooks are off, so Observer's gates do not run"},
	agentconfig.FindingHooksOffOverridden:   {false, "a lower layer turns hooks off, but this file turns them back on, so they run"},
	agentconfig.FindingHookArrayReplaced:    {true, "a higher layer's hook array replaces the one holding Observer's group, so Observer's hook does not run here"},
	agentconfig.FindingLayersDropped:        {true, "this setting drops the user layer, Observer's hooks included"},
	agentconfig.FindingMCPFirstFileOnly:     {false, "the tool reads only this MCP file; the others listed are ignored"},
	agentconfig.FindingAuthPinsVendorHost:   {true, "this sign-in mode talks to the vendor directly whatever base URL is set, so turns bypass the proxy"},
	agentconfig.FindingInactiveProvider:     {true, "the active provider is not the one Observer's route is written for, so turns bypass the proxy"},
	agentconfig.FindingProviderUnverified:   {false, "whether this provider honours Observer's route is not verified yet"},
	agentconfig.FindingUserPolicyOverride:   {true, "the user's own preferences domain sets this policy key and the tool applies it as policy; it is user-set, not tamper-proof administrator policy (runtime:user_prefs wins when the administrator did not set the key; runtime:managed_prefs means the administrator set it too and the managed value is expected to win, not verified live)"},
}

// layerAdviceByOS is layerAdvice's wording for a code on one OS where the
// default wording names another OS's mechanism (FU-187): on Windows the
// user-set policy source is the per-user HKCU policy key, not a macOS
// preferences domain. Which of it and the HKLM key wins is live-grounded for
// EnforcedHooks (HKLM whenever it sets the key, FU-177 GUI run, FU-206) and
// not verified live for any other key.
var layerAdviceByOS = map[agentconfig.FindingCode]map[string]string{
	agentconfig.FindingUserPolicyOverride: {
		"windows": "the user's own HKCU policy key (" + hook.IBMBobHKCUPolicySource + " for IBM Bob) sets this policy key and the tool applies it as policy; it is user-set, not tamper-proof administrator policy (runtime:user_prefs wins when the administrator's " + hook.IBMBobHKLMPolicySource + " key did not set it; runtime:managed_prefs means the administrator set it too: " + hook.IBMBobEnforcedHooksPrecedence + "; for any other key, which value the tool applies is not verified live)",
	},
}

// layerAdviceFor is code's doctor wording on goos.
func layerAdviceFor(code agentconfig.FindingCode, goos string) string {
	if s, ok := layerAdviceByOS[code][goos]; ok {
		return s
	}
	return layerAdvice[code].advice
}

// LayerFindingWarns reports whether code is a finding the config.layers row
// warns on: one that weakens capture or routing. It is the node half of the
// managed-integrity `config_layer_risks` vocabulary (orgcontract
// ConfigLayerRiskCodes; TestConfigLayerRiskCodesMatchTheDoctor holds the two
// together).
func LayerFindingWarns(code agentconfig.FindingCode) bool { return layerAdvice[code].warn }

// configLayersCheck renders one pass; goos picks the per-OS wording
// (runtime.GOOS in production).
func configLayersCheck(name string, rep agentconfigsvc.LayerReport, projects int, goos string) Check {
	if len(rep.Findings) == 0 {
		return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("no config layer decides against Observer (user, system and %d project(s) read)", projects)}
	}
	status := StatusOK
	tools := map[string]bool{}
	details := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		a := layerAdvice[f.Code]
		if a.warn {
			status = StatusWarn
			tools[f.Tool] = true
		}
		src := rep.Path(f)
		if src == "" {
			src = f.Winning.String()
		}
		where := ""
		if f.Project != "" {
			where = " in project " + f.Project
		}
		details = append(details, fmt.Sprintf("%s %s: %s (%s, from %s)%s: %s", f.Tool, f.Key, f.Code, f.Class, src, where, layerAdviceFor(f.Code, goos)))
	}
	sort.Strings(details)
	if status == StatusOK {
		return Check{Name: name, Status: StatusOK, Message: fmt.Sprintf("%d informational config layer note(s)", len(details)), Details: details}
	}
	names := make([]string, 0, len(tools))
	for t := range tools {
		names = append(names, t)
	}
	sort.Strings(names)
	return Check{
		Name: name, Status: StatusWarn,
		Message: fmt.Sprintf("%d config layer finding(s) decide against Observer on %s", len(details), strings.Join(names, ", ")),
		Details: details,
	}
}
