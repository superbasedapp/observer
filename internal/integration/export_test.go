package integration

import "strings"

// Accessors only this package's tests use. They lived in the production
// files beside the tables they read; nothing outside the tests called them,
// so they are compiled into test builds only (export_test.go is also how
// the integration_test package reaches NewToolReasons and
// JetBrainsProductHosts).

// AllRouteKinds is the closed RouteKind vocabulary, for coverage sweeps that
// must prove every kind has a defined behaviour.
func AllRouteKinds() []RouteKind {
	return []RouteKind{
		RouteLauncher, RouteEnvSettings, RouteConfigFile, RouteProviderJSON,
		RouteVSCodeSettings, RouteManual,
	}
}

// CodingSurfacesFor returns the rows of one doctor group.
func CodingSurfacesFor(group string) []CodingSurface {
	var out []CodingSurface
	for _, s := range CodingSurfaces() {
		if s.Group() == group {
			out = append(out, s)
		}
	}
	return out
}

// LiveCheckRefs splits a cell's LiveCheck ("LC16, LC24") into ids.
func LiveCheckRefs(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// NewToolReasons returns newToolReasons as a copy, for the pin test and the
// lane report.
func NewToolReasons() map[string]string {
	out := make(map[string]string, len(newToolReasons))
	for k, v := range newToolReasons {
		out[k] = v
	}
	return out
}

// FU57Elsewhere returns fu57Elsewhere as a copy, for the pin test and the
// lane report.
func FU57Elsewhere() map[int]string {
	out := make(map[int]string, len(fu57Elsewhere))
	for k, v := range fu57Elsewhere {
		out[k] = v
	}
	return out
}

// HasDisplayName reports whether tool has a known product name (so a caller
// can tell a resolved name from the id echoed back).
func HasDisplayName(tool string) bool {
	_, ok := displayNames[tool]
	return ok
}

// InstallerKinds returns the closed installer vocabulary.
func InstallerKinds() []InstallerKind { return append([]InstallerKind(nil), installerKinds...) }

// JetBrainsProductHosts returns the product host tokens the hook surface
// rows are declared for, for the pin test.
func JetBrainsProductHosts() []string { return append([]string(nil), jetbrainsProductHosts...) }

// KnownHookDecision reports whether d is in the closed decision vocabulary.
func KnownHookDecision(d string) bool { return hookDecisions[d] }

// ValidPhase reports whether phase is in c's closed phase set. An unknown
// capability admits no phase.
func (c HookCap) ValidPhase(phase string) bool {
	for _, p := range hookCapPhases[c] {
		if p == phase {
			return true
		}
	}
	return false
}

// NativeSandboxTools lists the tools with a native sandbox row.
func NativeSandboxTools() []string {
	out := make([]string, 0, len(nativeSandboxes))
	for t := range nativeSandboxes {
		out = append(out, t)
	}
	return out
}

// StatusLineTools returns every tool with a grounded status-line command
// (Kind != StatusLineNone), unsorted.
func StatusLineTools() []string {
	out := make([]string, 0, len(statusLines))
	for t, s := range statusLines {
		if s.Kind != StatusLineNone {
			out = append(out, t)
		}
	}
	return out
}

// WindowsHookRunnerFor returns tool's Windows hook-runner precondition, read
// from its registry row's HookSpec.WindowsRunner. A "-windows" cross-OS
// target answers for its base row. ok is false when the row declares none.
func WindowsHookRunnerFor(tool string) (WindowsHookRunner, bool) {
	c, found := For(strings.TrimSuffix(tool, "-windows"))
	if !found || !c.Hook.WindowsRunner.Declared() {
		return WindowsHookRunner{}, false
	}
	return runnerOf(c), true
}
