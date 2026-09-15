// adapter_registry_sync_test.go pins the three sources of truth for the
// registered adapter set so the enabled_adapters startup warning can never
// silently lose coverage: the watcher's defaults.Adapters(), the
// internal/integration capability registry, and config.Default()'s
// EnabledAdapters allow-list must all agree (modulo the sanctioned
// package-less roo-code and zoo-code entries).
package invariant

import (
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// packagelessAdapters are tool names that legitimately appear in the
// default EnabledAdapters allow-list WITHOUT a corresponding adapter
// package (and therefore no defaults.Adapters() entry and no
// integration registry row). roo-code is enabled for forward-compat
// but has no parser package yet. zoo-code (added 2026-09-03, ticket
// U1) is the same shape: ZooCode, the community continuation of Roo
// Code, is parsed by internal/adapter/cline's clineExtensions table
// and retagged per-file — no adapter package or registry row of its
// own, exactly like roo-code. These are the ONLY sanctioned
// asymmetries; everything else must agree across all three sources of
// truth.
var packagelessAdapters = map[string]struct{}{
	"roo-code": {},
	"zoo-code": {},
}

// TestAdapterRegistrySourcesAgree pins the three sources of truth for
// "which adapters exist" so the enabled_adapters startup warning can
// never silently shrink its coverage:
//
//   - defaults.Adapters()                 — the watcher's registered set
//     AND the input to warnMissingDefaultsFromAllowList (the warning can
//     only flag a missing adapter it knows about).
//   - integration.Capabilities()          — the one-owner capability
//     registry (CLAUDE.md #3/#5).
//   - config.Default().EnabledAdapters    — what a fresh install enables.
//
// A new adapter must land in all three (registry row + defaults entry +
// default allow-list). Adding it to only one — e.g. the integration
// registry but not defaults.go — would make the startup warning blind to
// it: a user's explicit allow-list could omit it forever with no WARN.
// This test makes that omission a loud build failure instead.
func TestAdapterRegistrySourcesAgree(t *testing.T) {
	defaultsSet := map[string]struct{}{}
	for _, a := range defaults.Adapters() {
		defaultsSet[a.Name()] = struct{}{}
	}
	registrySet := map[string]struct{}{}
	for _, c := range integration.Capabilities() {
		registrySet[c.Tool] = struct{}{}
	}
	allowSet := map[string]struct{}{}
	for _, t := range config.Default().Observer.Watch.EnabledAdapters {
		allowSet[t] = struct{}{}
	}

	// 1) defaults.Adapters() and the integration registry must name the
	//    exact same adapters (no package-less exceptions here — every
	//    parser package has a registry row and vice versa).
	if diff := symmetricDiff(defaultsSet, registrySet); len(diff) > 0 {
		t.Errorf("defaults.Adapters() and integration.Capabilities() disagree on: %v\n"+
			"  every adapter package must have an integration registry row and vice versa", diff)
	}

	// 2) Every defaults adapter must be in the default allow-list, or a
	//    fresh install silently won't scan it.
	for name := range defaultsSet {
		if _, ok := allowSet[name]; !ok {
			t.Errorf("adapter %q is registered (defaults.Adapters) but absent from config.Default() EnabledAdapters — fresh installs won't scan it", name)
		}
	}

	// 3) Every default-allow-list entry must be a real adapter, except
	//    the sanctioned package-less names (roo-code).
	for name := range allowSet {
		if _, ok := defaultsSet[name]; ok {
			continue
		}
		if _, sanctioned := packagelessAdapters[name]; sanctioned {
			continue
		}
		t.Errorf("config.Default() EnabledAdapters names %q which has no adapter package — add the package or list it in packagelessAdapters", name)
	}
}

// symmetricDiff returns the names present in exactly one of a or b.
func symmetricDiff(a, b map[string]struct{}) []string {
	var diff []string
	for k := range a {
		if _, ok := b[k]; !ok {
			diff = append(diff, "only-in-defaults:"+k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			diff = append(diff, "only-in-registry:"+k)
		}
	}
	sort.Strings(diff)
	return diff
}
