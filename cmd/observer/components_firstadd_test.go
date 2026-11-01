package main

import (
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
)

// activeWithModuleRules is the active set the status surfaces report.
func activeWithModuleRules(snap componentstate.Snapshot) []string {
	var out []string
	for _, id := range snap.ActiveIDs() {
		if moduleRuleActive(snap, id) {
			out = append(out, id)
		}
	}
	return out
}

// TestFirstComponentsAddGrowsTheDefaultsByOne pins D-MU3 (live macOS install
// 2026-10-29, and scripts/install.sh --service): on a defaults install (no
// [components] block) `observer components add integration.service` writes
// a block with that add; the active set must be the defaults plus exactly
// that component, not every compiled component (114 to 129 before).
func TestFirstComponentsAddGrowsTheDefaultsByOne(t *testing.T) {
	const id = "integration.service"
	defaults := activeWithModuleRules(componentstate.Resolve(config.ComponentsConfig{}, nil))
	after := activeWithModuleRules(componentstate.Resolve(config.ComponentsConfig{Add: []string{id}}, nil))
	want := defaults
	if !slices.Contains(want, id) {
		want = append(slices.Clone(defaults), id)
		slices.Sort(want)
	}
	if !slices.Equal(after, want) {
		var extra, missing []string
		for _, a := range after {
			if !slices.Contains(want, a) {
				extra = append(extra, a)
			}
		}
		for _, w := range want {
			if !slices.Contains(after, w) {
				missing = append(missing, w)
			}
		}
		t.Fatalf("after add: %d active, want %d (defaults %d plus %s); extra %v, missing %v",
			len(after), len(want), len(defaults), id, extra, missing)
	}
	// Removing one component on a defaults install takes away exactly that one.
	const gone = "integration.mcp-server"
	removed := activeWithModuleRules(componentstate.Resolve(config.ComponentsConfig{Remove: []string{gone}}, nil))
	if slices.Contains(defaults, gone) {
		for _, a := range removed {
			if !slices.Contains(defaults, a) {
				t.Errorf("remove %s activated %s", gone, a)
			}
		}
	}
}
