package poolside

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// TestPrivateMappingAgreesWithTooltax is the WP-T3 conformance pin for an
// adapter that has NOT (yet) been converted to read internal/tooltax
// directly. Plan of record:
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §2 — "until
// an adapter is converted, a conformance test pins its private map as a
// subset of the tooltax table so drift is loud without a big-bang
// rewrite".
//
// The private classifier here is the package-private actionMap, keyed by
// the LITERAL native name (records.go) — poolside's native tool names are
// exact-match, unlike muse's normalized keys.
//
// It is a SUBSET check, deliberately: tooltax is allowed to know MORE
// native names than this adapter does. What it may NOT do is DISAGREE
// about a name the adapter already classifies.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	checked := 0
	for _, e := range tooltax.Table() {
		if e.Tool != models.ToolPoolside || e.IsGlob() {
			continue
		}
		got := actionMap[e.Native]
		if got == "" || got == models.ActionUnknown {
			continue
		}
		checked++
		if got != e.ActionType {
			t.Errorf("drift: %s %q — adapter classifies as %q, tooltax table says %q",
				models.ToolPoolside, e.Native, got, e.ActionType)
		}
	}
	if checked == 0 {
		t.Errorf("no %s row in the tooltax table reached the adapter's classifier — "+
			"the pin is vacuous (did the tool id or the classifier change?)", models.ToolPoolside)
	}
}

// TestPrivateActionMapIsSubsetOfTooltax pins the OTHER direction: every
// name the map classifies must exist in the tooltax table with the SAME
// action type.
func TestPrivateActionMapIsSubsetOfTooltax(t *testing.T) {
	if len(actionMap) == 0 {
		t.Fatal("actionMap is empty — the pin is vacuous")
	}
	for native, want := range actionMap {
		got, ok := tooltax.ResolveActionType(models.ToolPoolside, native)
		if !ok {
			t.Errorf("tooltax has no row for %s %q (the adapter maps it to %q) — "+
				"add the name to internal/tooltax's table", models.ToolPoolside, native, want)
			continue
		}
		if got != want {
			t.Errorf("drift: %s %q — adapter map says %q, tooltax says %q",
				models.ToolPoolside, native, got, want)
		}
	}
}
