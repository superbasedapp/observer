package kirocrew

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax"
)

// This is the WP-T3 conformance pin for kiro-crew (plan of record:
// docs/plans/tool-taxonomy-standardization-plan-2026-07-31.md §2), in the
// simpler MAP form: this adapter's classifier IS a data table
// (kindActions), not an AST-extractable switch, so both directions can be
// checked by walking it directly — no conformast needed.

// TestKindActionsAgreeWithTooltax is the CLASSIFIER→TABLE direction: every
// kind this adapter classifies must have a matching kiro-crew tooltax row.
func TestKindActionsAgreeWithTooltax(t *testing.T) {
	if len(kindActions) == 0 {
		t.Fatal("kindActions is empty — the pin would be vacuous")
	}
	for kind, action := range kindActions {
		e, ok := tooltax.Resolve(models.ToolKiroCrew, kind)
		if !ok || e.Tool != models.ToolKiroCrew {
			t.Errorf("the classifier maps %q → %q but internal/tooltax has no "+
				"%s-specific row for it — add the name to tooltax's table",
				kind, action, models.ToolKiroCrew)
			continue
		}
		if e.ActionType != action {
			t.Errorf("drift: %s %q — adapter says %q, tooltax says %q",
				models.ToolKiroCrew, kind, action, e.ActionType)
		}
	}
}

// TestTooltaxRowsAreAllClassified is the TABLE→CLASSIFIER direction: every
// kiro-crew row in tooltax must be a kind this adapter actually reads, so
// the table cannot grow rows the parser will never produce.
func TestTooltaxRowsAreAllClassified(t *testing.T) {
	var seen int
	for _, e := range tooltax.Table() {
		if e.Tool != models.ToolKiroCrew || e.IsGlob() {
			continue
		}
		seen++
		got, ok := kindActions[e.Native]
		if !ok {
			t.Errorf("tooltax carries a %s row for %q but the adapter's kindActions "+
				"does not classify it — the row can never match a real event",
				models.ToolKiroCrew, e.Native)
			continue
		}
		if got != e.ActionType {
			t.Errorf("drift: %s %q — tooltax says %q, adapter says %q",
				models.ToolKiroCrew, e.Native, e.ActionType, got)
		}
	}
	if seen != len(kindActions) {
		t.Errorf("tooltax has %d %s rows, kindActions has %d entries — the two must agree exactly",
			seen, models.ToolKiroCrew, len(kindActions))
	}
}

// TestSurfaceHostMatchesKiroCLIStamp pins the ONE token the two feed paths
// share: this adapter and internal/adapter/kirocli's agentSurfaces table
// must stamp the same SurfaceHost, or a Crew-driven session and a
// twin-less Crew chat would show up as two different surfaces.
func TestSurfaceHostMatchesKiroCLIStamp(t *testing.T) {
	if surfaceHost != "kiro-crew" {
		t.Errorf("surfaceHost = %q, want %q (kirocli.agentSurfaces stamps that literal)",
			surfaceHost, "kiro-crew")
	}
	if !models.KnownSurface(models.SurfaceDesktop) {
		t.Error("SurfaceDesktop is not a known surface kind")
	}
}
