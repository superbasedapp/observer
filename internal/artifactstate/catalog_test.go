package artifactstate

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// TestCatalogStatesCoverTheTables pins the catalog's artifact rows to the
// rule tables in step: every state a table can produce is listed on the
// row it reports for, and every state a row lists is a State this package
// knows. A new rule row with a new state fails here until the catalog says
// so (docs/components.md is generated from the catalog).
func TestCatalogStatesCoverTheTables(t *testing.T) {
	produced := map[components.ArtifactKind][]State{
		components.ArtifactBrowserExtension: browserStates(),
		components.ArtifactEditorExtension:  editorStates(),
		components.ArtifactPluginShim:       shimStates(),
		components.ArtifactHelperBinary:     helperStates(),
	}
	known := map[State]bool{}
	for _, s := range []State{StateNotDetected, StateConnected, StateStale, StateIncompatible, StateHostRemoved, StatePolicyBlocked, StateInstalled, StateAbsent, StateNotApplicable} {
		known[s] = true
	}
	arts := components.Artifacts()
	if len(arts) == 0 {
		t.Fatal("no artifact rows")
	}
	for _, a := range arts {
		listed := map[State]bool{}
		for _, s := range a.States {
			listed[State(s)] = true
			if !known[State(s)] {
				t.Errorf("%s lists state %q that internal/artifactstate does not define", a.ID, s)
			}
		}
		states, ok := produced[a.Kind]
		if !ok {
			t.Errorf("%s: no rule table for artifact kind %s", a.ID, a.Kind)
			continue
		}
		for _, s := range states {
			if !listed[s] {
				t.Errorf("%s: the %s table can report %q but the catalog row does not list it", a.ID, a.Kind, s)
			}
		}
	}
}
