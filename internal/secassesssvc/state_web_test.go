package secassesssvc

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestRunStatesMatchTheWebWords: the run states the server sends and the words
// the web has for them are one list (plan section 3.7). A state without words
// would render as its own name; a word entry for a state that does not exist is
// dead text. The two phases that are not states (held, cancelled) are the only
// extra entries the web table may have.
func TestRunStatesMatchTheWebWords(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "secAssess.ts"))
	if err != nil {
		t.Skipf("the web sources are not in this tree: %v", err)
	}
	block := regexp.MustCompile(`(?s)export const ASSESS_STATE[^=]*=\s*\{(.*?)\n\};`).FindSubmatch(src)
	if block == nil {
		t.Fatal("ASSESS_STATE was not found in secAssess.ts")
	}
	web := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^  ([a-z_]+): \{`).FindAllSubmatch(block[1], -1) {
		web[string(m[1])] = true
	}
	phases := map[string]bool{"held": true, "cancelled": true}
	want := map[string]bool{}
	for _, s := range secassess.States() {
		want[string(s)] = true
		if !web[string(s)] {
			t.Errorf("state %q has no words in ASSESS_STATE", s)
		}
	}
	var extra []string
	for k := range web {
		if !want[k] && !phases[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		t.Errorf("ASSESS_STATE has entries for states the server never sends: %v", extra)
	}
}

// TestStatesCoverTheDerivations: everything StateOf and StateOfModel can return
// is in the list States returns, ended or not (StateWhenEnded folds the end in).
func TestStatesCoverTheDerivations(t *testing.T) {
	listed := map[secassess.State]bool{}
	for _, s := range secassess.States() {
		listed[s] = true
	}
	imps := []secassess.ImportOutcome{secassess.ImportNone, secassess.ImportDone, secassess.ImportFailed, secassess.ImportUnavailable}
	vals := []secassess.ValidationState{"", secassess.ValidationValid, secassess.ValidationPartial, secassess.ValidationInvalid}
	for _, imp := range imps {
		for _, rep := range []bool{false, true} {
			for _, sarif := range []bool{false, true} {
				for _, model := range []bool{false, true} {
					f := secassess.FilesPresent{Report: rep, SARIF: sarif, Model: model}
					if got := secassess.StateOf(f, imp); !listed[got] || !listed[secassess.StateWhenEnded(got, true)] {
						t.Errorf("StateOf returned %q, not in States()", got)
					}
					for _, v := range vals {
						for _, stale := range []bool{false, true} {
							if got := secassess.StateOfModel(f, secassess.ModelState{Validation: v, Stale: stale}, imp); !listed[got] || !listed[secassess.StateWhenEnded(got, true)] {
								t.Errorf("StateOfModel returned %q, not in States()", got)
							}
						}
					}
				}
			}
		}
	}
}
