package agentconfig

import (
	"strings"
	"testing"
)

// TestConditionalTrustRowsStayOutOfTheDefaultTable: the N2 devcontainer row
// is read only under its condition; the default table is unchanged.
func TestConditionalTrustRowsStayOutOfTheDefaultTable(t *testing.T) {
	for _, p := range TrustPaths() {
		if p.Class == TrustDevcontainer || strings.HasPrefix(p.Rel, ".devcontainer") {
			t.Errorf("%s: a conditional row reached the default table", p.Rel)
		}
	}
	if got, want := len(TrustPathsWith()), len(TrustPaths()); got != want {
		t.Errorf("no condition: %d rows, want %d", got, want)
	}
	with := map[string]TrustPath{}
	for _, p := range TrustPathsWith(TrustCondOCISandbox) {
		with[p.Rel] = p
	}
	dc, ok := with[".devcontainer/devcontainer.json"]
	if !ok || dc.Class != TrustDevcontainer || !dc.RepoRootOnly || len(dc.Sources) != 1 || dc.Sources[0] != "repo/devcontainer" {
		t.Fatalf("the devcontainer row under its condition: %+v", dc)
	}
	if d, ok := with[".devcontainer/"]; !ok || d.Class != TrustConfigDir {
		t.Errorf("the .devcontainer config directory row: %+v", d)
	}
	if len(with) != len(TrustPaths())+2 {
		t.Errorf("the condition adds exactly the row and its directory: %d vs %d", len(with), len(TrustPaths()))
	}
}

func TestConditionalRepositoryFilesGrounded(t *testing.T) {
	known := map[TrustCondition]bool{TrustCondOCISandbox: true, TrustCondDevcontainerHost: true}
	seen := map[string]bool{}
	for _, r := range RepositoryFiles() {
		seen[r.ID] = true
	}
	for _, r := range ConditionalRepositoryFiles() {
		if !strings.HasPrefix(r.ID, "repo/") || seen[r.ID] || r.Rel == "" || r.Grounding.Source == "" || r.Class == "" || !known[r.Condition] {
			t.Errorf("%+v: malformed conditional row", r)
		}
		seen[r.ID] = true
	}
}
