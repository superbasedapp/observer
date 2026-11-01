package secverify

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// TestEverySARIFResultHasAPhysicalLocation walks every result kind verify
// emits (a detector finding with and without a line, a failed record and
// a missing one, with an anchor, without one and with a refused one) and
// requires the shape GitHub code scanning accepts: a non-empty relative
// artifactLocation.uri under %SRCROOT% and a region from line 1. A result
// without one makes code scanning drop the whole analysis
// ("locationFromSarifResult: expected a physical location").
func TestEverySARIFResultHasAPhysicalLocation(t *testing.T) {
	rep := run(t, DefaultPolicy(), nil,
		change{"A", "dir with space/prod.py", []string{"k='" + fakeAWSKey + "'"}},
		change{"A", ".mcp.json", []string{"{}"}},
	)
	rep.Provenance = ProvenanceReport{Checked: true, Floor: secchange.FloorLabel, Commits: []ProvenanceCommitReport{
		{CommitOutcome: secchange.CommitOutcome{SHA: strings.Repeat("a", 40), Provenance: secchange.ProvenanceFailed, Reason: "record_invalid"}, Path: "z/b.go"},
		{CommitOutcome: secchange.CommitOutcome{SHA: strings.Repeat("b", 40), Provenance: secchange.ProvenanceUnknown, Reason: "no_record"}},
		{CommitOutcome: secchange.CommitOutcome{SHA: strings.Repeat("c", 40), Provenance: secchange.ProvenanceUnknown, Reason: "no_record"}, Path: "../outside"},
		{CommitOutcome: secchange.CommitOutcome{SHA: strings.Repeat("d", 40), Provenance: secchange.ProvenanceVerified, Reason: "record_verified"}},
	}}
	var b bytes.Buffer
	if err := WriteSARIF(&b, rep, "/w/repo", "v1.40.0"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation *struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	uris := map[string]bool{}
	for _, r := range log.Runs[0].Results {
		if len(r.Locations) == 0 {
			t.Fatalf("%s: no location", r.RuleID)
		}
		for _, l := range r.Locations {
			pl := l.PhysicalLocation
			if pl == nil || pl.ArtifactLocation.URI == "" || pl.Region == nil || pl.Region.StartLine < 1 {
				t.Fatalf("%s: physical location missing or incomplete: %+v", r.RuleID, pl)
			}
			if pl.ArtifactLocation.URIBaseID != srcRoot {
				t.Fatalf("%s: uriBaseId %q", r.RuleID, pl.ArtifactLocation.URIBaseID)
			}
			rel, err := url.PathUnescape(pl.ArtifactLocation.URI)
			if err != nil || ValidRelPath(rel) != nil || strings.Contains(pl.ArtifactLocation.URI, "://") {
				t.Fatalf("%s: uri %q is not a clean relative path", r.RuleID, pl.ArtifactLocation.URI)
			}
			uris[rel] = true
		}
		kinds[r.RuleID]++
	}
	if kinds[RuleProvenanceFailed] != 1 || kinds[RuleProvenanceUnknown] != 2 || len(kinds) < 3 {
		t.Fatalf("result kinds %v", kinds)
	}
	for _, want := range []string{"z/b.go", ProvenanceFallbackPath, "dir with space/prod.py"} {
		if !uris[want] {
			t.Fatalf("no result located at %q: %v", want, uris)
		}
	}
	if uris["../outside"] || uris["outside"] {
		t.Fatalf("a refused anchor reached the file: %v", uris)
	}
}

// TestProvenanceAnchor is the location rule, one row per case.
func TestProvenanceAnchor(t *testing.T) {
	for _, c := range []struct {
		name          string
		changed, root []string
		want          string
	}{
		{"first changed path in sorted order", []string{"z.go", "a/b.go", "B.go"}, nil, "B.go"},
		{"a refused path is skipped", []string{"../x", "/abs", "m.go"}, nil, "m.go"},
		{"no change: the root README", nil, []string{"src", "README.md", "README"}, "README.md"},
		{"no change: README names in order", nil, []string{"README.txt", "README"}, "README"},
		{"no change, no README: empty (writer falls back)", nil, []string{"src", "go.mod"}, ""},
		{"only refused paths: the README", []string{"../x"}, []string{"README.md"}, "README.md"},
	} {
		if got := ProvenanceAnchor(c.changed, c.root); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	if ProvenanceFallbackPath != ExampleWorkflowParams("").PolicyPath {
		t.Fatalf("fallback %q is not the template's policy path", ProvenanceFallbackPath)
	}
}
