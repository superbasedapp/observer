package secverify

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secchange"
)

// TestProvenanceSARIFResults (lane SEC-F2B): a failed record and a missing
// one become SARIF results under two stable rule ids, located at a file
// (code scanning drops an upload with a result that has none) and by the
// commit, while the verdict the run reports is the report's own.
func TestProvenanceSARIFResults(t *testing.T) {
	sha1, sha2, sha3 := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	rep := Report{Verdict: VerdictPass, Rule: "V-PASS", Provenance: ProvenanceReport{
		Checked: true, Floor: secchange.FloorLabel,
		Commits: []ProvenanceCommitReport{
			{CommitOutcome: secchange.CommitOutcome{SHA: sha1, Provenance: secchange.ProvenanceFailed, Reason: "record_failed"}, Errors: []string{"bad_signature"}, Path: "src/a.go"},
			{CommitOutcome: secchange.CommitOutcome{SHA: sha2, Provenance: secchange.ProvenanceUnknown, Reason: "no_record"}},
			{CommitOutcome: secchange.CommitOutcome{SHA: sha3, Provenance: secchange.ProvenanceVerified, Reason: "record_verified"}},
		},
	}}
	var b bytes.Buffer
	if err := WriteSARIF(&b, rep, "/w/repo", "v1.40.0"); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation *struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
					} `json:"logicalLocations"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if run.Properties["superbased/verdict"] != string(VerdictPass) {
		t.Fatalf("the SARIF changed the verdict: %v", run.Properties["superbased/verdict"])
	}
	if len(run.Results) != 2 {
		t.Fatalf("results %+v", run.Results)
	}
	want := map[string]struct{ level, commit, uri string }{
		RuleProvenanceFailed:  {"error", "commit/" + sha1, "src/a.go"},
		RuleProvenanceUnknown: {"note", "commit/" + sha2, ProvenanceFallbackPath},
	}
	for _, r := range run.Results {
		w, ok := want[r.RuleID]
		if !ok || r.Level != w.level || len(r.Locations) != 1 || r.Locations[0].PhysicalLocation == nil ||
			r.Locations[0].LogicalLocations[0].FullyQualifiedName != w.commit || r.PartialFingerprints[FingerprintKey] == "" {
			t.Fatalf("result %+v", r)
		}
		pl := r.Locations[0].PhysicalLocation
		if pl.ArtifactLocation.URI != w.uri || pl.ArtifactLocation.URIBaseID != srcRoot || pl.Region.StartLine != 1 {
			t.Fatalf("physical location %+v", pl)
		}
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules %+v", run.Tool.Driver.Rules)
	}
	var again bytes.Buffer
	if err := WriteSARIF(&again, rep, "/w/repo", "v1.40.0"); err != nil || again.String() != b.String() {
		t.Fatal("provenance results are not stable")
	}
	var off bytes.Buffer
	if err := WriteSARIF(&off, Report{Verdict: VerdictPass}, "/w/repo", ""); err != nil || strings.Contains(off.String(), "provenance/") {
		t.Fatalf("an unchecked run wrote provenance results: %v", err)
	}
}

// TestWorkflowFetchesNotesAndPassesKeys (lane SEC-F2B): the rendered
// workflow fetches refs/notes/observer and passes the keys file from the
// protected repository, and says a fork's upload may fail on a private
// repository (decision log P-076).
func TestWorkflowFetchesNotesAndPassesKeys(t *testing.T) {
	out, err := RenderWorkflow(ExampleWorkflowParams("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"'+refs/notes/observer:refs/notes/observer'",
		`keys=(--keys "policy/` + DefaultKeysPath + `")`,
		`"${keys[@]}"`,
		"may fail on a private repository",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("workflow lacks %q", want)
		}
	}
	if strings.Contains(out, "a fork's read-only token) is a") {
		t.Error("the old fork wording is back")
	}
	p := ExampleWorkflowParams("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	p.KeysPath = "../keys.json"
	if p.Validate() == nil {
		t.Fatal("a keys path leaving the repository was accepted")
	}
}
