package secassess

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLiveScore scores the assessment.json of a live run against the fixture's
// answer key (depth plan section 8, step D). It is the operator-attended
// counterpart of the golden tests: nothing here runs unless
// OBSERVER_SECASSESS_LIVE_RUN names a run directory
// (<project>/.observer/assessments/<run id>), and it asserts nothing about the
// score. It prints the account, which the live-check register records.
//
//	OBSERVER_SECASSESS_LIVE_RUN=<run dir> go test ./internal/secassess -run TestLiveScore -v
//
// A threat model, a penetration test or red team run and a retest are scored;
// the file's own schema word picks which. A retest is scored against the run it
// replayed: OBSERVER_SECASSESS_LIVE_OF=<that run's folder> names it (without it
// the one sibling folder that holds a pen test naming the retest's findings is
// used, and several or none is an error that says so).
//
// The score reads the run's own project (the copy of the application the agent
// worked on, three levels above the run directory) to resolve the key's anchors
// and to check every reference, exactly as the module's own check does, and it
// scores what the check keeps. The sets in force are the defaults: a run that
// was started with narrower sets is checked here against all of them, which
// can only add warnings.
func TestLiveScore(t *testing.T) {
	run := os.Getenv("OBSERVER_SECASSESS_LIVE_RUN")
	if run == "" {
		t.Skip("set OBSERVER_SECASSESS_LIVE_RUN to a run directory (<project>/.observer/assessments/<run id>)")
	}
	dir := scFixtureDir()
	if dir == "" {
		t.Fatal("the answer key is not found: run from a checkout that has testdata/secassess, or set OBSERVER_SECASSESS_FIXTURE_DIR")
	}
	m, k := scLoadKeys(t, dir)

	runDir, err := filepath.Abs(run)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(runDir, "assessment.json"))
	if err != nil {
		t.Fatalf("the run has no assessment.json: %v", err)
	}
	var head struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		t.Fatalf("assessment.json is not JSON: %v", err)
	}
	runID := filepath.Base(runDir)
	project := scDir{filepath.Join(runDir, "..", "..", "..")}

	switch head.Schema {
	case ContractPentest.Schema():
		o := DefaultValidateOptions(ContractPentest, runID)
		o.Refs = project
		s, err := scorePentest(m, project, Validate(data, o))
		if err != nil {
			t.Fatalf("the project does not carry the fixture's anchors (it was changed, or it is not the fixture): %v", err)
		}
		t.Log("\n" + strings.Join(s.Lines(), "\n"))
	case ContractThreatModel.Schema():
		o := DefaultValidateOptions(ContractThreatModel, runID)
		o.Refs = project
		s, err := scoreThreatModel(m, k, project, Validate(data, o))
		if err != nil {
			t.Fatalf("the project does not carry the fixture's anchors (it was changed, or it is not the fixture): %v", err)
		}
		t.Log("\n" + strings.Join(s.Lines(), "\n"))
	case ContractRetest.Schema():
		// A retest names the earlier run's findings, so the earlier pen test or red
		// team run is scored first (scoreretest_test.go). OBSERVER_SECASSESS_LIVE_OF
		// names its run folder; without it the one sibling run folder that holds the
		// findings is used.
		s, err := scLiveRetest(m, runDir, os.Getenv("OBSERVER_SECASSESS_LIVE_OF"), data)
		if err != nil {
			t.Fatalf("the retest cannot be scored: %v", err)
		}
		t.Log("\n" + strings.Join(s.Lines(), "\n"))
	default:
		t.Fatalf("assessment.json names schema %q, which this scorer does not read (a threat model, a penetration test or red team, or a retest)", head.Schema)
	}
}
