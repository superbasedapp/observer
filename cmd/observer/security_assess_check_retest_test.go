//go:build !sbo_omit_security

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// Tests of the self-check for every schema the tasks ask an agent to write
// (the retest and the red team came after the check, and a retest agent was told
// its file was refused at the schema word, live run 2026-11-16).

// checkExample is the example model of a contract, as its task carries it.
func checkExample(c secassess.Contract) string {
	return secassess.SchemaExample(secassess.SchemaInput{Contract: c, RunID: checkRun, PromptVersion: "x.1", Helper: true, Exercise: c == secassess.ContractPentest})
}

// writeProbeConfig writes the request helper's settings into the run folder of
// the project, naming the findings a retest replays.
func writeProbeConfig(t *testing.T, root string, findings ...string) {
	t.Helper()
	replay := map[string]any{}
	for _, f := range findings {
		replay[f] = map[string]any{"steps": []any{map[string]any{"method": "GET", "path": "/x"}}}
	}
	b, err := json.Marshal(map[string]any{"schema": secassess.ProbeConfigSchema, "run_id": checkRun, "origin": "http://127.0.0.1:3000", "budget": 10, "pace_rps": 1, "max_bytes": 1000, "replay": replay})
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(root, filepath.FromSlash(secassess.ResultPaths(checkRun).ProbeConfig))
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSecurityAssessCheckReadsEverySchema: every contract that has a model file
// is a row of the check's table, and the example its task carries (the red
// team's, with the exercise, included) reads clean under its own schema word.
func TestSecurityAssessCheckReadsEverySchema(t *testing.T) {
	for _, m := range secassess.ModelContracts {
		t.Run(m.Schema, func(t *testing.T) {
			chk, ok := securityAssessChecks[m.Contract]
			if !ok || len(chk.rows) == 0 {
				t.Fatalf("the contract %s has no row in the self-check's table", m.Contract)
			}
			root, rel := checkProject(t, checkExample(m.Contract))
			if m.Contract == secassess.ContractRetest {
				writeProbeConfig(t, root, "F-1")
			}
			out, err := runCheck(t, root, rel, "", false)
			if err != nil {
				t.Fatalf("the example is not accepted: %v\n%s", err, out)
			}
			if !strings.Contains(out, "schema "+m.Schema) || !strings.Contains(out, "Read without anything refused or left out.") {
				t.Errorf("output:\n%s", out)
			}
		})
	}
}

// TestSecurityAssessCheckRedTeamFile: a red team run writes the penetration
// test's schema with an exercise, and the check reads it as one.
func TestSecurityAssessCheckRedTeamFile(t *testing.T) {
	pt := checkExample(secassess.ContractPentest)
	if !strings.Contains(pt, `"exercise"`) {
		t.Fatal("the red team example carries no exercise")
	}
	root, rel := checkProject(t, pt)
	out, err := runCheck(t, root, rel, "", false)
	if err != nil || !strings.Contains(out, "schema observer.pentest.v1") {
		t.Fatalf("err %v\n%s", err, out)
	}
}

// TestSecurityAssessCheckRetest: the retest's rows are what the check reports,
// and the findings are the ones the run folder says were replayed.
func TestSecurityAssessCheckRetest(t *testing.T) {
	ex := checkExample(secassess.ContractRetest)
	cases := []struct {
		name    string
		model   string
		replay  []string // the findings probe.json carries; nil writes no probe.json
		wantErr bool
		must    []string
		mustNot []string
	}{
		{
			name: "the example, with the replay list", model: ex, replay: []string{"F-1"},
			must: []string{"Read without anything refused or left out.", "schema observer.retest.v1"}, mustNot: []string{"References:", "holds no list"},
		},
		{
			name: "one result written with a lone text for its evidence reads as a list (the live file)", replay: []string{"F-1"},
			model: strings.Replace(ex, `"evidence":["p3"]`, `"evidence":"p3"`, 1), must: []string{"Read without anything refused or left out."},
		},
		{
			name: "evidence that is not text is left out and said, not a refusal of the file", replay: []string{"F-1"},
			model: strings.Replace(ex, `"evidence":["p3"]`, `"evidence":{"id":"p3"}`, 1), wantErr: true,
			must: []string{"Read, with items left out", "1 fields or entries left out", "[V2 dropped] results[0].evidence:"},
		},
		{
			name: "a result for a finding the retest did not replay is refused", replay: []string{"F-2"},
			model: ex, wantErr: true, must: []string{"[RT4 refused]", "is not one of the findings this retest replayed", "[RT6 warn]", "1 of the findings this retest replayed have no result"},
		},
		{
			name: "a replayed finding with no result is named, and is not a failure", replay: []string{"F-1", "F-2"}, model: ex,
			must: []string{"[RT6 warn]", "1 of the findings this retest replayed have no result"},
		},
		{
			name: "a label outside the closed list is refused", replay: []string{"F-1"},
			model: strings.Replace(ex, `"result":"not_reproduced"`, `"result":"fixed"`, 1), wantErr: true, must: []string{"[RT4 refused]", "must be reproduced, not_reproduced or inconclusive"},
		},
		{
			name: "no replay list in the run folder: the check says what it cannot tell", replay: nil, model: ex,
			must: []string{"Read without anything refused or left out.", "holds no list of the findings this retest replayed"},
		},
		{
			name: "the wrong run id refuses the file", replay: []string{"F-1"},
			model: strings.Replace(ex, `"run_id":"`+checkRun+`"`, `"run_id":"0000000000000000"`, 1), wantErr: true, must: []string{"Not read", "[V2 refused]"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, rel := checkProject(t, tc.model)
			if tc.replay != nil {
				writeProbeConfig(t, root, tc.replay...)
			}
			out, err := runCheck(t, root, rel, "", false)
			if (err != nil) != tc.wantErr || (err != nil && !errors.Is(err, errSecurityAssessCheck)) {
				t.Fatalf("err = %v, want error %v\n%s", err, tc.wantErr, out)
			}
			for _, m := range tc.must {
				if !strings.Contains(out, m) {
					t.Errorf("the output lacks %q:\n%s", m, out)
				}
			}
			for _, m := range tc.mustNot {
				if strings.Contains(out, m) {
					t.Errorf("the output has %q:\n%s", m, out)
				}
			}
			// Only the retest's own rows and the two shared structure rows are reported.
			for _, line := range strings.Split(out, "\n") {
				if !strings.HasPrefix(line, "- [") {
					continue
				}
				row, _, _ := strings.Cut(strings.TrimPrefix(line, "- ["), " ")
				if !securityAssessCheckRow(secassess.ContractRetest, row) {
					t.Errorf("a row outside the retest's was reported: %q", line)
				}
			}
		})
	}
}

// TestSecurityAssessCheckRetestReplayList: what ReplayedFindings reads is the
// helper's settings only, never trusted past the check: ids that are not item
// ids are not findings, and a settings file that is not JSON lists none.
func TestSecurityAssessCheckRetestReplayList(t *testing.T) {
	ex := checkExample(secassess.ContractRetest)
	root, rel := checkProject(t, ex)
	p := filepath.Join(root, filepath.FromSlash(secassess.ResultPaths(checkRun).ProbeConfig))
	if err := os.WriteFile(p, []byte(`{"replay":{"bad id":{},"F-1":{}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := runCheck(t, root, rel, "", false); err != nil || strings.Contains(out, "holds no list") {
		t.Fatalf("a list with one valid id: %v\n%s", err, out)
	}
	if err := os.WriteFile(p, []byte(`{nope`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runCheck(t, root, rel, "", false)
	if err != nil || !strings.Contains(out, "holds no list of the findings this retest replayed") {
		t.Fatalf("a settings file that is not JSON: %v\n%s", err, out)
	}
}

// TestSecurityAssessCheckJSONRetest: the JSON output names the schema and carries
// the note, and the file's own counts.
func TestSecurityAssessCheckJSONRetest(t *testing.T) {
	root, rel := checkProject(t, checkExample(secassess.ContractRetest))
	js, err := runCheck(t, root, rel, "", true)
	if err != nil {
		t.Fatalf("%v\n%s", err, js)
	}
	var got securityAssessCheckJS
	if err := json.Unmarshal([]byte(js), &got); err != nil {
		t.Fatal(err)
	}
	if got.Schema != secassess.SchemaRetest || got.State != "valid" || got.Counts["results"].Kept != 1 || !strings.Contains(got.Note, "holds no list") {
		t.Errorf("report = %+v", got)
	}
}
