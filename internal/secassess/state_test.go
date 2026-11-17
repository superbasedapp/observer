package secassess

import "testing"

func TestStateOf(t *testing.T) {
	cases := []struct {
		name string
		f    FilesPresent
		imp  ImportOutcome
		want State
	}{
		{"nothing yet", FilesPresent{}, ImportNone, StateStarted},
		{"a commands file alone is not progress", FilesPresent{Commands: true}, ImportNone, StateStarted},
		{"report only", FilesPresent{Report: true}, ImportNone, StateReportReady},
		{"findings file", FilesPresent{Report: true, SARIF: true}, ImportNone, StateFindingsReady},
		{"findings file without a report", FilesPresent{SARIF: true}, ImportNone, StateFindingsReady},
		{"imported", FilesPresent{Report: true, SARIF: true}, ImportDone, StateImported},
		{"import failed", FilesPresent{SARIF: true}, ImportFailed, StateImportFailed},
		{"import unavailable", FilesPresent{SARIF: true}, ImportUnavailable, StateImportUnavailable},
		{"an outcome with the file gone falls back to the report", FilesPresent{Report: true}, ImportDone, StateReportReady},
		{"an outcome with nothing there", FilesPresent{}, ImportDone, StateStarted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StateOf(tc.f, tc.imp); got != tc.want {
				t.Fatalf("state = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestResultPaths(t *testing.T) {
	p := ResultPaths(testRun)
	want := Paths{
		Dir:      ".observer/assessments/" + testRun,
		Report:   ".observer/assessments/" + testRun + "/report.md",
		SARIF:    ".observer/assessments/" + testRun + "/findings.sarif",
		Commands: ".observer/assessments/" + testRun + "/commands.txt",
		Model:    ".observer/assessments/" + testRun + "/assessment.json",

		ProbeHelper: ".observer/assessments/" + testRun + "/probe.py",
		ProbeConfig: ".observer/assessments/" + testRun + "/probe.json",
		ProbeLog:    ".observer/assessments/" + testRun + "/probes.jsonl",
	}
	if p != want {
		t.Errorf("paths = %+v", p)
	}
	for _, bad := range []string{"", "short", "../../etc/passwd", "3FA9C2D17B0E4A56", "3fa9c2d17b0e4a5g", testRun + "0", "3fa9c2d17b0e4a5/"} {
		if ValidRunID(bad) || ResultPaths(bad) != (Paths{}) {
			t.Errorf("%q was accepted as a run id", bad)
		}
	}
}

func TestStateOfModel(t *testing.T) {
	cases := []struct {
		name string
		f    FilesPresent
		m    ModelState
		imp  ImportOutcome
		want State
	}{
		{"nothing yet", FilesPresent{}, ModelState{}, ImportNone, StateStarted},
		{"a report alone", FilesPresent{Report: true}, ModelState{}, ImportNone, StateReportReady},
		{"the agent's own findings file plays no part", FilesPresent{Report: true, SARIF: true}, ModelState{}, ImportNone, StateReportReady},
		{"a model not yet validated", FilesPresent{Report: true, Model: true}, ModelState{}, ImportNone, StateModelReady},
		{"a model without a report", FilesPresent{Model: true}, ModelState{}, ImportNone, StateModelReady},
		{"validated", FilesPresent{Model: true}, ModelState{Validation: ValidationValid}, ImportNone, StateValidated},
		{"partly validated is validated", FilesPresent{Model: true}, ModelState{Validation: ValidationPartial}, ImportNone, StateValidated},
		{"refused whole", FilesPresent{Model: true}, ModelState{Validation: ValidationInvalid}, ImportNone, StateInvalid},
		{"changed since it was validated", FilesPresent{Model: true}, ModelState{Validation: ValidationValid, Stale: true}, ImportNone, StateModelReady},
		{"changed since it was refused", FilesPresent{Model: true}, ModelState{Validation: ValidationInvalid, Stale: true}, ImportNone, StateModelReady},
		{"the model was deleted after validation", FilesPresent{Report: true}, ModelState{Validation: ValidationValid}, ImportNone, StateReportReady},
		{"imported", FilesPresent{Model: true}, ModelState{Validation: ValidationValid}, ImportDone, StateImported},
		{"import failed", FilesPresent{Model: true}, ModelState{Validation: ValidationPartial}, ImportFailed, StateImportFailed},
		{"import unavailable", FilesPresent{Model: true}, ModelState{Validation: ValidationValid}, ImportUnavailable, StateImportUnavailable},
		{"an import that derived nothing", FilesPresent{Model: true}, ModelState{Validation: ValidationValid}, ImportNoFindings, StateNoFindings},
		{"no findings for an older model is not shown", FilesPresent{Model: true}, ModelState{Validation: ValidationValid, Stale: true}, ImportNoFindings, StateModelReady},
		{"no findings with no validation is not shown", FilesPresent{Model: true}, ModelState{}, ImportNoFindings, StateModelReady},
		{"an import outcome for an older model is not shown", FilesPresent{Model: true}, ModelState{Validation: ValidationValid, Stale: true}, ImportDone, StateModelReady},
		{"an import outcome with no validation is not shown", FilesPresent{Model: true}, ModelState{}, ImportDone, StateModelReady},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := StateOfModel(tc.f, tc.m, tc.imp); got != tc.want {
				t.Fatalf("state = %s, want %s", got, tc.want)
			}
		})
	}
}

// TestKindContracts pins the contract column: the four agent-modelled kinds
// carry a model contract whose schema is the one the validator reads, the others
// keep the SARIF contract (empty).
func TestKindContracts(t *testing.T) {
	want := map[ID]Contract{
		ThreatModel: ContractThreatModel, PentestLocal: ContractPentest, RedTeamLocal: ContractPentest, PentestRetest: ContractRetest,
	}
	for _, k := range Kinds() {
		if got := k.Contract; got != want[k.ID] {
			t.Errorf("%s: contract %q, want %q", k.ID, got, want[k.ID])
		}
		if k.Contract != "" && k.Contract.Schema() == "" {
			t.Errorf("%s: contract %q has no schema id", k.ID, k.Contract)
		}
	}
}

// TestStateWhenEnded: once a run's terminal has ended, "started" (nothing
// written yet) becomes "ended_empty" and every other state stays as it is. One
// row per state, ended and not ended, so a state added later must be decided
// here (a result that exists stays what it is; nothing written reads as over).
func TestStateWhenEnded(t *testing.T) {
	endedTo := map[State]State{
		StateStarted: StateEndedEmpty,
	}
	for _, s := range States() {
		for _, ended := range []bool{false, true} {
			want := s
			if ended {
				if to, ok := endedTo[s]; ok {
					want = to
				}
			}
			name := string(s) + "/running"
			if ended {
				name = string(s) + "/ended"
			}
			t.Run(name, func(t *testing.T) {
				if got := StateWhenEnded(s, ended); got != want {
					t.Fatalf("StateWhenEnded(%s, %v) = %s, want %s", s, ended, got, want)
				}
			})
		}
	}
	// A state this table has never heard of is left alone.
	if got := StateWhenEnded("something_new", true); got != "something_new" {
		t.Errorf("an unknown state became %s", got)
	}
}

// TestEndedStatesAreStates: every row of the ended table reads and writes a
// listed state, and the state it writes is not one a file can produce (it is
// reached only through the end), so the two derivations never disagree.
func TestEndedStatesAreStates(t *testing.T) {
	listed := map[State]bool{}
	for _, s := range States() {
		listed[s] = true
	}
	for _, r := range endedStates {
		if !listed[r.From] || !listed[r.To] || r.From == r.To {
			t.Errorf("row %s -> %s names a state that is not listed or maps to itself", r.From, r.To)
		}
		for _, imp := range []ImportOutcome{ImportNone, ImportDone, ImportFailed, ImportUnavailable, ImportNoFindings} {
			for _, rep := range []bool{false, true} {
				for _, sarif := range []bool{false, true} {
					for _, model := range []bool{false, true} {
						f := FilesPresent{Report: rep, SARIF: sarif, Model: model}
						if StateOf(f, imp) == r.To || StateOfModel(f, ModelState{}, imp) == r.To {
							t.Fatalf("a file can produce %s without the end: %+v %s", r.To, f, imp)
						}
					}
				}
			}
		}
	}
}
