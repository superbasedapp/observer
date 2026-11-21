package migplan

import (
	"reflect"
	"strings"
	"testing"
)

func run(vs ...int) []Step   { return steps(ActionRun, vs...) }
func adopt(vs ...int) []Step { return steps(ActionAdopt, vs...) }

func steps(a Action, vs ...int) []Step {
	out := make([]Step, 0, len(vs))
	for _, v := range vs {
		out = append(out, Step{Version: v, Action: a})
	}
	return out
}

func recorded(vs ...int) map[int]string {
	m := map[int]string{}
	for _, v := range vs {
		m[v] = RecordApplied
	}
	return m
}

// want is the comparable projection of a Plan (Rule names are checked by
// TestDecideRuleNames, not here).
type want struct {
	steps        []Step
	horizon      int
	writeHorizon bool
	forget       []int
	version      int
	writeVersion bool
	newer        bool
}

func TestDecide(t *testing.T) {
	for _, tc := range []struct {
		name     string
		embedded []int
		ledger   Ledger
		late     map[int]bool
		want     want
	}{
		{
			name:     "fresh database runs every step and initialises the ledger",
			embedded: []int{1, 2, 3},
			want:     want{steps: run(1, 2, 3), writeHorizon: true, version: 3, writeVersion: true},
		},
		{
			name: "empty lineage on a fresh database writes nothing",
			want: want{},
		},
		{
			name:     "contiguous ledger already at max re-runs nothing",
			embedded: []int{1, 2, 3},
			ledger:   Ledger{Version: 3, HasHorizon: true, Steps: recorded(1, 2, 3)},
			want:     want{version: 3},
		},
		{
			name:     "pre-ledger database at max adopts every step without running",
			embedded: []int{1, 2, 3},
			ledger:   Ledger{Version: 3},
			want:     want{steps: adopt(1, 2, 3), horizon: 3, writeHorizon: true, version: 3},
		},
		{
			name:     "pre-ledger database at 241 that never ran late step 240 runs it, 241 does not re-run",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241},
			late:     map[int]bool{240: false},
			want: want{
				steps:   []Step{{239, ActionAdopt, ""}, {240, ActionRun, ""}, {241, ActionAdopt, ""}},
				horizon: 241, writeHorizon: true, version: 241,
			},
		},
		{
			name:     "pre-ledger database that did run late step 240 re-runs nothing",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241},
			late:     map[int]bool{240: true},
			want:     want{steps: adopt(239, 240, 241), horizon: 241, writeHorizon: true, version: 241},
		},
		{
			name:     "pre-ledger database from the 240 line adopts 240 and runs 241",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 240},
			late:     map[int]bool{240: true},
			want: want{
				steps:   []Step{{239, ActionAdopt, ""}, {240, ActionAdopt, ""}, {241, ActionRun, ""}},
				horizon: 240, writeHorizon: true, version: 241, writeVersion: true,
			},
		},
		{
			name:     "ledger database at 241 runs an unlisted step 240 that arrives later",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241, HasHorizon: true, Steps: recorded(239, 241)},
			want:     want{steps: run(240), version: 241},
		},
		{
			name:     "ledger database at 241 runs a listed late step 240 whose probe is missing",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241, HasHorizon: true, Horizon: 239, Steps: recorded(239, 241)},
			late:     map[int]bool{240: false},
			want:     want{steps: run(240), horizon: 239, version: 241},
		},
		{
			name:     "ledger database that recorded 240 re-runs nothing even when its probe disagrees",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241, HasHorizon: true, Steps: recorded(239, 240, 241)},
			late:     map[int]bool{240: false},
			want:     want{version: 241},
		},
		{
			name:     "ledger database that adopted late step 240 under its horizon runs it when its probe is missing",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241, HasHorizon: true, Horizon: 241, Steps: map[int]string{239: RecordAdopted, 240: RecordAdopted, 241: RecordAdopted}},
			late:     map[int]bool{240: false},
			want:     want{steps: run(240), horizon: 241, version: 241},
		},
		{
			name:     "ledger database that adopted late step 240 re-runs nothing when its probe is present",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241, HasHorizon: true, Horizon: 241, Steps: map[int]string{239: RecordAdopted, 240: RecordAdopted, 241: RecordAdopted}},
			late:     map[int]bool{240: true},
			want:     want{horizon: 241, version: 241},
		},
		{
			name:     "an adopted step that is not a late step stays adopted",
			embedded: []int{239, 240, 241},
			ledger:   Ledger{Version: 241, HasHorizon: true, Horizon: 241, Steps: map[int]string{239: RecordAdopted, 240: RecordAdopted, 241: RecordAdopted}},
			want:     want{horizon: 241, version: 241},
		},
		{
			name:     "listed late step not yet reached on a fresh database runs in order",
			embedded: []int{1, 2, 3},
			late:     map[int]bool{2: false},
			want:     want{steps: run(1, 2, 3), writeHorizon: true, version: 3, writeVersion: true},
		},
		{
			name:     "late probe for a version this lineage does not embed is ignored",
			embedded: []int{239, 241},
			ledger:   Ledger{Version: 241},
			late:     map[int]bool{240: false},
			want:     want{steps: adopt(239, 241), horizon: 241, writeHorizon: true, version: 241},
		},
		{
			name:     "version record newer than the lineage is flagged and nothing runs",
			embedded: []int{1, 2, 3},
			ledger:   Ledger{Version: 9, HasHorizon: true, Steps: recorded(1, 2, 3, 9)},
			want:     want{version: 9, newer: true},
		},
		{
			name:   "version record on an empty lineage is newer than the lineage",
			ledger: Ledger{Version: 136},
			want:   want{horizon: 136, version: 136, newer: true},
		},
		{
			name:     "rewound version record voids the records above it and replays them",
			embedded: []int{1, 2, 3, 4, 5},
			ledger:   Ledger{Version: 3, HasHorizon: true, Steps: recorded(1, 2, 3, 4, 5)},
			want:     want{steps: run(4, 5), forget: []int{4, 5}, version: 5, writeVersion: true},
		},
		{
			name:     "rewind below the horizon lowers the horizon so the replay runs",
			embedded: []int{1, 2, 3, 4, 5},
			ledger:   Ledger{Version: 3, HasHorizon: true, Horizon: 5, Steps: recorded(1, 2, 3, 4, 5)},
			want: want{
				steps: run(4, 5), horizon: 3, writeHorizon: true, forget: []int{4, 5},
				version: 5, writeVersion: true,
			},
		},
		{
			name:     "rewind forgets a record for a step this lineage does not embed",
			embedded: []int{1, 2},
			ledger:   Ledger{Version: 2, HasHorizon: true, Steps: recorded(1, 2, 7)},
			want:     want{forget: []int{7}, version: 2},
		},
		{
			name:     "pre-ledger runner that advanced a ledger database extends the horizon",
			embedded: []int{1, 2, 3, 4, 5, 6},
			ledger:   Ledger{Version: 5, HasHorizon: true, Horizon: 3, Steps: recorded(1, 2, 3)},
			want: want{
				steps: append(adopt(4, 5), run(6)...), horizon: 5, writeHorizon: true,
				version: 6, writeVersion: true,
			},
		},
		{
			name:     "a step run by the ledger runner above the horizon is not mistaken for a pre-ledger advance",
			embedded: []int{1, 2, 3, 4},
			ledger:   Ledger{Version: 4, HasHorizon: true, Horizon: 2, Steps: recorded(1, 2, 4)},
			want:     want{steps: run(3), horizon: 2, version: 4},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Decide(Input{Embedded: tc.embedded, Ledger: tc.ledger, Late: tc.late})
			if err != nil {
				t.Fatalf("Decide: %v", err)
			}
			for i := range got.Steps {
				got.Steps[i].Rule = ""
			}
			proj := want{
				steps: got.Steps, horizon: got.Horizon, writeHorizon: got.WriteHorizon,
				forget: got.Forget, version: got.Version, writeVersion: got.WriteVersion,
				newer: got.NewerThanLineage,
			}
			if len(proj.steps) == 0 {
				proj.steps = nil
			}
			if len(tc.want.steps) == 0 {
				tc.want.steps = nil
			}
			if !reflect.DeepEqual(proj, tc.want) {
				t.Fatalf("plan mismatch\n got %+v\nwant %+v", proj, tc.want)
			}
		})
	}
}

func TestDecideRuleNames(t *testing.T) {
	got, err := Decide(Input{
		Embedded: []int{1, 2, 3, 4, 5},
		Ledger:   Ledger{Version: 4, HasHorizon: true, Horizon: 3, Steps: recorded(1, 4)},
		Late:     map[int]bool{2: true, 3: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	// 1 and 4 are recorded (skipped); 2 late present; 3 late missing; 5 pending.
	wantRules := map[int]string{2: "late step present", 3: "late step missing", 5: "pending"}
	if len(got.Steps) != len(wantRules) {
		t.Fatalf("steps = %+v", got.Steps)
	}
	for _, s := range got.Steps {
		if wantRules[s.Version] != s.Rule {
			t.Errorf("step %d rule = %q, want %q", s.Version, s.Rule, wantRules[s.Version])
		}
	}
	adopted, err := Decide(Input{Embedded: []int{1}, Ledger: Ledger{Version: 1}})
	if err != nil || len(adopted.Steps) != 1 || adopted.Steps[0].Rule != "within pre-ledger horizon" {
		t.Fatalf("pre-ledger adoption = %+v, %v", adopted.Steps, err)
	}
	healed, err := Decide(Input{
		Embedded: []int{1, 2},
		Ledger:   Ledger{Version: 2, HasHorizon: true, Horizon: 2, Steps: map[int]string{1: RecordAdopted, 2: RecordAdopted}},
		Late:     map[int]bool{1: false},
	})
	if err != nil || len(healed.Steps) != 1 || healed.Steps[0].Rule != "adopted late step missing" {
		t.Fatalf("adopted late step = %+v, %v", healed.Steps, err)
	}
}

func TestDecideRejectsMalformedLineage(t *testing.T) {
	for _, tc := range []struct {
		name     string
		embedded []int
	}{
		{"duplicate", []int{1, 2, 2}},
		{"descending", []int{2, 1}},
		{"zero", []int{0, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decide(Input{Embedded: tc.embedded}); err == nil {
				t.Fatal("malformed lineage accepted")
			}
		})
	}
}

func TestParseLedger(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rows    map[string]string
		want    Ledger
		wantErr string
	}{
		{name: "empty", rows: map[string]string{}, want: Ledger{Steps: map[int]string{}}},
		{
			name: "pre-ledger version only, foreign keys ignored",
			rows: map[string]string{"version": "241", "org_push_cursor": "x"},
			want: Ledger{Version: 241, Steps: map[int]string{}},
		},
		{
			name: "full ledger",
			rows: map[string]string{"version": "3", HorizonKey: "1", "migration:1": RecordAdopted, "migration:3": RecordApplied},
			want: Ledger{Version: 3, HasHorizon: true, Horizon: 1, Steps: map[int]string{1: RecordAdopted, 3: RecordApplied}},
		},
		{name: "invalid version", rows: map[string]string{"version": "x"}, wantErr: "invalid version"},
		{name: "negative version", rows: map[string]string{"version": "-1"}, wantErr: "invalid version"},
		{name: "invalid horizon", rows: map[string]string{HorizonKey: ""}, wantErr: "invalid ledger horizon"},
		{name: "invalid step key", rows: map[string]string{"migration:abc": RecordApplied}, wantErr: "invalid step record key"},
		{name: "invalid step value", rows: map[string]string{"migration:4": "maybe"}, wantErr: "invalid step record"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseLedger(tc.rows)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestActionRecordAndStepKey(t *testing.T) {
	if ActionRun.Record() != RecordApplied || ActionAdopt.Record() != RecordAdopted {
		t.Fatal("action record mapping changed")
	}
	if StepKey(240) != "migration:240" {
		t.Fatalf("StepKey(240) = %q", StepKey(240))
	}
}

func TestPlanNoopAndRunVersions(t *testing.T) {
	for _, tc := range []struct {
		name string
		plan Plan
		noop bool
		runs []int
	}{
		{name: "zero plan", plan: Plan{}, noop: true},
		{name: "newer than lineage alone writes nothing", plan: Plan{NewerThanLineage: true, Version: 9}, noop: true},
		{name: "adopt only is not a noop and runs nothing", plan: Plan{Steps: adopt(1, 2)}},
		{name: "horizon write only", plan: Plan{WriteHorizon: true}},
		{name: "version write only", plan: Plan{WriteVersion: true}},
		{name: "forget only", plan: Plan{Forget: []int{4}}},
		{
			name: "mixed steps list only the runs",
			plan: Plan{Steps: []Step{{1, ActionAdopt, ""}, {2, ActionRun, ""}, {3, ActionAdopt, ""}, {4, ActionRun, ""}}},
			runs: []int{2, 4},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.plan.Noop(); got != tc.noop {
				t.Errorf("Noop() = %v, want %v", got, tc.noop)
			}
			if got := tc.plan.RunVersions(); !reflect.DeepEqual(got, tc.runs) {
				t.Errorf("RunVersions() = %v, want %v", got, tc.runs)
			}
		})
	}
}
