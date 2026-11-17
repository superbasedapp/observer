package secassesssvc

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestValidateRunCompares (depth plan W3.4): a run that named an earlier run is
// compared with it once its own model is checked, and the comparison is kept in
// the stored copy.
func TestValidateRunCompares(t *testing.T) {
	prev := &secassess.ThreatModelDoc{Threats: []secassess.Threat{
		{ID: "T-1", Title: "Credential stuffing", Framework: "stride", Category: "spoofing", Element: secassess.Element{Kind: "component", ID: "api"}, Band: secassess.BandHigh, Score: 16},
		{ID: "T-9", Title: "Gone threat", Framework: "stride", Category: "tampering", Element: secassess.Element{Kind: "component", ID: "db"}, Band: secassess.BandLow, Score: 2},
	}}
	run := modelRun(secassess.ContractThreatModel, true)

	t.Run("an earlier model is compared", func(t *testing.T) {
		root, side := t.TempDir(), newSide(t)
		writeAPIProject(t, root)
		writeModel(t, root, svcThreatModel)
		in := validateOpts(root, run, false)
		in.PreviousRun, in.Previous = "fedcba9876543210", prev
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Compared != "fedcba9876543210" || rec.CompareState != CompareOK || rec.Diff == nil {
			t.Fatalf("record = %+v", rec)
		}
		if rec.Diff.PrevRun != "fedcba9876543210" || len(rec.Diff.Removed) != 1 || rec.Diff.Removed[0].ID != "T-9" || rec.Diff.MatchedByID != 1 {
			t.Fatalf("diff = %+v", rec.Diff)
		}
		stored, ok := ReadModel(side, svcRun)
		if !ok || stored.Diff == nil || stored.CompareState != CompareOK || len(stored.Diff.Removed) != 1 {
			t.Fatalf("the stored copy lost the comparison: %+v", stored)
		}
	})
	t.Run("an earlier copy that is gone is said so, not guessed", func(t *testing.T) {
		root, side := t.TempDir(), newSide(t)
		writeAPIProject(t, root)
		writeModel(t, root, svcThreatModel)
		in := validateOpts(root, run, false)
		in.PreviousRun = "fedcba9876543210"
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil {
			t.Fatal(err)
		}
		if rec.CompareState != ComparePreviousMissing || rec.Diff != nil || rec.Compared == "" {
			t.Fatalf("record = %+v", rec)
		}
	})
	t.Run("no earlier run chosen leaves no comparison", func(t *testing.T) {
		root, side := t.TempDir(), newSide(t)
		writeAPIProject(t, root)
		writeModel(t, root, svcThreatModel)
		rec, _, err := ValidateRun(context.Background(), side, validateOpts(root, run, false))
		if err != nil {
			t.Fatal(err)
		}
		if rec.Compared != "" || rec.CompareState != "" || rec.Diff != nil {
			t.Fatalf("record = %+v", rec)
		}
	})
	t.Run("a pen test is never compared", func(t *testing.T) {
		root, side := t.TempDir(), newSide(t)
		writeAPIProject(t, root)
		writeModel(t, root, svcPentest)
		in := validateOpts(root, modelRun(secassess.ContractPentest, true), false)
		in.PreviousRun, in.Previous = "fedcba9876543210", prev
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Diff != nil || rec.CompareState != "" {
			t.Fatalf("record = %+v", rec)
		}
	})
}

// TestFitModelDropsTheComparisonFirst: when a stored copy is too large the
// comparison (which can be made again from the two copies) goes before the
// model does.
func TestFitModelDropsTheComparisonFirst(t *testing.T) {
	const limit = 8 << 10
	tm := &secassess.ThreatModelDoc{Summary: "small"}
	big := &secassess.ModelDiff{}
	for i := 0; i < 400; i++ {
		big.Added = append(big.Added, secassess.DiffItem{ID: "T-" + strings.Repeat("x", 30), Title: strings.Repeat("t", 40)})
	}
	rec := ModelRecord{Schema: ModelSchema, RunID: svcRun, Compared: "fedcba9876543210", CompareState: CompareOK, Diff: big}
	rec.Result.TM = tm
	blob, truncated := fitModelWithin(rec, limit)
	if blob == nil || truncated {
		t.Fatalf("the model should survive: %d %v", len(blob), truncated)
	}
	if !strings.Contains(string(blob), `"compare_state":"too_large"`) || strings.Contains(string(blob), `"diff"`) {
		t.Errorf("the comparison was not dropped first: %s", blob)
	}
	if !strings.Contains(string(blob), `"summary":"small"`) {
		t.Error("the model was dropped with the comparison")
	}
}

func runOf(id, kind, project string, created time.Time, state string, scope ...string) Run {
	r := Run{ID: id, Kind: kind, ProjectRootHash: project, CreatedAt: created, Phase: PhaseStarted, ScopePaths: scope}
	if state != "" {
		r.Validation = &ValidationRecord{State: state}
	}
	return r
}

// TestPreviousOptions: one row per way a run can be left out, plus the order
// and the default pick.
func TestPreviousOptions(t *testing.T) {
	side := newSide(t)
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	keep := func(id string) {
		rec := ModelRecord{Schema: ModelSchema, RunID: id, Contract: secassess.ContractThreatModel}
		rec.Result.TM = &secassess.ThreatModelDoc{}
		blob, err := marshalStored(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := side.Put(id, SideModel, blob); err != nil {
			t.Fatal(err)
		}
	}
	runs := []Run{
		runOf("0000000000000001", "threat_model", "p1", t0, "valid"),
		runOf("0000000000000002", "threat_model", "p1", t0.Add(time.Hour), "partial", "cmd/api"),
		runOf("0000000000000003", "threat_model", "p1", t0.Add(2*time.Hour), "invalid"),
		runOf("0000000000000004", "threat_model", "p1", t0.Add(3*time.Hour), ""),
		runOf("0000000000000005", "threat_model", "p2", t0.Add(4*time.Hour), "valid"),
		runOf("0000000000000006", "pentest_local", "p1", t0.Add(5*time.Hour), "valid"),
		runOf("0000000000000007", "threat_model", "p1", t0.Add(6*time.Hour), "valid"), // its stored copy is gone
		runOf("0000000000000008", "threat_model", "p1", t0.Add(7*time.Hour), "valid", "web"),
	}
	held := runOf("0000000000000009", "threat_model", "p1", t0.Add(8*time.Hour), "valid")
	held.Phase = PhaseHeld
	runs = append(runs, held)
	for _, id := range []string{"0000000000000001", "0000000000000002", "0000000000000003", "0000000000000005", "0000000000000006", "0000000000000008", "0000000000000009"} {
		keep(id)
	}
	got := PreviousOptions(runs, side, "p1", "0000000000000008")
	var ids []string
	for _, o := range got {
		ids = append(ids, o.ID)
	}
	// 3 is invalid, 4 has no check, 5 is another project, 6 another kind, 7 has no
	// stored copy, 8 is the run being planned, 9 never started: 2 and 1 remain,
	// newest first.
	if strings.Join(ids, ",") != "0000000000000002,0000000000000001" {
		t.Fatalf("options = %v", ids)
	}
	// Run 2 has the scope but its model is only partial: an option, labelled,
	// and never the default pick.
	if got[0].State != "partial" || got[1].State != "valid" {
		t.Errorf("states = %q %q", got[0].State, got[1].State)
	}
	if def := DefaultPrevious(got, []string{"cmd/api"}); def != "" {
		t.Errorf("a partial model must not be the default, got %q", def)
	}
	if def := DefaultPrevious(got, nil); def != "0000000000000001" {
		t.Errorf("default for the whole project = %q", def)
	}
	if def := DefaultPrevious(got, []string{"other"}); def != "" {
		t.Errorf("a different scope is a different model: default %q", def)
	}
	if PreviousModel(side, "0000000000000001") == nil || PreviousModel(side, "0000000000000007") != nil || PreviousModel(nil, "x") != nil {
		t.Error("PreviousModel does not follow the stored copy")
	}
}

// pcRuns builds n valid threat model runs of project p1, oldest first, ids
// 0000000000000001 and up, one hour apart; the scope and state of run i come from
// the callbacks.
func pcRuns(n int, scope func(i int) []string, state func(i int) string) []Run {
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var runs []Run
	for i := 1; i <= n; i++ {
		runs = append(runs, runOf(fmt.Sprintf("%016d", i), "threat_model", "p1", t0.Add(time.Duration(i)*time.Hour), state(i), scope(i)...))
	}
	return runs
}

func pcIDs(opts []PreviousOption) []string {
	var out []string
	for _, o := range opts {
		out = append(out, o.ID)
	}
	return out
}

func always(s string) func(int) string { return func(int) string { return s } }

// TestPreviousChoices (review W3-10): the default is chosen over every earlier
// run of the project and the scope, before the list is cut to ten; a partial
// model is an option and never the default.
func TestPreviousChoices(t *testing.T) {
	scoped := []string{"cmd/api"}
	id := func(i int) string { return fmt.Sprintf("%016d", i) }
	cases := []struct {
		name     string
		runs     []Run
		exclude  string
		scope    []string
		wantOpts []string
		wantDef  string
	}{
		{
			// The reviewer's case: eleven newer runs of other scopes hide an older
			// run with the asked scope. The default is found and shown besides the ten.
			"eleven recent runs of other scopes hide an older same-scope run",
			pcRuns(12, func(i int) []string {
				if i == 1 {
					return scoped
				}
				return []string{"web"}
			}, always("valid")),
			"", scoped,
			[]string{id(12), id(11), id(10), id(9), id(8), id(7), id(6), id(5), id(4), id(3), id(1)},
			id(1),
		},
		{
			"a default that is among the newest ten adds nothing",
			pcRuns(12, func(i int) []string {
				if i == 5 {
					return scoped
				}
				return []string{"web"}
			}, always("valid")),
			"", scoped,
			[]string{id(12), id(11), id(10), id(9), id(8), id(7), id(6), id(5), id(4), id(3)},
			id(5),
		},
		{
			"the default sits just past the ten shown",
			pcRuns(11, func(i int) []string {
				if i == 1 {
					return nil
				}
				return []string{"web"}
			}, always("valid")),
			"", nil,
			[]string{id(11), id(10), id(9), id(8), id(7), id(6), id(5), id(4), id(3), id(2), id(1)},
			id(1),
		},
		{
			"the whole project is a scope of its own",
			pcRuns(3, func(i int) []string {
				if i == 3 {
					return scoped
				}
				return nil
			}, always("valid")),
			"", nil,
			[]string{id(3), id(2), id(1)},
			id(2),
		},
		{
			// A partial model is offered and labelled, but is not the default: the
			// older valid run of the same scope is.
			"a partial model is an option but not the default",
			pcRuns(3, func(int) []string { return scoped }, func(i int) string {
				if i == 3 {
					return "partial"
				}
				return "valid"
			}),
			"", scoped,
			[]string{id(3), id(2), id(1)},
			id(2),
		},
		{
			"only a partial model of the scope: an option, no default",
			pcRuns(2, func(int) []string { return scoped }, always("partial")),
			"", scoped,
			[]string{id(2), id(1)},
			"",
		},
		{
			"a partial model older than the ten is not pulled in as a default",
			pcRuns(12, func(i int) []string {
				if i == 1 {
					return scoped
				}
				return []string{"web"}
			}, func(i int) string {
				if i == 1 {
					return "partial"
				}
				return "valid"
			}),
			"", scoped,
			[]string{id(12), id(11), id(10), id(9), id(8), id(7), id(6), id(5), id(4), id(3)},
			"",
		},
		{
			"nothing matching",
			pcRuns(3, func(int) []string { return []string{"web"} }, always("invalid")),
			"", scoped,
			nil,
			"",
		},
		{
			"no runs at all", nil, "", scoped, nil, "",
		},
		{
			"the run being planned is never its own earlier run",
			pcRuns(3, func(int) []string { return scoped }, always("valid")),
			id(3), scoped,
			[]string{id(2), id(1)},
			id(2),
		},
		{
			"a different scope is a different model: options, no default",
			pcRuns(2, func(int) []string { return []string{"web"} }, always("valid")),
			"", scoped,
			[]string{id(2), id(1)},
			"",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, def := PreviousChoices(tc.runs, nil, "p1", tc.exclude, tc.scope)
			if got := pcIDs(opts); !reflect.DeepEqual(got, tc.wantOpts) {
				t.Errorf("options %v, want %v", got, tc.wantOpts)
			}
			if def != tc.wantDef {
				t.Errorf("default %q, want %q", def, tc.wantDef)
			}
			if len(opts) > MaxPreviousOptions+1 {
				t.Errorf("%d options: more than the ten and the default", len(opts))
			}
			// The default, when there is one, is always among the options shown.
			if def != "" && !slices.Contains(pcIDs(opts), def) {
				t.Errorf("the default %q is not among the options %v", def, pcIDs(opts))
			}
			// Newest first.
			for i := 1; i < len(opts); i++ {
				if opts[i].CreatedAt.After(opts[i-1].CreatedAt) {
					t.Errorf("options are not newest first: %v", pcIDs(opts))
				}
			}
		})
	}
}

// TestPreviousChoicesSeesTheStoredCopy: the stored copy still decides what is an
// option, for the default as well as for the list.
func TestPreviousChoicesSeesTheStoredCopy(t *testing.T) {
	side := newSide(t)
	runs := pcRuns(3, func(int) []string { return nil }, always("valid"))
	for _, r := range runs[:2] { // the newest has no stored copy
		rec := ModelRecord{Schema: ModelSchema, RunID: r.ID, Contract: secassess.ContractThreatModel}
		rec.Result.TM = &secassess.ThreatModelDoc{}
		blob, err := marshalStored(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := side.Put(r.ID, SideModel, blob); err != nil {
			t.Fatal(err)
		}
	}
	opts, def := PreviousChoices(runs, side, "p1", "", nil)
	if got := pcIDs(opts); !reflect.DeepEqual(got, []string{fmt.Sprintf("%016d", 2), fmt.Sprintf("%016d", 1)}) || def != fmt.Sprintf("%016d", 2) {
		t.Errorf("options %v default %q", got, def)
	}
}

func TestPreviousOptionsCap(t *testing.T) {
	side := newSide(t)
	t0 := time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC)
	var runs []Run
	for i := 0; i < MaxPreviousOptions+4; i++ {
		id := strings.Repeat("a", 15) + string(rune('a'+i))
		runs = append(runs, runOf(id, "threat_model", "p1", t0.Add(time.Duration(i)*time.Hour), "valid"))
	}
	if got := PreviousOptions(runs, nil, "p1", ""); len(got) != MaxPreviousOptions {
		t.Fatalf("%d options", len(got))
	}
	_ = side
}

// TestRunRecordsThePlansChoices: the depth fields survive the record and are
// bounded.
func TestRunRecordsThePlansChoices(t *testing.T) {
	st := New(filepath.Join(t.TempDir(), Filename))
	scope := []string{}
	for i := 0; i < 12; i++ {
		scope = append(scope, strings.Repeat("d", 200))
	}
	r := Run{ID: svcRun, Kind: "threat_model", Phase: PhaseStarted, ScopePaths: scope, ScopeNote: "the billing service", PreviousRun: "fedcba9876543210", Start: strings.Repeat("s", secassess.MaxStartChoice), Prepare: true, SecretMode: "warn", Grounding: "full"}
	if _, err := st.Record(r, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, ok := st.Get(svcRun)
	if !ok {
		t.Fatal("not recorded")
	}
	if len(got.ScopePaths) != maxRunScopePaths || len(got.ScopePaths[0]) != maxRunScopePath || got.ScopeNote != "the billing service" || got.PreviousRun != "fedcba9876543210" ||
		len(got.Start) != secassess.MaxStartChoice || !got.Prepare || got.SecretMode != "warn" || got.Grounding != "full" {
		t.Fatalf("run = %+v", got)
	}
}

// TestRunRecordRefusesAStartChoiceOverItsBound: a start choice over its bound is
// refused whole, never cut (a cut command is one nobody wrote, and a held run
// would replay it), and nothing is recorded.
func TestRunRecordRefusesAStartChoiceOverItsBound(t *testing.T) {
	st := New(filepath.Join(t.TempDir(), Filename))
	over := Run{ID: svcRun, Kind: "pentest_local", Phase: PhaseStarted, Start: strings.Repeat("s", secassess.MaxStartChoice+1)}
	if _, err := st.Record(over, time.Now()); !errors.Is(err, ErrStartTooLong) {
		t.Fatalf("a start choice one byte over its bound: err = %v", err)
	}
	if _, ok := st.Get(svcRun); ok {
		t.Fatal("the refused run was recorded")
	}
	over.Start = strings.Repeat("s", secassess.MaxStartChoice)
	if _, err := st.Record(over, time.Now()); err != nil {
		t.Fatalf("a start choice at its bound: %v", err)
	}
}
