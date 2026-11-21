package secassesssvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

const svcRun = "0123456789abcdef"

// svcThreatModel is a small valid threat model whose references point into
// cmd/api/main.go (see writeAPIProject).
const svcThreatModel = `{
 "schema":"observer.threatmodel.v1","run_id":"0123456789abcdef","prompt_version":"tm.2",
 "generator":{"tool":"claude-code","model":"m"},
 "summary":"A small web service.",
 "scope":{"in_scope":["cmd/api"],"assumptions":["Runs behind a proxy."]},
 "system":{
  "components":[
   {"id":"api","name":"API","type":"service","zone":"dmz","paths":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},
   {"id":"db","name":"Database","type":"datastore","zone":"internal"}
  ],
  "zones":[{"id":"dmz","name":"DMZ"},{"id":"internal","name":"Internal"}],
  "actors":[{"id":"user","name":"User","kind":"end_user"}],
  "assets":[{"id":"creds","name":"Credentials","sensitivity":"restricted","stored_in":["db"]}],
  "entry_points":[{"id":"login","component":"api","kind":"http_route","authn":"none","exposure":"internet","ref":{"path":"cmd/api/main.go","line":12}}],
  "flows":[{"id":"f1","from":"user","to":"api","data":["creds"],"protocol":"https","crosses":["dmz"],"authn":"none","encrypted":"yes"}]},
 "threats":[
  {"id":"T-1","title":"Credential stuffing","framework":"stride","category":"spoofing","element":{"kind":"component","id":"api"},"actor":"user","description":"Login has no throttle.","rating":{"likelihood":4,"impact":4},
   "missing":[{"text":"Rate limit the login route.","control":"throttle","effort":"s","refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]}],
   "cwe":["CWE-307"],"status":"identified"}
 ]
}`

const svcPentest = `{
 "schema":"observer.pentest.v1","run_id":"0123456789abcdef","prompt_version":"pt.2","generator":{"tool":"claude-code"},"summary":"Tested the dev server.",
 "target":{"url":"http://127.0.0.1:3000/","start":{"argv":["npm","run","dev"],"source":"package.json scripts.dev","started":true,"startup_seconds":6}},
 "method":{"standard":"wstg+ptes"},
 "coverage":[{"category":"ATHN","status":"tested","notes":"Tried weak passwords."}],
 "findings":[{"id":"F-1","title":"No login throttle","category":"ATHN","cwe":["CWE-307"],"rating":{"likelihood":4,"impact":3},"basis":"observed",
   "where":{"refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},"route":"/login",
   "impact":"Account takeover.","fix":"Add a throttle.","status":"open"}],
 "limits":["Only the dev server."]
}`

// writeAPIProject writes cmd/api/main.go with the line the fixtures cite.
func writeAPIProject(t *testing.T, root string) {
	t.Helper()
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) {"
	writeProjectFile(t, root, "cmd/api/main.go", strings.Join(lines, "\n")+"\n")
}

func writeModel(t *testing.T, root, body string) {
	t.Helper()
	writeProjectFile(t, root, secassess.ResultPaths(svcRun).Model, body)
}

func modelRun(contract secassess.Contract, ended bool) Run {
	r := Run{ID: svcRun, Kind: "threat_model", Contract: string(contract), Phase: PhaseStarted, Target: "http://127.0.0.1:3000/"}
	if ended {
		r.EndedAt = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	}
	return r
}

func newSide(t *testing.T) *SideData { return NewSideData(filepath.Join(t.TempDir(), SideDirName)) }

func validateOpts(root string, r Run, anyway bool) ModelInput {
	return ModelInput{
		ProjectRoot: root, Run: r, Anyway: anyway, Now: time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC),
		Options: secassess.DefaultValidateOptions(secassess.Contract(r.Contract), r.ID),
	}
}

func TestValidateRunThreatModel(t *testing.T) {
	root, side := t.TempDir(), newSide(t)
	writeAPIProject(t, root)
	writeModel(t, root, svcThreatModel)
	rec, v, err := ValidateRun(context.Background(), side, validateOpts(root, modelRun(secassess.ContractThreatModel, true), false))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if rec.Result.Report.State != secassess.ValidationValid && rec.Result.Report.State != secassess.ValidationPartial {
		t.Fatalf("report = %+v", rec.Result.Report)
	}
	if rec.Result.TM == nil || rec.SourceSHA == "" || rec.SourceBytes != int64(len(svcThreatModel)) || rec.Anyway {
		t.Fatalf("record = %+v", rec)
	}
	if v.State != string(rec.Result.Report.State) || v.ModelBytes != rec.SourceBytes || v.ModelMod == 0 || v.Refs.Found == 0 {
		t.Fatalf("scalars = %+v", v)
	}
	// The files the references were checked against are stamped, and the copy is stored.
	if len(rec.Files) != 1 || rec.Files[0].Path != "cmd/api/main.go" || rec.Files[0].Lines != 30 {
		t.Fatalf("files = %+v", rec.Files)
	}
	got, ok := ReadModel(side, svcRun)
	if !ok || got.RunID != svcRun || got.Result.TM == nil || got.SourceSHA != rec.SourceSHA {
		t.Fatalf("stored copy = %+v %v", got, ok)
	}
	// Nothing drifted yet; a changed file is named.
	if d, _ := StampsDrift(root, got.Files); len(d) != 0 {
		t.Fatalf("drift on an unchanged project: %v", d)
	}
	writeProjectFile(t, root, "cmd/api/main.go", "package main\n")
	if d, _ := StampsDrift(root, got.Files); len(d) != 1 || d[0] != "cmd/api/main.go" {
		t.Fatalf("drift after an edit: %v", d)
	}
}

func TestValidateRunPentest(t *testing.T) {
	root := t.TempDir()
	writeAPIProject(t, root)
	writeModel(t, root, svcPentest)
	r := modelRun(secassess.ContractPentest, true)
	r.Kind = "pentest_local"
	rec, _, err := ValidateRun(context.Background(), nil, validateOpts(root, r, false))
	if err != nil || rec.Result.PT == nil {
		t.Fatalf("validate: %v %+v", err, rec.Result.Report)
	}
	if hasIssueCode(rec.Result.Report, "target_differs") {
		t.Errorf("the run's own target was flagged: %+v", rec.Result.Report.Issues)
	}
	// A different confirmed target is said, not silently accepted.
	r.Target = "http://127.0.0.1:4000/"
	rec, _, err = ValidateRun(context.Background(), nil, validateOpts(root, r, false))
	if err != nil || !hasIssueCode(rec.Result.Report, "target_differs") {
		t.Fatalf("a different target: %v %+v", err, rec.Result.Report.Issues)
	}
}

func hasIssueCode(r secassess.Report, code string) bool {
	for _, i := range r.Issues {
		if i.Code == code {
			return true
		}
	}
	return false
}

// TestValidateRunRefusals: what is not a validation at all, one row each.
func TestValidateRunRefusals(t *testing.T) {
	root := t.TempDir()
	writeAPIProject(t, root)
	cases := []struct {
		name   string
		run    func() Run
		anyway bool
		model  string
		want   error
	}{
		{"a legacy run has no model contract", func() Run { return modelRun("", true) }, false, svcThreatModel, ErrNoModelContract},
		{"the sarif contract is not a model contract", func() Run { return modelRun(secassess.ContractSARIF, true) }, false, svcThreatModel, ErrNoModelContract},
		{"a held run has no folder", func() Run {
			r := modelRun(secassess.ContractThreatModel, true)
			r.Phase = PhaseHeld
			return r
		}, false, svcThreatModel, ErrRunNotStarted},
		{"a run still running is refused", func() Run { return modelRun(secassess.ContractThreatModel, false) }, false, svcThreatModel, ErrRunRunning},
		{"a run still running is validated when asked", func() Run { return modelRun(secassess.ContractThreatModel, false) }, true, svcThreatModel, nil},
		{"no assessment.json", func() Run { return modelRun(secassess.ContractThreatModel, true) }, false, "", ErrAbsent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_ = os.RemoveAll(filepath.Join(root, ".observer"))
			if tc.model != "" {
				writeModel(t, root, tc.model)
			}
			rec, _, err := ValidateRun(context.Background(), newSide(t), validateOpts(root, tc.run(), tc.anyway))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.anyway && tc.want == nil && !rec.Anyway {
				t.Errorf("a validate-anyway record does not say so")
			}
		})
	}
}

// TestValidateRunUnreadableFiles: a file the validator will not read is an
// invalid model with a closed reason, never an error and never a panic.
func TestValidateRunUnreadableFiles(t *testing.T) {
	t.Run("not JSON", func(t *testing.T) {
		root := t.TempDir()
		writeModel(t, root, "this is not json")
		rec, v, err := ValidateRun(context.Background(), nil, validateOpts(root, modelRun(secassess.ContractThreatModel, true), false))
		if err != nil || rec.Result.Report.State != secassess.ValidationInvalid || rec.Result.Report.Fatal == "" || v.State != "invalid" {
			t.Fatalf("%v %+v", err, rec.Result.Report)
		}
		if rec.Result.TM != nil || rec.Result.PT != nil {
			t.Errorf("a refused file kept a model")
		}
	})
	t.Run("over the size cap", func(t *testing.T) {
		root := t.TempDir()
		writeModel(t, root, strings.Repeat("x", secassess.MaxModelBytes+1))
		rec, _, err := ValidateRun(context.Background(), nil, validateOpts(root, modelRun(secassess.ContractThreatModel, true), false))
		if err != nil || rec.Result.Report.State != secassess.ValidationInvalid || rec.Result.Report.Fatal != "too_large" {
			t.Fatalf("%v %+v", err, rec.Result.Report)
		}
		// The default cap is 4 MiB and the message names it and the setting.
		if msg := rec.Result.Report.Issues[0].Message; !strings.Contains(msg, "4 MiB") || !strings.Contains(msg, "model_max_mib") {
			t.Errorf("message %q", msg)
		}
	})
	t.Run("a link in place of the file", func(t *testing.T) {
		root := t.TempDir()
		writeAPIProject(t, root)
		dir := filepath.Join(root, filepath.FromSlash(secassess.ResultPaths(svcRun).Dir))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, "cmd", "api", "main.go"), filepath.Join(dir, "assessment.json")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		rec, _, err := ValidateRun(context.Background(), nil, validateOpts(root, modelRun(secassess.ContractThreatModel, true), false))
		if err != nil || rec.Result.Report.State != secassess.ValidationInvalid || rec.Result.Report.Fatal != "not_regular" {
			t.Fatalf("%v %+v", err, rec.Result.Report)
		}
	})
}

// TestValidateRunNeverFoundWithoutAChecker: a project whose files cannot be read
// leaves every reference unchecked, never found.
func TestValidateRunMissingFiles(t *testing.T) {
	root := t.TempDir()
	writeModel(t, root, svcThreatModel) // the cited main.go is not written
	rec, v, err := ValidateRun(context.Background(), nil, validateOpts(root, modelRun(secassess.ContractThreatModel, true), false))
	if err != nil {
		t.Fatal(err)
	}
	if v.Refs.Found != 0 || v.Refs.Missing == 0 {
		t.Fatalf("refs = %+v", v.Refs)
	}
	if len(rec.Files) != 0 {
		t.Errorf("stamped files that were not read: %+v", rec.Files)
	}
}

// TestFitModel: a record over the side file's cap loses its model first and its
// issues second, and says so.
func TestFitModel(t *testing.T) {
	big := ModelRecord{Schema: ModelSchema, RunID: svcRun}
	const limit = 64 << 10
	tm := &secassess.ThreatModelDoc{Summary: strings.Repeat("s", limit)}
	big.Result.TM = tm
	big.Result.Report.State = secassess.ValidationPartial
	blob, truncated := fitModelWithin(big, limit)
	if blob == nil || !truncated || len(blob) > limit {
		t.Fatalf("blob %d truncated %v", len(blob), truncated)
	}
	small := ModelRecord{Schema: ModelSchema, RunID: svcRun}
	if blob, truncated := fitModelWithin(small, limit); blob == nil || truncated {
		t.Fatalf("a small record: %d %v", len(blob), truncated)
	}
	// Even the report does not fit: nothing is stored, and it says so.
	huge := ModelRecord{Schema: ModelSchema, RunID: svcRun}
	huge.Result.Report.Fatal = strings.Repeat("f", limit+1)
	if blob, truncated := fitModelWithin(huge, limit); blob != nil || !truncated {
		t.Fatalf("a record that cannot fit: %d %v", len(blob), truncated)
	}
}

// TestDescribeModelStates: the run's state follows the validation and reads the
// file as stale once it changes.
func TestDescribeModelStates(t *testing.T) {
	root, side := t.TempDir(), newSide(t)
	writeAPIProject(t, root)
	run := modelRun(secassess.ContractThreatModel, true)
	// The run has ended and wrote nothing: over, not "started" (a run still live reads started).
	if st := Describe(root, run).State; st != secassess.StateEndedEmpty {
		t.Fatalf("ended, nothing written: %s", st)
	}
	if st := Describe(root, modelRun(secassess.ContractThreatModel, false)).State; st != secassess.StateStarted {
		t.Fatalf("live, nothing written: %s", st)
	}
	writeProjectFile(t, root, secassess.ResultPaths(svcRun).Report, "# report\n")
	if st := Describe(root, run).State; st != secassess.StateReportReady {
		t.Fatalf("report only: %s", st)
	}
	writeModel(t, root, svcThreatModel)
	if st := Describe(root, run).State; st != secassess.StateModelReady {
		t.Fatalf("model, not validated: %s", st)
	}
	_, v, err := ValidateRun(context.Background(), side, validateOpts(root, run, false))
	if err != nil {
		t.Fatal(err)
	}
	run.Validation = &v
	if got := Describe(root, run); got.State != secassess.StateValidated || got.ModelStale {
		t.Fatalf("validated: %s stale %v", got.State, got.ModelStale)
	}
	// The agent rewrites the file after validation: the validation is out of date.
	writeModel(t, root, svcThreatModel+"\n ")
	if got := Describe(root, run); got.State != secassess.StateModelReady || !got.ModelStale {
		t.Fatalf("edited after validation: %s stale %v", got.State, got.ModelStale)
	}
	// An invalid outcome reads as invalid.
	run.Validation = &ValidationRecord{State: string(secassess.ValidationInvalid), ModelBytes: int64(len(svcThreatModel) + 2)}
	info, _ := os.Stat(filepath.Join(root, filepath.FromSlash(secassess.ResultPaths(svcRun).Model)))
	run.Validation.ModelMod = info.ModTime().UnixNano()
	if got := Describe(root, run); got.State != secassess.StateInvalid {
		t.Fatalf("invalid: %s", got.State)
	}
	// A legacy run (no contract) never reads a model state.
	legacy := run
	legacy.Contract = ""
	if got := Describe(root, legacy); got.State != secassess.StateReportReady {
		t.Fatalf("legacy run: %s", got.State)
	}
}

// TestStoreSetValidation: the scalar record is kept on the run and capped.
func TestStoreSetValidation(t *testing.T) {
	s := New(filepath.Join(t.TempDir(), Filename))
	if _, err := s.Record(Run{ID: svcRun, Kind: "threat_model", Contract: "threatmodel.v1"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetValidation(svcRun, ValidationRecord{State: strings.Repeat("v", 1000), ModelBytes: 12, Refs: secassess.RefTally{Found: 3}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Get(svcRun)
	if got.Validation == nil || len(got.Validation.State) > maxField || got.Validation.Refs.Found != 3 || got.Contract != "threatmodel.v1" {
		t.Fatalf("run = %+v", got)
	}
	if err := s.SetValidation("ffffffffffffffff", ValidationRecord{}); err == nil {
		t.Fatal("a validation was recorded on a run that does not exist")
	}
}

// TestValidateRunKeepsTheStoredComparison (review W3-19): validating again after
// the earlier run's checked copy was pruned must not replace a comparison the
// stored copy already holds, as long as it is the same earlier run and the same
// assessment.json.
func TestValidateRunKeepsTheStoredComparison(t *testing.T) {
	const earlier = "fedcba9876543210"
	prev := &secassess.ThreatModelDoc{Threats: []secassess.Threat{
		{ID: "T-1", Title: "Credential stuffing", Framework: "stride", Category: "spoofing", Element: secassess.Element{Kind: "component", ID: "api"}, Band: secassess.BandHigh, Score: 16},
		{ID: "T-9", Title: "Gone threat", Framework: "stride", Category: "tampering", Element: secassess.Element{Kind: "component", ID: "db"}, Band: secassess.BandLow, Score: 2},
	}}
	run := modelRun(secassess.ContractThreatModel, true)
	// first validates with the earlier copy present and stores the comparison.
	first := func(t *testing.T) (string, *SideData) {
		t.Helper()
		root, side := t.TempDir(), newSide(t)
		writeAPIProject(t, root)
		writeModel(t, root, svcThreatModel)
		in := validateOpts(root, run, false)
		in.PreviousRun, in.Previous = earlier, prev
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil || rec.CompareState != CompareOK || rec.Diff == nil {
			t.Fatalf("first validation: %v %+v", err, rec)
		}
		return root, side
	}
	// again validates once more, the earlier copy gone.
	again := func(t *testing.T, root string, side *SideData, previousRun string) ModelRecord {
		t.Helper()
		in := validateOpts(root, run, false)
		in.PreviousRun = previousRun
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	t.Run("the same earlier run and the same file keep the comparison", func(t *testing.T) {
		root, side := first(t)
		rec := again(t, root, side, earlier)
		if rec.CompareState != CompareOK || rec.Diff == nil || rec.Compared != earlier || rec.Diff.PrevRun != earlier || len(rec.Diff.Removed) != 1 || rec.Diff.Removed[0].ID != "T-9" {
			t.Fatalf("record = %+v", rec)
		}
		stored, ok := ReadModel(side, svcRun)
		if !ok || stored.CompareState != CompareOK || stored.Diff == nil || len(stored.Diff.Removed) != 1 {
			t.Fatalf("the stored copy lost the comparison: %+v", stored)
		}
	})
	t.Run("a changed assessment.json is a new question: previous_missing", func(t *testing.T) {
		root, side := first(t)
		writeModel(t, root, strings.Replace(svcThreatModel, "A small web service.", "A small web service, rewritten.", 1))
		rec := again(t, root, side, earlier)
		if rec.CompareState != ComparePreviousMissing || rec.Diff != nil || rec.Compared != earlier {
			t.Fatalf("record = %+v", rec)
		}
	})
	t.Run("another earlier run is a new question: previous_missing", func(t *testing.T) {
		root, side := first(t)
		rec := again(t, root, side, "0123456789abcdee")
		if rec.CompareState != ComparePreviousMissing || rec.Diff != nil || rec.Compared != "0123456789abcdee" {
			t.Fatalf("record = %+v", rec)
		}
	})
	t.Run("a stored copy that never held a comparison has none to keep", func(t *testing.T) {
		root, side := t.TempDir(), newSide(t)
		writeAPIProject(t, root)
		writeModel(t, root, svcThreatModel)
		in := validateOpts(root, run, false)
		in.PreviousRun = earlier // the earlier copy was already gone
		if rec, _, err := ValidateRun(context.Background(), side, in); err != nil || rec.CompareState != ComparePreviousMissing {
			t.Fatalf("first: %v %+v", err, rec)
		}
		if rec := again(t, root, side, earlier); rec.CompareState != ComparePreviousMissing || rec.Diff != nil {
			t.Fatalf("record = %+v", rec)
		}
	})
	t.Run("no side store keeps nothing", func(t *testing.T) {
		root := t.TempDir()
		writeAPIProject(t, root)
		writeModel(t, root, svcThreatModel)
		in := validateOpts(root, run, false)
		in.PreviousRun = earlier
		rec, _, err := ValidateRun(context.Background(), nil, in)
		if err != nil || rec.CompareState != ComparePreviousMissing || rec.Diff != nil {
			t.Fatalf("record = %+v err %v", rec, err)
		}
	})
	t.Run("a comparison that was too large to keep has none to keep", func(t *testing.T) {
		root, side := first(t)
		stored, _ := ReadModel(side, svcRun)
		stored.Diff, stored.CompareState = nil, CompareTooLarge
		blob, err := marshalStored(stored)
		if err != nil {
			t.Fatal(err)
		}
		if err := side.Put(svcRun, SideModel, blob); err != nil {
			t.Fatal(err)
		}
		if rec := again(t, root, side, earlier); rec.CompareState != ComparePreviousMissing || rec.Diff != nil {
			t.Fatalf("record = %+v", rec)
		}
	})
}
