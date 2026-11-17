package secassesssvc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// modelImportFixture validates the fixture threat model into a side store and
// returns the run as the dashboard would hold it after the check.
func modelImportFixture(t *testing.T, model string) (root string, side *SideData, run Run) {
	t.Helper()
	root, side = t.TempDir(), newSide(t)
	writeAPIProject(t, root)
	writeModel(t, root, model)
	run = modelRun(secassess.ContractThreatModel, true)
	_, v, err := ValidateRun(context.Background(), side, validateOpts(root, run, false))
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	run.Validation = &v
	return root, side, run
}

// recordingSeam is an import seam that remembers what it was handed.
type recordingSeam struct {
	calls int
	data  []byte
	err   error
}

func (s *recordingSeam) fn(_ context.Context, _ string, data []byte) (Counts, error) {
	s.calls++
	s.data = data
	if s.err != nil {
		return Counts{}, s.err
	}
	return Counts{Findings: 1, New: 1}, nil
}

func modelImportInput(root string, side *SideData, run Run, seam *recordingSeam, d DeriveSettings) ImportInput {
	return ImportInput{
		ProjectRoot: root, Run: run, Selected: true, Seam: seam.fn, Side: side, Derive: d,
		Now: time.Date(2026, 11, 14, 14, 0, 0, 0, time.UTC),
	}
}

// TestModelImportTakesTheDerivedDocument: a validated threat model imports the
// findings Observer derives from it, under both rule-id shapes, and the record
// says what the derivation did.
func TestModelImportTakesTheDerivedDocument(t *testing.T) {
	root, side, run := modelImportFixture(t, svcThreatModel)
	cases := []struct {
		name    string
		derive  DeriveSettings
		wantID  string
		notWant string
	}{
		{"the run id in the rule id", DeriveSettings{}, "assess.tm." + svcRun + ".cwe-307", ""},
		{"a stable rule id", DeriveSettings{Dedup: true}, "assess.tm.cwe-307", "assess.tm." + svcRun},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seam := &recordingSeam{}
			rec, err := RunImport(context.Background(), modelImportInput(root, side, run, seam, tc.derive))
			if err != nil || rec.Outcome != string(secassess.ImportDone) {
				t.Fatalf("record = %+v, %v", rec, err)
			}
			if seam.calls != 1 || !strings.Contains(string(seam.data), tc.wantID) {
				t.Errorf("seam calls %d, document %s", seam.calls, seam.data)
			}
			if tc.notWant != "" && strings.Contains(string(seam.data), tc.notWant) {
				t.Errorf("the document names %q: %s", tc.notWant, seam.data)
			}
			// Nothing the agent wrote as prose reaches the import.
			for _, prose := range []string{"Rate limit the login route", "Login has no throttle", "Credential stuffing"} {
				if strings.Contains(string(seam.data), prose) {
					t.Errorf("the derived document carries the agent's words %q", prose)
				}
			}
			d := rec.Derived
			if d == nil || d.Considered != 1 || d.Kept != 1 || d.Dedup != tc.derive.Dedup || rec.Prepared != 1 || rec.Findings != 1 {
				t.Errorf("derived = %+v prepared %d", d, rec.Prepared)
			}
		})
	}
}

// TestModelImportNeedsACurrentValidation: no validation, a refused one and a
// stale one each answer ErrNotValidated and call nothing.
func TestModelImportNeedsACurrentValidation(t *testing.T) {
	root, side, run := modelImportFixture(t, svcThreatModel)
	refused := run
	rv := *run.Validation
	rv.State = string(secassess.ValidationInvalid)
	refused.Validation = &rv
	none := run
	none.Validation = nil
	for name, r := range map[string]Run{"never validated": none, "refused whole": refused} {
		seam := &recordingSeam{}
		if _, err := RunImport(context.Background(), modelImportInput(root, side, r, seam, DeriveSettings{})); !errors.Is(err, ErrNotValidated) || seam.calls != 0 {
			t.Errorf("%s: err = %v, calls %d", name, err, seam.calls)
		}
	}
	// The file changed after the validation.
	writeModel(t, root, svcThreatModel+"\n ")
	seam := &recordingSeam{}
	if _, err := RunImport(context.Background(), modelImportInput(root, side, run, seam, DeriveSettings{})); !errors.Is(err, ErrNotValidated) || seam.calls != 0 {
		t.Errorf("stale: err = %v, calls %d", err, seam.calls)
	}
	// No project folder.
	if _, err := RunImport(context.Background(), ImportInput{ProjectRoot: "", Run: run, Selected: true, Seam: seam.fn, Side: side, Now: time.Now()}); !errors.Is(err, ErrNotValidated) {
		t.Errorf("no root: err = %v", err)
	}
	// An unselected component answers unavailable before anything is read.
	rec, err := RunImport(context.Background(), ImportInput{ProjectRoot: root, Run: none, Selected: false, Seam: seam.fn, Side: side, Now: time.Now()})
	if err != nil || rec.Outcome != string(secassess.ImportUnavailable) || rec.Reason != ReasonNotSelected {
		t.Errorf("unselected: %+v, %v", rec, err)
	}
}

// TestModelImportWithNothingToImport: a model that derives no finding records
// no_findings, hands the import nothing and says why in the counts.
func TestModelImportWithNothingToImport(t *testing.T) {
	// A missing mitigation with no reference has no location.
	noRef := strings.Replace(svcThreatModel, `,"refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]`, "", 1)
	if noRef == svcThreatModel {
		t.Fatal("fixture: the reference was not removed")
	}
	cases := []struct {
		name   string
		model  string
		derive DeriveSettings
		check  func(*DerivedRecord) bool
	}{
		{"no location", noRef, DeriveSettings{}, func(d *DerivedRecord) bool { return d.NoLocation == 1 && d.Considered == 1 }},
		{"under the minimum band", svcThreatModel, DeriveSettings{MinBand: secassess.BandCritical}, func(d *DerivedRecord) bool { return d.UnderMinBand == 1 && d.MinBand == "critical" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, side, run := modelImportFixture(t, tc.model)
			seam := &recordingSeam{}
			rec, err := RunImport(context.Background(), modelImportInput(root, side, run, seam, tc.derive))
			if err != nil || rec.Outcome != string(secassess.ImportNoFindings) || seam.calls != 0 {
				t.Fatalf("record = %+v, %v, calls %d", rec, err, seam.calls)
			}
			if rec.Derived == nil || !tc.check(rec.Derived) || rec.Derived.Kept != 0 {
				t.Errorf("derived = %+v", rec.Derived)
			}
		})
	}
}

// manyThreats is a threat model with n threats, each with one located missing
// mitigation at its own line, rated so the order is known.
func manyThreats(n int) string {
	var b strings.Builder
	b.WriteString(`{"schema":"observer.threatmodel.v1","run_id":"` + svcRun + `","generator":{"tool":"t"},
 "scope":{},"system":{"components":[{"id":"api","name":"API","type":"service"}]},"threats":[`)
	for i := 1; i <= n; i++ {
		if i > 1 {
			b.WriteString(",")
		}
		// likelihood 1..5 and impact 5 give scores 5, 10, 15, 20, 25 in turn.
		fmt.Fprintf(&b, `{"id":"T-%d","title":"t","framework":"stride","category":"spoofing","element":{"kind":"component","id":"api"},"rating":{"likelihood":%d,"impact":5},
  "missing":[{"text":"m","refs":[{"path":"cmd/api/main.go","line":%d}]}],"cwe":["CWE-%d"]}`, i, (i-1)%5+1, i, 100+i)
	}
	b.WriteString("]}")
	return b.String()
}

// TestModelImportCapAndOrder: no cap imports every located candidate; a cap
// keeps the highest bands first and counts what it left out.
func TestModelImportCapAndOrder(t *testing.T) {
	root, side, run := modelImportFixture(t, manyThreats(10))
	seam := &recordingSeam{}
	rec, err := RunImport(context.Background(), modelImportInput(root, side, run, seam, DeriveSettings{}))
	if err != nil || rec.Derived == nil || rec.Derived.Considered != 10 || rec.Derived.Kept != 10 || rec.Derived.OverCap != 0 {
		t.Fatalf("no cap: %+v, %v", rec.Derived, err)
	}
	seam = &recordingSeam{}
	rec, err = RunImport(context.Background(), modelImportInput(root, side, run, seam, DeriveSettings{Cap: 4}))
	if err != nil || rec.Derived.Kept != 4 || rec.Derived.OverCap != 6 || rec.Derived.Cap != 4 {
		t.Fatalf("cap 4: %+v, %v", rec.Derived, err)
	}
	// The four kept are the highest scores (25 twice, 20 twice): T-5 and T-10 first.
	for _, id := range []string{"cwe-105", "cwe-110", "cwe-104", "cwe-109"} {
		if !strings.Contains(string(seam.data), id) {
			t.Errorf("the capped document lacks %s: %s", id, seam.data)
		}
	}
	if strings.Contains(string(seam.data), "cwe-101") {
		t.Errorf("the capped document kept the lowest band: %s", seam.data)
	}
}

// TestModelImportFailures: the seam's failures are records, as for a findings
// file, and a lost stored copy is its own reason.
func TestModelImportFailures(t *testing.T) {
	root, side, run := modelImportFixture(t, svcThreatModel)
	for name, tc := range map[string]struct {
		err    error
		reason string
	}{
		"the import refuses the document": {errors.Join(ErrInputRefused, errors.New("x")), ReasonImportRefused},
		"the node fails":                  {errors.New("disk"), ReasonNodeError},
	} {
		seam := &recordingSeam{err: tc.err}
		rec, err := RunImport(context.Background(), modelImportInput(root, side, run, seam, DeriveSettings{}))
		if err != nil || rec.Outcome != string(secassess.ImportFailed) || rec.Reason != tc.reason {
			t.Errorf("%s: %+v, %v", name, rec, err)
		}
	}
	// The side copy is gone: the model is current but there is nothing to derive from.
	if err := side.Delete(run.ID); err != nil {
		t.Fatal(err)
	}
	seam := &recordingSeam{}
	rec, err := RunImport(context.Background(), modelImportInput(root, side, run, seam, DeriveSettings{}))
	if err != nil || rec.Outcome != string(secassess.ImportFailed) || rec.Reason != ReasonModelUnavailable || seam.calls != 0 {
		t.Errorf("lost copy: %+v, %v, calls %d", rec, err, seam.calls)
	}
}

// TestLegacyRunStillImportsItsFindingsFile: a run recorded before the model
// contracts (no Contract) reads findings.sarif as it always did, even for a kind
// whose new runs derive their findings.
func TestLegacyRunStillImportsItsFindingsFile(t *testing.T) {
	root := t.TempDir()
	writeResult(t, root, "findings.sarif", goodSARIF)
	seam := &recordingSeam{}
	rec, err := RunImport(context.Background(), ImportInput{ProjectRoot: root, Run: Run{ID: rid, Kind: "threat_model"}, Selected: true, Seam: seam.fn, Now: time.Now()})
	if err != nil || rec.Outcome != string(secassess.ImportDone) || rec.Derived != nil || seam.calls != 1 {
		t.Fatalf("legacy threat model: %+v, %v, calls %d", rec, err, seam.calls)
	}
	if !strings.Contains(string(seam.data), "assess.tm."+rid+".weak-session") {
		t.Errorf("document = %s", seam.data)
	}
}
