package secassesssvc

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

const mib = 1 << 20

// padTo returns body followed by spaces up to exactly n bytes. Trailing white
// space after the one JSON value is valid, so the file stays a model.
func padTo(t *testing.T, body string, n int) string {
	t.Helper()
	if n < len(body) {
		t.Fatalf("a %d byte body does not fit %d bytes", len(body), n)
	}
	return body + strings.Repeat(" ", n-len(body))
}

// TestValidateRunModelCap: the size cap of assessment.json is the setting
// model_max_mib. At or under it the file is read; one byte over it the result
// is refused as too_large with the cap in MiB in the message; a setting above
// the ceiling is clamped to it and a setting that is zero or negative reads as
// the default.
func TestValidateRunModelCap(t *testing.T) {
	cases := []struct {
		name     string
		maxBytes int // ValidateOptions.MaxBytes
		size     int // the file's size
		wantCap  int // the cap in force
		refused  bool
	}{
		{"1 MiB: one byte under", 1 * mib, 1*mib - 1, 1 * mib, false},
		{"1 MiB: exactly the cap", 1 * mib, 1 * mib, 1 * mib, false},
		{"1 MiB: one byte over", 1 * mib, 1*mib + 1, 1 * mib, true},
		{"default (0): one byte under 4 MiB", 0, 4*mib - 1, 4 * mib, false},
		{"default (0): exactly 4 MiB", 0, 4 * mib, 4 * mib, false},
		{"default (0): one byte over 4 MiB", 0, 4*mib + 1, 4 * mib, true},
		{"a negative setting reads as the default", -3, 4*mib + 1, 4 * mib, true},
		{"8 MiB: one byte under", 8 * mib, 8*mib - 1, 8 * mib, false},
		{"8 MiB: exactly the cap", 8 * mib, 8 * mib, 8 * mib, false},
		{"8 MiB: one byte over", 8 * mib, 8*mib + 1, 8 * mib, true},
		{"8 MiB: a file the default would have read is read", 8 * mib, 5 * mib, 8 * mib, false},
		{"above the ceiling is clamped: exactly 32 MiB is read", 40 * mib, secassess.MaxModelBytesCeiling, secassess.MaxModelBytesCeiling, false},
		{"above the ceiling is clamped: one byte over 32 MiB is refused", 40 * mib, secassess.MaxModelBytesCeiling + 1, secassess.MaxModelBytesCeiling, true},
		{"exactly the ceiling setting", secassess.MaxModelBytesCeiling, secassess.MaxModelBytesCeiling + 1, secassess.MaxModelBytesCeiling, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeAPIProject(t, root)
			writeModel(t, root, padTo(t, svcThreatModel, tc.size))
			in := validateOpts(root, modelRun(secassess.ContractThreatModel, true), false)
			in.Options.MaxBytes = tc.maxBytes
			if got := in.Options.ModelCap(); got != tc.wantCap {
				t.Fatalf("ModelCap() = %d, want %d", got, tc.wantCap)
			}
			rec, v, err := ValidateRun(context.Background(), nil, in)
			if err != nil {
				t.Fatalf("validate: %v", err)
			}
			rep := rec.Result.Report
			if !tc.refused {
				if rep.State == secassess.ValidationInvalid || rep.Fatal != "" || rec.Result.TM == nil || rec.SourceBytes != int64(tc.size) {
					t.Fatalf("a file at or under the cap was not read: source %d, report %+v", rec.SourceBytes, rep)
				}
				return
			}
			if rep.State != secassess.ValidationInvalid || rep.Fatal != "too_large" || v.State != string(secassess.ValidationInvalid) {
				t.Fatalf("a file over the cap: report %+v, scalars %+v", rep, v)
			}
			if rec.Result.TM != nil || rec.Result.PT != nil || rec.SourceBytes != 0 || rec.SourceSHA != "" {
				t.Errorf("a refused file was read or kept: source %d %q", rec.SourceBytes, rec.SourceSHA)
			}
			if len(rep.Issues) != 1 {
				t.Fatalf("issues = %+v", rep.Issues)
			}
			msg := rep.Issues[0].Message
			if want := fmt.Sprintf("%d MiB", tc.wantCap>>20); !strings.Contains(msg, want) || !strings.Contains(msg, "model_max_mib") {
				t.Errorf("message %q does not name the cap %q and the setting", msg, want)
			}
		})
	}
}

// ---- the stored copy holds anything the validator accepts ----

// fillItems returns comma-joined items, as many as fit in max bytes.
func fillItems(max int, item func(i int) string) (string, int) {
	var b strings.Builder
	n := 0
	for {
		it := item(n)
		add := len(it)
		if n > 0 {
			add++
		}
		if b.Len()+add > max {
			return b.String(), n
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(it)
		n++
	}
}

// refList is the densest list of references: eight of the shortest a model can
// write (a bare path). The very first reference of a model points at "a"
// (which a test project holds); every other points at "b", which reads
// "missing" with the default read budget and "unchecked" when the budget is one
// file, the longest state word the stored copy can add to a bare reference.
func refList(first bool) string {
	refs := make([]string, 8)
	for i := range refs {
		p := "b"
		if first && i == 0 {
			p = "a"
		}
		refs[i] = `{"path":"` + p + `"}`
	}
	return strings.Join(refs, ",")
}

const (
	denseRunID  = svcRun
	denseTMHead = `{"schema":"observer.threatmodel.v1","run_id":"` + denseRunID + `","system":{"components":[{"id":"api","name":"API","type":"service"}]},"threats":[`
	densePTHead = `{"schema":"observer.pentest.v1","run_id":"` + denseRunID + `","findings":[`
	denseTMTail = `]}`
	// denseThreat is a threat as small as the validator accepts, ending where
	// its lists would begin.
	denseThreatOpen = `{"id":"T1","title":"t","framework":"stride","category":"spoofing","element":{"kind":"component","id":"api"},"rating":{"likelihood":5,"impact":5}`
)

// denseModel is one generated model with a count of the items the validator
// must keep (so a generator that is refused item by item cannot pass quietly).
type denseModel struct {
	body     string
	contract secassess.Contract
	items    int
	count    func(ModelRecord) int
}

func tmThreats(r ModelRecord) int {
	if r.Result.TM == nil {
		return -1
	}
	return len(r.Result.TM.Threats)
}

func tmMitigations(r ModelRecord) int {
	if r.Result.TM == nil || len(r.Result.TM.Threats) == 0 {
		return -1
	}
	t := r.Result.TM.Threats[0]
	return len(t.Existing) + len(t.Missing)
}

// markup is the worst case for a JSON encoder that escapes markup characters:
// a text made only of them survives the validator's cleaner (it is not a
// control character, a space or a dash).
func markup(c string, n int) string { return strings.Repeat(c, n) }

// denseModels are the generators, one per structure that can grow with the file
// size (the counts of threats, findings and mitigations are no longer capped).
func denseModels(limit int) map[string]denseModel {
	out := map[string]denseModel{}

	// A pen test: many findings, each as small as accepted, eight bare refs each.
	{
		raw, n := fillItems(limit-len(densePTHead)-len(denseTMTail), func(i int) string {
			return fmt.Sprintf(`{"id":"F%d","title":"t","category":"ATHN","rating":{"likelihood":5,"impact":5},"basis":"observed","where":{"refs":[%s]}}`, i, refList(i == 0))
		})
		out["pen test: findings with eight bare references"] = denseModel{
			body: densePTHead + raw + denseTMTail, contract: secassess.ContractPentest, items: n,
			count: func(r ModelRecord) int {
				if r.Result.PT == nil {
					return -1
				}
				return len(r.Result.PT.Findings)
			},
		}
	}
	// A pen test: findings with no reference at all (the stored copy adds the
	// band, the score and an empty where).
	{
		raw, n := fillItems(limit-len(densePTHead)-len(denseTMTail), func(i int) string {
			return fmt.Sprintf(`{"id":"F%d","title":"t","category":"ATHN","rating":{"likelihood":5,"impact":5},"basis":"observed"}`, i)
		})
		out["pen test: bare findings"] = denseModel{
			body: densePTHead + raw + denseTMTail, contract: secassess.ContractPentest, items: n,
			count: func(r ModelRecord) int {
				if r.Result.PT == nil {
					return -1
				}
				return len(r.Result.PT.Findings)
			},
		}
	}
	// A pen test whose every text is a markup character at its limit.
	{
		raw, n := fillItems(limit-len(densePTHead)-len(denseTMTail), func(i int) string {
			steps := make([]string, 8)
			for j := range steps {
				steps[j] = `{"step":"` + markup("<", 200) + `","request":"` + markup("&", 300) + `"}`
			}
			return fmt.Sprintf(`{"id":"F%d","title":"%s","category":"ATHN","rating":{"likelihood":5,"impact":5},"basis":"observed","route":"%s","impact":"%s","fix":"%s","reproduction":[%s]}`,
				i, markup(">", 120), markup("&", 200), markup("<", 400), markup(">", 400), strings.Join(steps, ","))
		})
		out["pen test: markup-only text"] = denseModel{
			body: densePTHead + raw + denseTMTail, contract: secassess.ContractPentest, items: n,
			count: func(r ModelRecord) int {
				if r.Result.PT == nil {
					return -1
				}
				return len(r.Result.PT.Findings)
			},
		}
	}
	// A threat model: one threat holding as many mitigations as the file takes,
	// each with eight bare references.
	{
		pre := denseTMHead + denseThreatOpen + `,"missing":[`
		mid := `],"existing":[`
		suf := `]}` + denseTMTail
		room := limit - len(pre) - len(mid) - len(suf)
		mit := func(i int) string { return `{"text":"m","refs":[` + refList(i == 0) + `]}` }
		missing, nm := fillItems(room/2, mit)
		existing, ne := fillItems(room-len(missing)-1, func(i int) string { return mit(i + 1) })
		out["threat model: a threat with many mitigations of eight bare references"] = denseModel{
			body: pre + missing + mid + existing + suf, contract: secassess.ContractThreatModel, items: nm + ne, count: tmMitigations,
		}
	}
	// A threat model: many threats and no mitigations.
	{
		raw, n := fillItems(limit-len(denseTMHead)-len(denseTMTail), func(i int) string {
			return fmt.Sprintf(`{"id":"T%d","title":"t","framework":"stride","category":"spoofing","element":{"kind":"component","id":"api"},"rating":{"likelihood":5,"impact":5}}`, i)
		})
		out["threat model: many bare threats"] = denseModel{
			body: denseTMHead + raw + denseTMTail, contract: secassess.ContractThreatModel, items: n, count: tmThreats,
		}
	}
	// A threat model: mitigations whose text is markup at its limit.
	{
		pre := denseTMHead + denseThreatOpen + `,"missing":[`
		suf := `]}` + denseTMTail
		raw, n := fillItems(limit-len(pre)-len(suf), func(i int) string { return `{"text":"` + markup("<", 200) + `"}` })
		out["threat model: markup-only mitigation text"] = denseModel{
			body: pre + raw + suf, contract: secassess.ContractThreatModel, items: n, count: tmMitigations,
		}
	}
	// A threat model: markup in the threats' own text fields.
	{
		raw, n := fillItems(limit-len(denseTMHead)-len(denseTMTail), func(i int) string {
			return fmt.Sprintf(`{"id":"T%d","title":"%s","framework":"stride","category":"spoofing","element":{"kind":"component","id":"api"},"description":"%s","rating":{"likelihood":5,"impact":5}}`,
				i, markup("<", 120), markup("&", 600))
		})
		out["threat model: markup-only titles and descriptions"] = denseModel{
			body: denseTMHead + raw + denseTMTail, contract: secassess.ContractThreatModel, items: n, count: tmThreats,
		}
	}
	return out
}

// TestStoredModelHoldsAnythingTheValidatorAccepts pins the claim behind
// maxSideModel: whatever a validation accepts, the stored copy (the checked
// model with Observer's computed fields, and the report) is at most three
// times the size of the file it came from, so a copy sized from the largest
// size setting always fits. Because the ratio does not depend on the scale the
// models are generated at the cap of one MiB; the copy is also projected to
// the ceiling (32 MiB) and held to the side file's real cap.
func TestStoredModelHoldsAnythingTheValidatorAccepts(t *testing.T) {
	const limit = 1 * mib
	for name, dm := range denseModels(limit) {
		for _, budget := range []struct {
			name string
			b    RefBudget
		}{{"default budget", RefBudget{}}, {"a one file budget", RefBudget{Files: 1}}} {
			t.Run(name+" / "+budget.name, func(t *testing.T) {
				root, side := t.TempDir(), newSide(t)
				writeProjectFile(t, root, "a", "x\n")
				writeModel(t, root, dm.body)
				run := modelRun(dm.contract, true)
				if dm.contract == secassess.ContractPentest {
					run.Kind = "pentest_local"
				}
				in := validateOpts(root, run, false)
				in.Options.MaxBytes = limit
				in.Budget = budget.b
				rec, _, err := ValidateRun(context.Background(), side, in)
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				rep := rec.Result.Report
				if rep.State == secassess.ValidationInvalid {
					t.Fatalf("the generated model was refused: %+v", rep.Issues)
				}
				// The generator must really be the densest accepted: every item kept.
				if dm.items < 50 {
					t.Fatalf("the generator made only %d items", dm.items)
				}
				for k, c := range rep.Counts {
					if c.Refused != 0 || c.LeftOut != 0 {
						t.Fatalf("collection %s lost items: %+v", k, c)
					}
				}
				for _, is := range rep.Issues {
					if is.Severity == secassess.SevRefused || is.Severity == secassess.SevDropped {
						t.Fatalf("an item or field was left out: %+v", is)
					}
				}
				if int64(len(dm.body)) < limit*9/10 {
					t.Fatalf("the model is %d bytes, under nine tenths of the %d byte cap", len(dm.body), limit)
				}
				blob, ok := side.Get(svcRun, SideModel)
				if !ok {
					t.Fatal("no stored copy")
				}
				stored, ok := ReadModel(side, svcRun)
				if !ok || stored.Truncated || rec.Truncated || (stored.Result.TM == nil && stored.Result.PT == nil) {
					t.Fatalf("stored copy: ok %v, truncated %v/%v", ok, stored.Truncated, rec.Truncated)
				}
				if got := dm.count(stored); got != dm.items {
					t.Fatalf("the stored copy holds %d items of %d generated", got, dm.items)
				}
				ratio := float64(len(blob)) / float64(rec.SourceBytes)
				t.Logf("%d items, source %d bytes, stored %d bytes: ratio %.3f", dm.items, rec.SourceBytes, len(blob), ratio)
				if len(blob) > 3*int(rec.SourceBytes) {
					t.Errorf("the stored copy is %d bytes for a %d byte file (%.2f times, the claim is at most 3)", len(blob), rec.SourceBytes, ratio)
				}
				// The same copy at the ceiling must fit the side file's real cap.
				if projected := ratio * float64(secassess.MaxModelBytesCeiling); projected > float64(maxSideModel) {
					t.Errorf("a model at the %d byte ceiling would store %.0f bytes, over the side file's cap of %d", secassess.MaxModelBytesCeiling, projected, maxSideModel)
				}
			})
		}
	}
}

// TestStoredModelStructuralOverhead: what the stored copy adds that does not
// scale with the file (the coverage report of a model at the structural caps,
// the stamps of the files the references were checked against) stays inside the
// room maxSideModel leaves over three times the ceiling, even when the file is
// small enough that the overhead is a large share of it.
func TestStoredModelStructuralOverhead(t *testing.T) {
	slack := maxSideModel - 3*secassess.MaxModelBytesCeiling
	if slack <= 0 {
		t.Fatalf("no room beyond three times the ceiling: %d", slack)
	}
	t.Run("a threat model at every structural cap", func(t *testing.T) {
		var b strings.Builder
		b.WriteString(`{"schema":"observer.threatmodel.v1","run_id":"` + denseRunID + `","system":{"components":[`)
		for i := 0; i < 200; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"c%d","name":"n","type":"service","zone":"z%d"}`, i, i%50)
		}
		b.WriteString(`],"zones":[`)
		for i := 0; i < 50; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"z%d","name":"z"}`, i)
		}
		b.WriteString(`],"actors":[`)
		for i := 0; i < 50; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"u%d","name":"u","kind":"end_user"}`, i)
		}
		b.WriteString(`],"flows":[`)
		for i := 0; i < 400; i++ {
			if i > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"f%d","from":"c0","to":"c1","personal_data":true}`, i)
		}
		b.WriteString(`]},"threats":[`)
		b.WriteString(`{"id":"T1","title":"t","framework":"stride","category":"spoofing","element":{"kind":"component","id":"c0"},"rating":{"likelihood":5,"impact":5}}`)
		b.WriteString(`]}`)
		root, side := t.TempDir(), newSide(t)
		writeModel(t, root, b.String())
		in := validateOpts(root, modelRun(secassess.ContractThreatModel, true), false)
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil || rec.Result.Report.State == secassess.ValidationInvalid {
			t.Fatalf("validate: %v %+v", err, rec.Result.Report.Issues)
		}
		blob, _ := side.Get(svcRun, SideModel)
		stored, ok := ReadModel(side, svcRun)
		if !ok || stored.Truncated {
			t.Fatalf("stored copy: ok %v truncated %v", ok, stored.Truncated)
		}
		over := len(blob) - 3*int(rec.SourceBytes)
		t.Logf("source %d bytes, stored %d bytes, %d past three times the source (room %d)", rec.SourceBytes, len(blob), over, slack)
		if over > slack {
			t.Errorf("the structural overhead is %d bytes, more than the %d bytes of room", over, slack)
		}
	})
	t.Run("stamps of many distinct files read", func(t *testing.T) {
		// 64 components of eight paths each (the per-item bound), every path a
		// different file the project holds: more files than the default budget.
		const components, perItem = 64, 8
		const files = components * perItem
		root, side := t.TempDir(), newSide(t)
		var b strings.Builder
		b.WriteString(`{"schema":"observer.threatmodel.v1","run_id":"` + denseRunID + `","system":{"components":[`)
		for c := 0; c < components; c++ {
			if c > 0 {
				b.WriteByte(',')
			}
			fmt.Fprintf(&b, `{"id":"c%d","name":"n","type":"service","paths":[`, c)
			for p := 0; p < perItem; p++ {
				f := fmt.Sprintf("d/%04d", c*perItem+p)
				writeProjectFile(t, root, f, "x")
				if p > 0 {
					b.WriteByte(',')
				}
				b.WriteString(`{"path":"` + f + `"}`)
			}
			b.WriteString(`]}`)
		}
		b.WriteString(`]}}`)
		writeModel(t, root, b.String())
		in := validateOpts(root, modelRun(secassess.ContractThreatModel, true), false)
		in.Budget = RefBudget{Files: 5000}
		rec, _, err := ValidateRun(context.Background(), side, in)
		if err != nil || rec.Result.Report.State == secassess.ValidationInvalid {
			t.Fatalf("validate: %v %+v", err, rec.Result.Report.Issues)
		}
		if len(rec.Files) != files {
			t.Fatalf("%d stamps, want %d", len(rec.Files), files)
		}
		blob, _ := side.Get(svcRun, SideModel)
		over := len(blob) - 3*int(rec.SourceBytes)
		t.Logf("source %d bytes, stored %d bytes, %d past three times the source (room %d)", rec.SourceBytes, len(blob), over, slack)
		if over > slack {
			t.Errorf("the stamps cost %d bytes past three times the source, more than the %d bytes of room", over, slack)
		}
	})
}

// TestStoredModelRoundTripsMarkup: the stored copy is written without the
// encoder's markup escaping (which would grow a text of markup characters six
// times), and what it reads back is the text the validator kept.
func TestStoredModelRoundTripsMarkup(t *testing.T) {
	root, side := t.TempDir(), newSide(t)
	writeAPIProject(t, root)
	text := `a<b & c>d "quoted" \ back`
	model := strings.Replace(svcThreatModel, `"title":"Credential stuffing"`, `"title":`+mustJSON(t, text), 1)
	if model == svcThreatModel {
		t.Fatal("fixture: the title was not replaced")
	}
	writeModel(t, root, model)
	rec, _, err := ValidateRun(context.Background(), side, validateOpts(root, modelRun(secassess.ContractThreatModel, true), false))
	if err != nil || rec.Result.TM == nil {
		t.Fatalf("validate: %v %+v", err, rec.Result.Report)
	}
	blob, _ := side.Get(svcRun, SideModel)
	backslash := string(rune(92))
	for _, esc := range []string{backslash + "u003c", backslash + "u003e", backslash + "u0026"} {
		if strings.Contains(string(blob), esc) {
			t.Errorf("the stored copy escapes markup (%s): %.200s", esc, blob)
		}
	}
	got, ok := ReadModel(side, svcRun)
	if !ok || got.Result.TM == nil || len(got.Result.TM.Threats) != 1 || got.Result.TM.Threats[0].Title != text {
		t.Fatalf("round trip: ok %v, %+v", ok, got.Result.TM)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- the import after a stored copy that is missing or was left out ----

// storedRecord reads the stored copy a validation left, for a test to change.
func storedRecord(t *testing.T, side *SideData) ModelRecord {
	t.Helper()
	rec, ok := ReadModel(side, svcRun)
	if !ok || rec.Result.TM == nil {
		t.Fatalf("the fixture has no stored model: ok %v", ok)
	}
	return rec
}

// putRecord stores rec as the run's model.json.
func putRecord(t *testing.T, side *SideData, rec ModelRecord) {
	t.Helper()
	if err := side.Put(svcRun, SideModel, []byte(mustJSON(t, rec))); err != nil {
		t.Fatal(err)
	}
}

// TestImportModelTooLargeToKeep: a stored copy that did not fit the side file
// (it carries Truncated, the model left out) answers its own reason, never
// "unavailable", so the run does not offer to validate again; nothing is handed
// to the import.
func TestImportModelTooLargeToKeep(t *testing.T) {
	const wantReason = "model_too_large_to_keep" // the closed value the dashboard keys on
	cases := []struct {
		name string
		edit func(t *testing.T, side *SideData)
	}{
		{"the model was left out by fitModel", func(t *testing.T, side *SideData) {
			rec := storedRecord(t, side)
			// A limit that holds the report but not the model.
			noModel := rec
			noModel.Result.TM, noModel.Truncated = nil, true
			limit := len(mustJSON(t, noModel))
			blob, truncated := fitModelWithin(rec, limit)
			if blob == nil || !truncated {
				t.Fatalf("fitModelWithin(%d) = %d bytes, truncated %v", limit, len(blob), truncated)
			}
			if err := side.Put(svcRun, SideModel, blob); err != nil {
				t.Fatal(err)
			}
			if got, ok := ReadModel(side, svcRun); !ok || !got.Truncated || got.Result.TM != nil {
				t.Fatalf("the stored record: ok %v, truncated %v, model kept %v", ok, got.Truncated, got.Result.TM != nil)
			}
		}},
		{"the flag wins even when a model is still in the record", func(t *testing.T, side *SideData) {
			rec := storedRecord(t, side)
			rec.Truncated = true
			putRecord(t, side, rec)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, side, run := modelImportFixture(t, svcThreatModel)
			tc.edit(t, side)
			seam := &recordingSeam{}
			rec, err := RunImport(context.Background(), modelImportInput(root, side, run, seam, DeriveSettings{}))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if rec.Outcome != string(secassess.ImportFailed) || rec.Reason != wantReason || ReasonModelTooLarge != wantReason {
				t.Fatalf("record = %+v", rec)
			}
			if seam.calls != 0 || rec.Derived != nil || rec.Prepared != 0 || rec.Findings != 0 {
				t.Errorf("something was imported: calls %d, record %+v", seam.calls, rec)
			}
		})
	}
}

// TestImportModelUnavailable: a model that was validated but whose stored copy
// cannot be read back (deleted, another run's, unreadable, or empty without
// having been left out) answers model_unavailable, which validating again
// rebuilds; nothing is handed to the import.
func TestImportModelUnavailable(t *testing.T) {
	const wantReason = "model_unavailable" // the closed value the dashboard keys on
	cases := []struct {
		name string
		edit func(t *testing.T, side *SideData) *SideData // returns the side data the import is given
	}{
		{"the stored data was deleted", func(t *testing.T, side *SideData) *SideData {
			if err := side.Delete(svcRun); err != nil {
				t.Fatal(err)
			}
			return side
		}},
		{"model.json is not JSON", func(t *testing.T, side *SideData) *SideData {
			if err := side.Put(svcRun, SideModel, []byte("{not json")); err != nil {
				t.Fatal(err)
			}
			return side
		}},
		{"model.json is the record of another run", func(t *testing.T, side *SideData) *SideData {
			rec := storedRecord(t, side)
			rec.RunID = "ffffffffffffffff"
			putRecord(t, side, rec)
			return side
		}},
		{"the record holds no model and was not left out", func(t *testing.T, side *SideData) *SideData {
			rec := storedRecord(t, side)
			rec.Result.TM, rec.Truncated = nil, false
			putRecord(t, side, rec)
			return side
		}},
		{"the node keeps no side data", func(*testing.T, *SideData) *SideData { return NewSideData("") }},
		{"no side data was given", func(*testing.T, *SideData) *SideData { return nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, side, run := modelImportFixture(t, svcThreatModel)
			given := tc.edit(t, side)
			seam := &recordingSeam{}
			rec, err := RunImport(context.Background(), modelImportInput(root, given, run, seam, DeriveSettings{}))
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if rec.Outcome != string(secassess.ImportFailed) || rec.Reason != wantReason || ReasonModelUnavailable != wantReason {
				t.Fatalf("record = %+v", rec)
			}
			if rec.Reason == ReasonModelTooLarge {
				t.Errorf("a lost copy reads as too large to keep")
			}
			if seam.calls != 0 || rec.Derived != nil {
				t.Errorf("something was imported: calls %d, record %+v", seam.calls, rec)
			}
		})
	}
}
