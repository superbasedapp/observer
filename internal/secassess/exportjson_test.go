package secassess

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// exDecode reads an export back into the envelope and checks it is valid JSON.
func exDecode(t *testing.T, b []byte) ExportDoc {
	t.Helper()
	if !json.Valid(b) {
		t.Fatalf("the export is not valid JSON: %s", b)
	}
	var doc ExportDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// exKeys is the top-level keys of an export.
func exKeys(t *testing.T, b []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestRenderExportJSONThreatModel: the envelope says what it is, and the model
// in it decodes back to exactly the checked model.
func TestRenderExportJSONThreatModel(t *testing.T) {
	res := exTM(t, nil)
	meta := exMeta(ThreatModel)
	meta.Anyway = true
	b, err := RenderExportJSON(meta, res)
	if err != nil {
		t.Fatal(err)
	}
	doc := exDecode(t, b)
	if doc.Schema != ExportSchema || ExportSchema != "observer.assessment-export.v1" {
		t.Errorf("schema = %q", doc.Schema)
	}
	if doc.Note != exportNote || !strings.Contains(doc.Note, "not the agent's file as written") {
		t.Errorf("note = %q", doc.Note)
	}
	if doc.RunID != modelRun || doc.Kind != ThreatModel || doc.Contract != ContractThreatModel || !doc.Anyway || doc.SourceSHA != "a1b2c3d4e5f60718" {
		t.Errorf("envelope = %+v", doc)
	}
	if !doc.ValidatedAt.Equal(meta.ValidatedAt) || doc.ValidatedAt.Location() != time.UTC {
		t.Errorf("validated_at = %v, want %v in UTC", doc.ValidatedAt, meta.ValidatedAt)
	}
	if doc.Redaction != (ExportRedaction{On: true, Hidden: 2}) {
		t.Errorf("redaction = %+v", doc.Redaction)
	}
	// The report comes back as it went in (compared as JSON, which is what the
	// page and the files carry).
	wantRep, _ := json.Marshal(res.Report)
	gotRep, _ := json.Marshal(doc.Validation)
	if string(wantRep) != string(gotRep) {
		t.Errorf("the validation report changed:\n got %s\nwant %s", gotRep, wantRep)
	}
	var tm ThreatModelDoc
	if err := json.Unmarshal(doc.Model, &tm); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&tm, res.TM) {
		t.Errorf("the model decoded from the export differs from the checked model:\n got %+v\nwant %+v", tm, *res.TM)
	}
	want := []string{"anyway", "contract", "kind", "model", "note", "redaction", "run_id", "schema", "source_sha", "validated_at", "validation"}
	if got := exKeys(t, b); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("keys = %v, want %v", got, want)
	}
}

// TestRenderExportJSONPenTest: the same for a pen test.
func TestRenderExportJSONPenTest(t *testing.T) {
	res := exPT(t, nil)
	b, err := RenderExportJSON(exMeta(RedTeamLocal), res)
	if err != nil {
		t.Fatal(err)
	}
	doc := exDecode(t, b)
	if doc.Kind != RedTeamLocal || doc.Contract != ContractPentest || doc.Anyway {
		t.Errorf("envelope = %+v", doc)
	}
	var pt PentestDoc
	if err := json.Unmarshal(doc.Model, &pt); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&pt, res.PT) {
		t.Errorf("the model decoded from the export differs from the checked model:\n got %+v\nwant %+v", pt, *res.PT)
	}
}

// TestRenderExportJSONIsTheCopiedModel: the model in the envelope is exactly
// what the page's "Copy checked model" copies (the checked model, indented), so
// the two exports of one model agree.
func TestRenderExportJSONIsTheCopiedModel(t *testing.T) {
	res := exTM(t, nil)
	b, err := RenderExportJSON(exMeta(ThreatModel), res)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := json.MarshalIndent(res.TM, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Model json.RawMessage `json:"model"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	var a, c any
	if err := json.Unmarshal(env.Model, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(copied, &c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, c) {
		t.Error("the model in the export is not the model the page copies")
	}
}

// TestRenderExportJSONLayout: two-space indentation, one key per line, and the
// same bytes every time.
func TestRenderExportJSONLayout(t *testing.T) {
	res := exTM(t, nil)
	b, _ := RenderExportJSON(exMeta(ThreatModel), res)
	if !strings.HasPrefix(string(b), "{\n  \"schema\": \"observer.assessment-export.v1\",\n  \"note\": ") {
		t.Errorf("the export starts %q", string(b[:min(len(b), 90)]))
	}
	if !strings.Contains(string(b), "\n      \"") || strings.Contains(string(b), "\t") {
		t.Error("the export is not indented with spaces")
	}
	again, _ := RenderExportJSON(exMeta(ThreatModel), res)
	if string(b) != string(again) {
		t.Error("two renders of one result differ")
	}
}

// TestRenderExportJSONHTMLEscaping: markup characters in the agent's text come
// out as JSON escapes, and nowhere in the export is a raw angle bracket or
// ampersand.
func TestRenderExportJSONHTMLEscaping(t *testing.T) {
	res := exTM(t, nil)
	res.TM.Summary = "<script>alert(1)</script> & more"
	res.Report.Issues = append(res.Report.Issues, Issue{Row: "V1", Code: "x", Severity: SevWarn, Message: "a <b> & c"})
	b, err := RenderExportJSON(exMeta(ThreatModel), res)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{exBackslash + "u003cscript" + exBackslash + "u003ealert(1)" + exBackslash + "u003c/script" + exBackslash + "u003e " + exBackslash + "u0026 more", "a " + exBackslash + "u003cb" + exBackslash + "u003e " + exBackslash + "u0026 c"} {
		if !strings.Contains(s, want) {
			t.Errorf("the export lacks %q", want)
		}
	}
	if strings.ContainsAny(s, "<>&") {
		t.Error("the export holds a raw angle bracket or ampersand")
	}
	var doc ExportDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	var tm ThreatModelDoc
	if err := json.Unmarshal(doc.Model, &tm); err != nil || tm.Summary != res.TM.Summary {
		t.Errorf("the summary does not read back: %q, %v", tm.Summary, err)
	}
}

// TestRenderExportJSONOmissions is the table of fields that are left out when
// they are not valid, and written when they are.
func TestRenderExportJSONOmissions(t *testing.T) {
	tests := []struct {
		name   string
		meta   func(m *ExportMeta)
		absent []string
		equals map[string]string
	}{
		{"valid values are written", func(m *ExportMeta) {}, nil, map[string]string{"run_id": modelRun, "source_sha": "a1b2c3d4e5f60718", "kind": "threat_model"}},
		{"a run id that is not one", func(m *ExportMeta) { m.RunID = "../etc" }, []string{"run_id"}, nil},
		{"a run id in capitals", func(m *ExportMeta) { m.RunID = strings.ToUpper(modelRun) }, []string{"run_id"}, nil},
		{"no run id", func(m *ExportMeta) { m.RunID = "" }, []string{"run_id"}, nil},
		{"a fingerprint that is not hex", func(m *ExportMeta) { m.SourceSHA = "xyz" }, []string{"source_sha"}, nil},
		{"a fingerprint in capitals", func(m *ExportMeta) { m.SourceSHA = "ABCD" }, []string{"source_sha"}, nil},
		{"a fingerprint that is too long", func(m *ExportMeta) { m.SourceSHA = "a1b2c3d4e5f607189" }, []string{"source_sha"}, nil},
		{"a fingerprint with markup", func(m *ExportMeta) { m.SourceSHA = "<b>" }, []string{"source_sha"}, nil},
		{"no fingerprint", func(m *ExportMeta) { m.SourceSHA = "" }, []string{"source_sha"}, nil},
		{"a kind the table does not know", func(m *ExportMeta) { m.Kind = "made_up" }, []string{"kind"}, nil},
		{"no kind", func(m *ExportMeta) { m.Kind = "" }, []string{"kind"}, nil},
		{"no time", func(m *ExportMeta) { m.ValidatedAt = time.Time{} }, []string{"validated_at"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := exMeta(ThreatModel)
			tc.meta(&m)
			b, err := RenderExportJSON(m, exTM(t, nil))
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(b, &raw); err != nil {
				t.Fatal(err)
			}
			for _, k := range tc.absent {
				if _, ok := raw[k]; ok {
					t.Errorf("%q is in the export: %v", k, raw[k])
				}
			}
			for k, want := range tc.equals {
				if raw[k] != want {
					t.Errorf("%q = %v, want %q", k, raw[k], want)
				}
			}
			// The fields that are always there stay there.
			for _, k := range []string{"schema", "note", "anyway", "redaction", "validation", "contract"} {
				if _, ok := raw[k]; !ok {
					t.Errorf("%q is not in the export", k)
				}
			}
		})
	}
}

// TestRenderExportJSONWithoutAModel: a result that kept only its report, a
// refused file and an empty result have no model key and still decode.
func TestRenderExportJSONWithoutAModel(t *testing.T) {
	results := map[string]Result{
		"a stored report only": rdStoredTM(&TMCoverage{Analysed: 1}, map[string]Count{"threats": {Read: 1, Kept: 1}}),
		"a refused file":       Validate([]byte("{nope"), optsFor(ContractThreatModel)),
		"nothing":              {},
	}
	for name, res := range results {
		t.Run(name, func(t *testing.T) {
			b, err := RenderExportJSON(exMeta(ThreatModel), res)
			if err != nil {
				t.Fatal(err)
			}
			doc := exDecode(t, b)
			if doc.Model != nil {
				t.Errorf("model = %s", doc.Model)
			}
			for _, k := range exKeys(t, b) {
				if k == "model" {
					t.Error("the export has a model key")
				}
			}
		})
	}
	// A result with no contract in its report reads the contract of its model.
	res := exTM(t, nil)
	res.Report.Contract = ""
	doc := exDecode(t, mustExport(t, exMeta(ThreatModel), res))
	if doc.Contract != ContractThreatModel {
		t.Errorf("contract = %q", doc.Contract)
	}
}

// mustExport renders the JSON export or fails.
func mustExport(t *testing.T, m ExportMeta, res Result) []byte {
	t.Helper()
	b, err := RenderExportJSON(m, res)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRenderExportJSONBothModels: a result that holds both writes the threat
// model, as the page's copy does.
func TestRenderExportJSONBothModels(t *testing.T) {
	res := exTM(t, nil)
	res.PT = exPT(t, nil).PT
	doc := exDecode(t, mustExport(t, exMeta(ThreatModel), res))
	var probe struct {
		Schema string `json:"schema"`
	}
	if err := json.Unmarshal(doc.Model, &probe); err != nil || probe.Schema != SchemaThreatModel {
		t.Errorf("the model is %q (%v), want the threat model", probe.Schema, err)
	}
}

// TestRenderExportJSONKeepsEverything: a model of 1,500 threats and the hostile
// model round trip in full, the second through every kind of character the
// agent can put in a string.
func TestRenderExportJSONKeepsEverything(t *testing.T) {
	tm := &ThreatModelDoc{}
	for i := 0; i < 1500; i++ {
		tm.Threats = append(tm.Threats, Threat{ID: "T-" + mdInt(i), Rating: Rating{Likelihood: 1 + i%5, Impact: 1 + i%4}})
	}
	doc := exDecode(t, mustExport(t, exMeta(ThreatModel), Result{TM: tm, Report: Report{State: ValidationValid, Contract: ContractThreatModel}}))
	var back ThreatModelDoc
	if err := json.Unmarshal(doc.Model, &back); err != nil || len(back.Threats) != 1500 {
		t.Fatalf("%d threats read back (%v)", len(back.Threats), err)
	}
	hostile, _ := exHostileResult(t)
	b := mustExport(t, exMeta(ThreatModel), hostile)
	if strings.ContainsAny(string(b), "<>&") {
		t.Error("the hostile export holds a raw angle bracket or ampersand")
	}
	doc = exDecode(t, b)
	var tm2 ThreatModelDoc
	if err := json.Unmarshal(doc.Model, &tm2); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&tm2, hostile.TM) {
		t.Error("the hostile model does not read back as it went in")
	}
}

// TestRenderExportJSONWording: the note never says a result is clean or passed.
func TestRenderExportJSONWording(t *testing.T) {
	if m := rdBannedPattern(t).FindString(exportNote); m != "" {
		t.Errorf("the note uses %q", m)
	}
}
