//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// Tests of what the model and report routes add for the model view (depth plan
// W5a and W6a): the reading and diagram computed from the stored copy, the
// vocabulary, redaction on the way out, the comparison with an earlier run, and
// the diagram size setting. The harness is the model routes' own
// (security_assess_model_test.go).

// A secret in a form the scrubber knows (the AWS documentation's example key).
const viewTestSecret = "AKIAIOSFODNN7EXAMPLE"

const viewTestOtherRun = "fedcba9876543210"

// viewRun records a second started run of the same project, ended, under a
// contract and kind, created an hour after the harness's own run (the later
// run, the one a comparison is made from).
func viewRun(t *testing.T, h *relaxHarness, id, kind string, contract secassess.Contract) {
	t.Helper()
	viewRunAt(t, h, id, kind, contract, time.Now().Add(time.Hour))
}

// viewRunAt is viewRun with the time the run was created.
func viewRunAt(t *testing.T, h *relaxHarness, id, kind string, contract secassess.Contract, created time.Time) {
	t.Helper()
	run := secassesssvc.Run{
		ID: id, Kind: kind, Tool: "claude-code", ProjectRootHash: h.hash, ProjectName: "api", Handle: "H-" + id[:4], Seeded: true,
		Contract: string(contract), Phase: secassesssvc.PhaseStarted, TimeBoxMinutes: 60, Audit: string(secassess.AuditOff),
		EndedAt: time.Now().Add(-5 * time.Minute).UTC(), CreatedAt: created.UTC(),
	}
	if _, err := h.runs.Record(run, time.Now()); err != nil {
		t.Fatal(err)
	}
}

// validateWith writes body as the run's assessment.json (run id substituted)
// and validates it through the route.
func (h *relaxHarness) validateWith(id, body string) {
	h.t.Helper()
	writeModelTestFile(h.t, h.root, secassess.ResultPaths(id).Model, strings.ReplaceAll(body, modelTestRun, id))
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		h.t.Fatalf("validate %s: %d %s", id, w.Code, w.Body)
	}
}

// TestSecurityAssessModelAnswerCarriesTheReadingDiagramAndVocabulary: the answer
// holds the coverage line, the diagram source (a threat model), the vocabulary
// and the redaction state; a model with a threat has no reading.
func TestSecurityAssessModelAnswerCarriesTheReadingDiagramAndVocabulary(t *testing.T) {
	h, id := modelHarness(t, true)
	h.validateWith(id, modelTestThreatModel)
	code, out := h.model(id)
	if code != http.StatusOK {
		t.Fatalf("model: %d", code)
	}
	if out.Reading != "" {
		t.Errorf("a model with a threat has a reading: %q", out.Reading)
	}
	if !strings.HasPrefix(out.CoverageLine, "Covered by the agent: ") {
		t.Errorf("coverage line = %q", out.CoverageLine)
	}
	if out.Mermaid == nil || !strings.HasPrefix(out.Mermaid.Source, "flowchart LR") || out.Mermaid.Nodes != 3 || out.Mermaid.MaxNodes != 60 {
		t.Errorf("diagram = %+v", out.Mermaid)
	}
	if len(out.Vocab.Stride) != 6 || len(out.Vocab.WSTG) != 12 || len(out.Vocab.Bands) != 4 {
		t.Errorf("vocabulary = %+v", out.Vocab)
	}
	if !out.Redaction.On {
		t.Errorf("redaction is off by default: %+v", out.Redaction)
	}
}

// TestSecurityAssessModelWithNoThreatIsNotAClearance: a valid model with no
// threat reads as what was and was not covered, never as an empty good result.
func TestSecurityAssessModelWithNoThreatIsNotAClearance(t *testing.T) {
	h, id := modelHarness(t, true)
	empty := `{"schema":"observer.threatmodel.v1","run_id":"` + modelTestRun + `","generator":{"tool":"claude-code"},
 "system":{"components":[{"id":"api","name":"API","type":"service"}]},"threats":[]}`
	h.validateWith(id, empty)
	_, out := h.model(id)
	if !strings.Contains(out.Reading, "not proof that none exists") || !strings.HasPrefix(out.Reading, "No threat was recorded") {
		t.Fatalf("reading = %q", out.Reading)
	}
	for _, bad := range []string{"clean", "secure", "verified", "confirmed", "passed"} {
		if strings.Contains(strings.ToLower(out.Reading+out.CoverageLine), bad) {
			t.Errorf("the words say %q: %q %q", bad, out.Reading, out.CoverageLine)
		}
	}
}

// TestSecurityAssessPenTestModelAnswerAndComparisonRefusal: a pen test whose
// target did not start reads as nothing tested in a running application, has
// no diagram, and cannot be compared with another run.
func TestSecurityAssessPenTestModelAnswerAndComparisonRefusal(t *testing.T) {
	h, _ := modelHarness(t, true)
	viewRun(t, h, viewTestOtherRun, "pentest_local", secassess.ContractPentest)
	body := `{"schema":"observer.pentest.v1","run_id":"` + modelTestRun + `","generator":{"tool":"claude-code"},
 "target":{"url":"http://localhost:3000/","start":{"started":false,"health":{}}},"method":{"standard":"wstg+ptes"},
 "coverage":[{"category":"INFO","status":"tested"}],"findings":[]}`
	h.validateWith(viewTestOtherRun, body)
	code, out := h.model(viewTestOtherRun)
	if code != http.StatusOK || out.Mermaid != nil {
		t.Fatalf("pen test model: %d %+v", code, out.Mermaid)
	}
	if !strings.HasPrefix(out.Reading, "The target was not started") || !strings.Contains(out.Reading, "not proof that none exists") {
		t.Fatalf("reading = %q", out.Reading)
	}
	if code, _ := h.modelSince(viewTestOtherRun, modelTestRun); code != http.StatusConflict {
		t.Fatalf("comparing a pen test: %d", code)
	}
}

func (h *relaxHarness) modelSince(id, since string) (int, map[string]any) {
	h.t.Helper()
	w := httptest.NewRecorder()
	h.s.handleSecurityAssessModel(w, httptest.NewRequest(http.MethodGet, "/api/security/assessments/model?run="+id+"&since="+since, nil))
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// TestSecurityAssessModelRedactsOnTheWayOut: the stored copy is cleaned when it
// is written; the answer is cleaned again with the redactor in force, so a
// secret that is in a stored copy (a pattern added since) is hidden when it is
// shown, and the count says how many places. With display_redaction off the
// stored text is shown as it is and the answer says redaction is off.
func TestSecurityAssessModelRedactsOnTheWayOut(t *testing.T) {
	h, id := modelHarness(t, true)
	h.validateWith(id, modelTestThreatModel)
	side := h.runs.Side()
	rec, ok := secassesssvc.ReadModel(side, id)
	if !ok || rec.Result.TM == nil {
		t.Fatal("no stored model")
	}
	rec.Result.TM.Summary = "The key " + viewTestSecret + " is in the config."
	rec.Result.TM.Threats[0].Title = "Leak of " + viewTestSecret
	rec.Result.Report.IgnoredKeys = []string{"extra " + viewTestSecret}
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := side.Put(id, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}

	_, out := h.model(id)
	shown, _ := json.Marshal(out)
	if strings.Contains(string(shown), viewTestSecret) {
		t.Fatalf("a secret reached the answer: %s", shown)
	}
	if !out.Redaction.On || out.Redaction.Hidden != 3 {
		t.Errorf("redaction = %+v, want on with 3 places hidden", out.Redaction)
	}

	h.setConfig("display_redaction = false\n")
	_, out = h.model(id)
	if out.Redaction.On || out.Redaction.Hidden != 0 || !strings.Contains(out.Record.Result.TM.Summary, viewTestSecret) {
		t.Errorf("with redaction off: %+v, summary %q", out.Redaction, out.Record.Result.TM.Summary)
	}
}

// TestSecurityAssessStoredModelIsRedactedAtWriteTime: what Observer keeps
// beside the run record is redacted when it is written, whatever
// display_redaction says; the agent's own file in the project is not touched.
func TestSecurityAssessStoredModelIsRedactedAtWriteTime(t *testing.T) {
	h, id := modelHarness(t, true)
	h.setConfig("display_redaction = false\n")
	body := strings.Replace(modelTestThreatModel, `"summary":"A small web service."`, `"summary":"The key `+viewTestSecret+` leaked."`, 1)
	h.validateWith(id, body)
	stored, ok := h.runs.Side().Get(id, secassesssvc.SideModel)
	if !ok {
		t.Fatal("no stored model")
	}
	if strings.Contains(string(stored), viewTestSecret) {
		t.Fatalf("the stored copy holds the secret: %s", stored)
	}
	onDisk, err := os.ReadFile(h.root + "/" + secassess.ResultPaths(id).Model)
	if err != nil || !strings.Contains(string(onDisk), viewTestSecret) {
		t.Fatalf("the agent's file was touched (err %v)", err)
	}
}

// TestSecurityAssessReportIsRedactedOnTheWayOut: the report is served with the
// secrets Observer recognises hidden and the count in a header; with
// display_redaction off it is served as written and the header is absent. The
// file in the project is never changed.
func TestSecurityAssessReportIsRedactedOnTheWayOut(t *testing.T) {
	h, id := modelHarness(t, true)
	report := "# Report\n\nFound key " + viewTestSecret + " in the settings.\nAnd again " + viewTestSecret + ".\n"
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Report, report)
	get := func() *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.s.handleSecurityAssessReport(w, httptest.NewRequest(http.MethodGet, "/api/security/assessments/report?run="+id, nil))
		return w
	}
	w := get()
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), viewTestSecret) {
		t.Fatalf("report: %d %q", w.Code, w.Body)
	}
	if got := w.Header().Get(redactedHeader); got != "2" {
		t.Errorf("%s = %q, want 2", redactedHeader, got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("headers: %v", w.Header())
	}
	h.setConfig("display_redaction = false\n")
	w = get()
	if w.Body.String() != report || w.Header().Get(redactedHeader) != "" {
		t.Errorf("with redaction off: %q header %q", w.Body, w.Header().Get(redactedHeader))
	}
	if onDisk, _ := os.ReadFile(h.root + "/" + secassess.ResultPaths(id).Report); string(onDisk) != report {
		t.Error("the report file in the project was changed")
	}
}

// TestSecurityAssessDiagramNodesSetting: the diagram is drawn under the cap the
// setting names, and the answer says which cap was in force.
func TestSecurityAssessDiagramNodesSetting(t *testing.T) {
	h, id := modelHarness(t, true)
	h.setConfig("diagram_max_nodes = 100\n")
	h.validateWith(id, modelTestThreatModel)
	if _, out := h.model(id); out.Mermaid == nil || out.Mermaid.MaxNodes != 100 {
		t.Fatalf("diagram = %+v", out.Mermaid)
	}
}

// secondTM is a later threat model of the same project: T-1 is rated higher and
// there is one more threat.
func secondTM() string {
	s := strings.Replace(modelTestThreatModel, `"rating":{"likelihood":4,"impact":4}`, `"rating":{"likelihood":5,"impact":5}`, 1)
	return strings.Replace(s, `"threats":[`, `"threats":[
  {"id":"T-2","title":"Session fixation","framework":"stride","category":"tampering","element":{"kind":"component","id":"db"},"rating":{"likelihood":2,"impact":2},"status":"identified"},`, 1)
}

// TestSecurityAssessModelSinceComparesTwoRuns: since= names an earlier run of
// the same project and kind; the answer carries Observer's comparison made from
// the two stored copies, and a refused comparison says why in a closed code.
func TestSecurityAssessModelSinceComparesTwoRuns(t *testing.T) {
	h, id := modelHarness(t, true)
	viewRun(t, h, viewTestOtherRun, "threat_model", secassess.ContractThreatModel)
	h.validateWith(id, modelTestThreatModel)
	h.validateWith(viewTestOtherRun, secondTM())

	code, raw := h.modelSince(viewTestOtherRun, id)
	if code != http.StatusOK {
		t.Fatalf("since: %d %v", code, raw)
	}
	since, _ := raw["since"].(map[string]any)
	if since == nil || since["prev_run"] != id {
		t.Fatalf("since = %v", raw["since"])
	}
	if added, _ := since["added"].([]any); len(added) != 1 {
		t.Errorf("added = %v", since["added"])
	}
	if changed, _ := since["changed"].([]any); len(changed) != 1 {
		t.Errorf("changed = %v", since["changed"])
	}
	if note, _ := since["note"].(string); !strings.Contains(note, "does not say which is right") {
		t.Errorf("note = %q", note)
	}

	refusals := []struct {
		name, run, since, code string
	}{
		{"itself", viewTestOtherRun, viewTestOtherRun, codeSinceUnknown},
		{"an unknown run", viewTestOtherRun, "0000000000000000", codeSinceUnknown},
		// The comparison reads "what changed since": a run started after this one
		// is not "since", so it is refused rather than shown backwards.
		{"a later run", id, viewTestOtherRun, codeSinceLater},
	}
	for _, rf := range refusals {
		t.Run(rf.name, func(t *testing.T) {
			c, body := h.modelSince(rf.run, rf.since)
			if c != http.StatusConflict || body["code"] != rf.code {
				t.Fatalf("%d %v", c, body)
			}
		})
	}

	// A run of another kind, and an earlier run whose model is gone.
	viewRunAt(t, h, "1111111111111111", "pentest_local", secassess.ContractPentest, time.Now().Add(-time.Hour))
	if c, body := h.modelSince(viewTestOtherRun, "1111111111111111"); c != http.StatusConflict || body["code"] != codeSinceMismatch {
		t.Errorf("another kind: %d %v", c, body)
	}
	viewRunAt(t, h, "2222222222222222", "threat_model", secassess.ContractThreatModel, time.Now().Add(-time.Hour))
	if c, body := h.modelSince(viewTestOtherRun, "2222222222222222"); c != http.StatusConflict || body["code"] != codeSinceNoModel {
		t.Errorf("no stored model: %d %v", c, body)
	}
}

// TestSecurityAssessModelSinceRedactsTheComparison: the titles in a comparison
// pass the redactor too.
func TestSecurityAssessModelSinceRedactsTheComparison(t *testing.T) {
	h, id := modelHarness(t, true)
	viewRun(t, h, viewTestOtherRun, "threat_model", secassess.ContractThreatModel)
	h.validateWith(id, modelTestThreatModel)
	h.validateWith(viewTestOtherRun, secondTM())
	side := h.runs.Side()
	rec, _ := secassesssvc.ReadModel(side, viewTestOtherRun)
	rec.Result.TM.Threats[0].Title = "Leak of " + viewTestSecret
	blob, _ := json.Marshal(rec)
	if err := side.Put(viewTestOtherRun, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.s.handleSecurityAssessModel(w, httptest.NewRequest(http.MethodGet, "/api/security/assessments/model?run="+viewTestOtherRun+"&since="+id, nil))
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), viewTestSecret) {
		t.Fatalf("since answer: %d %s", w.Code, w.Body)
	}
}

// TestSecurityAssessModelRedactsTheStoredComparison: a threat model checked with
// an earlier run chosen keeps the comparison in its stored copy (record.diff).
// That copy is built from two models redacted at write time, but the display
// pass runs again with the redactor in force now, so the stored comparison is
// redacted on the way out like the model beside it; with the setting off it is
// shown as stored.
func TestSecurityAssessModelRedactsTheStoredComparison(t *testing.T) {
	h, id := modelHarness(t, true)
	h.validateWith(id, modelTestThreatModel)
	side := h.runs.Side()
	rec, ok := secassesssvc.ReadModel(side, id)
	if !ok {
		t.Fatal("no stored model")
	}
	rec.Compared, rec.CompareState = viewTestOtherRun, secassesssvc.CompareOK
	rec.Diff = &secassess.ModelDiff{
		PrevRun: viewTestOtherRun,
		Added:   []secassess.DiffItem{{ID: "T-9", Title: "Leak of " + viewTestSecret, Category: "I"}},
		System:  secassess.SystemDiff{Components: secassess.NameDiff{Added: []string{"vault " + viewTestSecret}}},
		Note:    secassess.DiffNote,
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := side.Put(id, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}

	_, out := h.model(id)
	shown, _ := json.Marshal(out)
	if strings.Contains(string(shown), viewTestSecret) {
		t.Fatalf("a secret in the stored comparison reached the answer: %s", shown)
	}
	if out.Record.Diff == nil || out.Record.Diff.Added[0].ID != "T-9" || out.Record.Diff.Note != secassess.DiffNote || out.Record.Diff.PrevRun != viewTestOtherRun {
		t.Fatalf("the redacted comparison lost its keys or its note: %+v", out.Record.Diff)
	}
	if !out.Redaction.On || out.Redaction.Hidden != 2 {
		t.Errorf("redaction = %+v, want on with the 2 places of the comparison hidden", out.Redaction)
	}

	h.setConfig("display_redaction = false\n")
	_, out = h.model(id)
	if out.Redaction.On || out.Record.Diff == nil || !strings.Contains(out.Record.Diff.Added[0].Title, viewTestSecret) {
		t.Errorf("with redaction off the stored comparison is shown as stored: %+v", out.Record.Diff)
	}
}

// TestSecurityAssessRunRowSaysWhetherAModelIsStored: has_model is true only
// while the checked copy is on disk; a deleted copy leaves the validation on
// the row but there is nothing to open.
func TestSecurityAssessRunRowSaysWhetherAModelIsStored(t *testing.T) {
	h, id := modelHarness(t, true)
	view := func() securityAssessRunJS {
		run, ok := h.runs.Get(id)
		if !ok {
			t.Fatal("the run is gone")
		}
		return h.s.securityAssessRunViewFull(context.Background(), run, h.root)
	}
	if view().HasModel {
		t.Fatal("a run with no validation reads as having a model")
	}
	h.validateWith(id, modelTestThreatModel)
	if js := view(); !js.HasModel || js.Validation == nil {
		t.Fatalf("a validated run: has_model %v, validation %v", js.HasModel, js.Validation)
	}
	if err := h.runs.Side().Delete(id); err != nil {
		t.Fatal(err)
	}
	if js := view(); js.HasModel || js.Validation == nil {
		t.Fatalf("after Delete evidence: has_model %v, validation %v (the validation stays, the copy is gone)", js.HasModel, js.Validation)
	}
}

// viewKebabModel has two components whose ids share a long kebab-case run that
// the secret scrubber's key-prefix pattern matches inside ("sk-" and sixteen id
// characters, with no word boundary): after a redaction of the ids both would
// read the same. The names and a quoted line carry the same words as text.
const viewKebabModel = `{
 "schema":"observer.threatmodel.v1","run_id":"0123456789abcdef","prompt_version":"tm.2",
 "generator":{"tool":"claude-code","model":"m"},
 "summary":"A queue service.",
 "scope":{"in_scope":["cmd/api"]},
 "system":{
  "components":[
   {"id":"task-queue-worker-alpha-one","name":"Worker task-queue-worker-alpha-one","type":"service","zone":"task-queue-worker-zone","paths":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},
   {"id":"task-queue-worker-alpha-two","name":"Worker two","type":"service","zone":"task-queue-worker-zone"},
   {"id":"db","name":"Database","type":"datastore"}
  ],
  "zones":[{"id":"task-queue-worker-zone","name":"Workers"}],
  "actors":[],
  "flows":[
   {"id":"f1","from":"task-queue-worker-alpha-one","to":"db","protocol":"sql","encrypted":"yes","authn":"mtls"},
   {"id":"f2","from":"task-queue-worker-alpha-two","to":"db","protocol":"sql","encrypted":"yes","authn":"mtls"}]},
 "threats":[
  {"id":"T-task-queue-worker-1","title":"Replay on task-queue-worker-alpha-one","framework":"stride","category":"tampering","element":{"kind":"component","id":"task-queue-worker-alpha-one"},"rating":{"likelihood":3,"impact":3},"status":"identified"},
  {"id":"T-task-queue-worker-2","title":"Replay on the second worker","framework":"stride","category":"tampering","element":{"kind":"component","id":"task-queue-worker-alpha-two"},"rating":{"likelihood":3,"impact":3},"status":"identified"}
 ]
}`

// TestSecurityAssessDisplayRedactionKeepsKeysAndHidesText: with hiding on, two
// ids that the scrubber's key-prefix pattern would collapse stay two ids, the
// references to them (a flow end, an element, a zone) still point at the right
// item, the diagram joins the right boxes and the file path is as written; the
// text that names them (a component name, a threat title) is hidden.
func TestSecurityAssessDisplayRedactionKeepsKeysAndHidesText(t *testing.T) {
	h, id := modelHarness(t, true)
	h.validateWith(id, viewKebabModel)
	_, out := h.model(id)
	tm := out.Record.Result.TM
	if tm == nil {
		t.Fatalf("no model: %+v", out.Record.Result.Report)
	}
	if !out.Redaction.On {
		t.Fatal("display redaction is off by default")
	}
	const one, two = "task-queue-worker-alpha-one", "task-queue-worker-alpha-two"
	if tm.System.Components[0].ID != one || tm.System.Components[1].ID != two || tm.System.Components[0].Zone != "task-queue-worker-zone" {
		t.Errorf("component ids = %q %q zone %q", tm.System.Components[0].ID, tm.System.Components[1].ID, tm.System.Components[0].Zone)
	}
	if f := tm.System.Flows; f[0].From != one || f[1].From != two {
		t.Errorf("flow ends = %q %q", f[0].From, f[1].From)
	}
	if th := tm.Threats; th[0].Element.ID != one || th[1].Element.ID != two || th[0].ID == th[1].ID {
		t.Errorf("threats = %+v %+v", th[0].Element, th[1].Element)
	}
	if got := tm.System.Components[0].Paths[0].Path; got != "cmd/api/main.go" {
		t.Errorf("path = %q", got)
	}
	if strings.Contains(tm.System.Components[0].Name, one) || strings.Contains(tm.Threats[0].Title, one) {
		t.Errorf("the key-shaped text was not hidden: name %q title %q", tm.System.Components[0].Name, tm.Threats[0].Title)
	}
	if out.Redaction.Hidden < 2 {
		t.Errorf("hidden = %d, want the name and the title at least", out.Redaction.Hidden)
	}
	d := out.Mermaid
	if d == nil || d.Edges != 2 || d.OmittedEdges != 0 || !strings.Contains(d.Source, `c1 -->|"sql"| c3`) || !strings.Contains(d.Source, `c2 -->|"sql"| c3`) {
		t.Fatalf("the diagram does not join the two workers to the database: %+v", d)
	}
}

// TestSecurityAssessRedactionHonoursExtraPatterns: the developer's own
// [observer.secrets] extra_patterns hide text in the model as shown and in the
// copy Observer keeps, like every other seam that scrubs.
func TestSecurityAssessRedactionHonoursExtraPatterns(t *testing.T) {
	h, id := modelHarness(t, true)
	cfg := "[guard]\nenabled = true\nmode = \"enforce\"\n\n[observer.secrets]\nextra_patterns = [\"ACME-TOKEN-[0-9]{6}\"]\n\n[security.assessments]\n"
	if err := os.WriteFile(h.s.opts.ConfigPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	const internal = "ACME-TOKEN-123456"
	body := strings.Replace(modelTestThreatModel, `"summary":"A small web service."`, `"summary":"Calls use `+internal+` as a header."`, 1)
	h.validateWith(id, body)
	stored, _ := h.runs.Side().Get(id, secassesssvc.SideModel)
	if strings.Contains(string(stored), internal) {
		t.Fatalf("the stored copy holds the pattern's match: %s", stored)
	}
	// A stored copy written before the pattern existed is hidden when shown.
	rec, _ := secassesssvc.ReadModel(h.runs.Side(), id)
	rec.Result.TM.Summary = "Late: " + internal
	blob, _ := json.Marshal(rec)
	if err := h.runs.Side().Put(id, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}
	_, out := h.model(id)
	shown, _ := json.Marshal(out)
	if strings.Contains(string(shown), internal) || out.Redaction.Hidden < 1 {
		t.Fatalf("the model shows the pattern's match: hidden %d: %s", out.Redaction.Hidden, shown)
	}
	// And the report route.
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Report, "token "+internal+" here\n")
	w := httptest.NewRecorder()
	h.s.handleSecurityAssessReport(w, httptest.NewRequest(http.MethodGet, "/api/security/assessments/report?run="+id, nil))
	if strings.Contains(w.Body.String(), internal) || w.Header().Get(redactedHeader) != "1" {
		t.Errorf("report: %q header %q", w.Body, w.Header().Get(redactedHeader))
	}
}

// TestSecurityAssessDisplayCache: a display copy is built once per stored copy
// and redactor, a different redactor or stored copy is a different entry, an
// entry over the budget is not kept, the cache is bounded, and what it returns
// is what the build returned.
func TestSecurityAssessDisplayCache(t *testing.T) {
	var c displayCache
	builds := 0
	build := func() (secassess.Result, int) {
		builds++
		return secassess.Result{Report: secassess.Report{State: secassess.ValidationValid}}, builds
	}
	key := displayKey{side: "db", run: "r1", validated: 1, source: "s", redactor: "on:0:x"}
	if _, n := c.get(key, 100, build); n != 1 {
		t.Fatalf("first get = %d", n)
	}
	if _, n := c.get(key, 100, build); n != 1 || builds != 1 {
		t.Errorf("second get = %d after %d builds: the copy was not reused", n, builds)
	}
	for name, k := range map[string]displayKey{
		"another redactor":   {side: "db", run: "r1", validated: 1, source: "s", redactor: "on:1:y"},
		"another validation": {side: "db", run: "r1", validated: 2, source: "s", redactor: "on:0:x"},
		"another file":       {side: "db", run: "r1", validated: 1, source: "t", redactor: "on:0:x"},
		"another run":        {side: "db", run: "r2", validated: 1, source: "s", redactor: "on:0:x"},
		"another node":       {side: "other", run: "r1", validated: 1, source: "s", redactor: "on:0:x"},
	} {
		before := builds
		c.get(k, 100, build)
		if builds != before+1 {
			t.Errorf("%s shared a copy with another key", name)
		}
	}
	for i := 0; i < 3*displayCacheEntries; i++ {
		c.get(displayKey{run: strconv.Itoa(i)}, 100, build)
	}
	if c.len() > displayCacheEntries {
		t.Errorf("%d entries held, at most %d", c.len(), displayCacheEntries)
	}
	var big displayCache
	before := builds
	big.get(key, displayCacheBudget+1, build)
	big.get(key, displayCacheBudget+1, build)
	if builds != before+2 || big.len() != 0 {
		t.Errorf("an entry over the budget was kept: %d builds, %d held", builds-before, big.len())
	}
	// The identity of a redactor follows its extra patterns, in order.
	if redactorIdentity(nil) == redactorIdentity([]string{"a"}) || redactorIdentity([]string{"a", "b"}) == redactorIdentity([]string{"b", "a"}) {
		t.Error("two redactors with different patterns share an identity")
	}
	// The same patterns in two separately built slices are one identity (the
	// identity follows the patterns, not the slice that holds them).
	first, second := []string{"a", "b"}, []string{"a", "b"}
	if redactorIdentity(first) != redactorIdentity(second) {
		t.Error("the same patterns have two identities")
	}
}

// TestSecurityAssessModelAnswerIsTheSameFromTheCache: a second request is
// answered from the cached display copy and reads exactly as the first.
func TestSecurityAssessModelAnswerIsTheSameFromTheCache(t *testing.T) {
	h, id := modelHarness(t, true)
	h.validateWith(id, modelTestThreatModel)
	rec, _ := secassesssvc.ReadModel(h.runs.Side(), id)
	rec.Result.TM.Summary = "The key " + viewTestSecret + " leaked."
	blob, _ := json.Marshal(rec)
	if err := h.runs.Side().Put(id, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}
	_, first := h.model(id)
	before := sharedDisplayCache.len()
	_, second := h.model(id)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Errorf("the cached answer differs:\n%s\n%s", a, b)
	}
	if sharedDisplayCache.len() != before || before == 0 {
		t.Errorf("the second request changed the cache: %d then %d", before, sharedDisplayCache.len())
	}
	if first.Redaction.Hidden != 1 || second.Redaction.Hidden != 1 {
		t.Errorf("hidden = %d and %d, want 1", first.Redaction.Hidden, second.Redaction.Hidden)
	}
}

// TestModelAnswerFixturesDecodeAndAgreeWithTheGoSide: the web's answer fixtures
// (internal/secassess/testdata/model_answer_fixtures.json, written by
// web/src/lib/secAssessModel.test.ts from secAssessModelFixture.ts) are decoded
// into the real response type with unknown fields refused, so a renamed or
// invented member fails here; and what the Go side computes from the fixture's
// own stored result (the reading, the coverage line, the diagram and the
// vocabulary) is what the fixture says, so the web's tests run on words and
// shapes the server really produces.
func TestModelAnswerFixturesDecodeAndAgreeWithTheGoSide(t *testing.T) {
	data, err := os.ReadFile("../../secassess/testdata/model_answer_fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) < 6 {
		t.Fatalf("only %d fixtures: the file is cut short", len(raw))
	}
	for name, blob := range raw {
		t.Run(name, func(t *testing.T) {
			dec := json.NewDecoder(strings.NewReader(string(blob)))
			dec.DisallowUnknownFields()
			var a securityAssessModelJS
			if err := dec.Decode(&a); err != nil {
				t.Fatalf("the fixture is not the shape of the answer: %v", err)
			}
			res := a.Record.Result
			if got := secassess.CleanReading(res); got != a.Reading {
				t.Errorf("reading\n fixture: %q\n     Go: %q", a.Reading, got)
			}
			if got := secassess.CoverageLine(res); got != a.CoverageLine {
				t.Errorf("coverage line\n fixture: %q\n      Go: %q", a.CoverageLine, got)
			}
			if tm := res.TM; tm != nil {
				if a.Mermaid == nil {
					t.Fatal("a threat model answer without a diagram")
				}
				want := secassess.RenderMermaidWith(tm, secassess.MermaidOptions{MaxNodes: a.Mermaid.MaxNodes, LabelChars: a.Mermaid.LabelChars})
				if !reflect.DeepEqual(*a.Mermaid, want) {
					t.Errorf("diagram\n fixture: %+v\n     Go: %+v", *a.Mermaid, want)
				}
			} else if a.Mermaid != nil {
				t.Error("a pen test answer carries a diagram")
			}
			vocabSubsetProblems(t, a.Vocab)
			fixtureEvidenceProblems(t, a)
		})
	}
}

// fixtureEvidenceProblems fails for a fixture whose evidence words are not the
// ones the Go side can produce: a state or a reason the validator never sets,
// a refusal code the helper does not have, or counts that do not add up to the
// findings.
func fixtureEvidenceProblems(t *testing.T, a securityAssessModelJS) {
	t.Helper()
	states := map[secassess.EvidenceState]int{}
	if pt := a.Record.Result.PT; pt != nil {
		for _, f := range pt.Findings {
			switch f.EvidenceState {
			case "", secassess.EvidenceLogged, secassess.EvidenceUnlogged, secassess.EvidenceNotStarted:
			default:
				t.Errorf("finding %s has the evidence state %q", f.ID, f.EvidenceState)
			}
			if f.EvidenceReason != "" && !slices.Contains(secassess.EvidenceReasons, f.EvidenceReason) {
				t.Errorf("finding %s has the evidence reason %q", f.ID, f.EvidenceReason)
			}
			if (f.EvidenceState == secassess.EvidenceLogged) != (f.EvidenceReason == "") && f.EvidenceState != "" {
				t.Errorf("finding %s: state %q with reason %q", f.ID, f.EvidenceState, f.EvidenceReason)
			}
			states[f.EvidenceState]++
		}
		if ev := a.Record.Result.Report.Evidence; ev != nil {
			if ev.Logged != states[secassess.EvidenceLogged] || ev.NotStarted != states[secassess.EvidenceNotStarted] || ev.Logged+ev.Unlogged+ev.NotStarted != len(pt.Findings) {
				t.Errorf("evidence counts %+v do not match the %d findings %v", ev, len(pt.Findings), states)
			}
			for code := range ev.ByReason {
				if !slices.Contains(secassess.EvidenceReasons, code) {
					t.Errorf("evidence report counts the reason %q", code)
				}
			}
		}
	}
	for _, p := range a.Probes {
		if p.Refused != "" && !slices.Contains(secassess.ProbeRefusals(), p.Refused) {
			t.Errorf("probe %s was refused under %q", p.ID, p.Refused)
		}
	}
	if a.ProbeLog != nil && (a.ProbeLog.Shown != len(a.Probes) || a.ProbeLog.Shown > a.ProbeLog.Records) {
		t.Errorf("probe log %+v for %d probes", a.ProbeLog, len(a.Probes))
	}
}

// vocabSubsetProblems fails for every entry of a fixture's vocabulary that is
// not an entry of ModelVocab() word for word. A fixture may carry fewer entries
// than the real lists; it may not invent or reword one.
func vocabSubsetProblems(t *testing.T, got secassess.ModelVocabulary) {
	t.Helper()
	asMap := func(v secassess.ModelVocabulary) map[string][]map[string]any {
		blob, _ := json.Marshal(v)
		var generic map[string]json.RawMessage
		if err := json.Unmarshal(blob, &generic); err != nil {
			t.Fatal(err)
		}
		out := map[string][]map[string]any{}
		for k, raw := range generic {
			var list []map[string]any
			if err := json.Unmarshal(raw, &list); err == nil {
				out[k] = list
			}
		}
		return out
	}
	have, want := asMap(got), asMap(secassess.ModelVocab())
	if len(have) == 0 {
		t.Error("the fixture's vocabulary carries no list")
	}
	for k, items := range have {
		real := map[string]map[string]any{}
		for _, it := range want[k] {
			if id, ok := it["id"].(string); ok {
				real[id] = it
			}
		}
		for _, it := range items {
			id, _ := it["id"].(string)
			if !reflect.DeepEqual(real[id], it) {
				t.Errorf("vocab %s entry %q is not the real one:\n fixture: %v\n     Go: %v", k, id, it, real[id])
			}
		}
	}
}
