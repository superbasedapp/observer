//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

const modelTestRun = "0123456789abcdef"

const modelTestThreatModel = `{
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

// modelHarness is a relax harness with a started run that was launched under the
// threat model contract and has written its files into the project.
func modelHarness(t *testing.T, ended bool) (*relaxHarness, string) {
	t.Helper()
	h := newRelaxHarness(t, "")
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) {"
	writeModelTestFile(t, h.root, "cmd/api/main.go", strings.Join(lines, "\n")+"\n")
	run := secassesssvc.Run{
		ID: modelTestRun, Kind: "threat_model", Tool: "claude-code", ProjectRootHash: h.hash, ProjectName: "api",
		Handle: "H-model", Seeded: true, Contract: string(secassess.ContractThreatModel), Phase: secassesssvc.PhaseStarted,
		TimeBoxMinutes: 60, Audit: string(secassess.AuditOff),
	}
	if ended {
		run.EndedAt = time.Now().Add(-5 * time.Minute).UTC()
	}
	if _, err := h.runs.Record(run, time.Now()); err != nil {
		t.Fatal(err)
	}
	return h, modelTestRun
}

func writeModelTestFile(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (h *relaxHarness) validate(id string, anyway bool, confirm bool) *httptest.ResponseRecorder {
	h.t.Helper()
	return postAssess(h.t, h.s.handleSecurityAssessValidate, "/api/security/assessments/validate", map[string]any{"run": id, "anyway": anyway}, confirm)
}

func (h *relaxHarness) model(id string) (int, securityAssessModelJS) {
	h.t.Helper()
	var out securityAssessModelJS
	code := getAssessJSON(h.t, h.s.handleSecurityAssessModel, "/api/security/assessments/model?run="+id, &out)
	return code, out
}

func (h *relaxHarness) runRow(id string) securityAssessRunJS {
	h.t.Helper()
	var list securityAssessListJS
	if c := getAssessJSON(h.t, h.s.handleSecurityAssess, "/api/security/assessments", &list); c != http.StatusOK {
		h.t.Fatalf("list: %d", c)
	}
	for _, r := range list.Runs {
		if r.ID == id {
			return r
		}
	}
	h.t.Fatalf("run %s is not listed", id)
	return securityAssessRunJS{}
}

// TestSecurityAssessValidateRoundTrip: the whole workflow of a run that wrote
// its model: the row says model ready, Validate checks it, the row says
// validated with the reference tally, the stored copy is Observer's, and a
// change to the model or to a cited file is seen.
func TestSecurityAssessValidateRoundTrip(t *testing.T) {
	h, id := modelHarness(t, true)
	// The harness run has ended and wrote nothing yet: over, so "ended_empty", not "started"
	// (a run still live reads "started"); the model written below moves it on.
	if row := h.runRow(id); row.State != string(secassess.StateEndedEmpty) || row.Files.Model || row.Validation != nil || row.Contract != "threatmodel.v1" {
		t.Fatalf("before the model: %+v", row)
	}
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel)
	if row := h.runRow(id); row.State != "model_ready" || !row.Files.Model {
		t.Fatalf("model written: state %q files %+v", row.State, row.Files)
	}
	w := h.validate(id, false, true)
	if w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	row := h.runRow(id)
	if row.State != "validated" || row.Validation == nil || (row.Validation.State != "valid" && row.Validation.State != "partial") {
		t.Fatalf("after validate: state %q validation %+v", row.State, row.Validation)
	}
	if row.Validation.Refs.Found == 0 || row.Validation.Stale || row.Validation.Anyway {
		t.Fatalf("validation = %+v", row.Validation)
	}
	// The stored copy: what Observer checked, with the cited file stamped.
	code, m := h.model(id)
	if code != http.StatusOK || m.Record.RunID != id || m.Record.Result.TM == nil || len(m.Record.Files) != 1 || m.Stale || len(m.Drift) != 0 {
		t.Fatalf("model: %d %+v", code, m)
	}
	// A cited file changes: the model names it as drifted.
	writeModelTestFile(t, h.root, "cmd/api/main.go", "package main\n")
	if _, m := h.model(id); len(m.Drift) != 1 || m.Drift[0] != "cmd/api/main.go" {
		t.Fatalf("drift = %v", m.Drift)
	}
	// The agent rewrites its model: the validation is out of date and the row says so.
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel+"\n ")
	row = h.runRow(id)
	if row.State != "model_ready" || row.Validation == nil || !row.Validation.Stale {
		t.Fatalf("after a rewrite: state %q validation %+v", row.State, row.Validation)
	}
	if _, m := h.model(id); !m.Stale {
		t.Errorf("the stored copy is not marked stale after a rewrite")
	}
}

func TestSecurityAssessValidateRefusals(t *testing.T) {
	t.Run("the confirm token and the method are required", func(t *testing.T) {
		h, id := modelHarness(t, true)
		if w := h.validate(id, false, false); w.Code != http.StatusForbidden {
			t.Errorf("no token: %d", w.Code)
		}
		r := httptest.NewRecorder()
		h.s.handleSecurityAssessValidate(r, httptest.NewRequest(http.MethodGet, "/api/security/assessments/validate", nil))
		if r.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET: %d", r.Code)
		}
		r = httptest.NewRecorder()
		h.s.handleSecurityAssessModel(r, httptest.NewRequest(http.MethodPost, "/api/security/assessments/model", nil))
		if r.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST model: %d", r.Code)
		}
	})
	t.Run("an unknown run", func(t *testing.T) {
		h, _ := modelHarness(t, true)
		if w := h.validate("00000000deadbeef", false, true); w.Code != http.StatusNotFound {
			t.Errorf("validate: %d", w.Code)
		}
		if code, _ := h.model("00000000deadbeef"); code != http.StatusNotFound {
			t.Errorf("model: %d", code)
		}
	})
	cases := []struct {
		name  string
		setup func(h *relaxHarness, id string)
		any   bool
		code  int
		want  string
	}{
		{"no assessment.json yet", func(*relaxHarness, string) {}, false, http.StatusConflict, codeNoModelFile},
		{"a legacy run has nothing to validate", func(h *relaxHarness, id string) {
			if _, _, err := h.runs.Mutate(id, func(r *secassesssvc.Run) error { r.Contract = ""; return nil }); err != nil {
				t.Fatal(err)
			}
		}, false, http.StatusConflict, codeNoModelContract},
		{"a project whose folder is gone", func(h *relaxHarness, id string) {
			if _, _, err := h.runs.Mutate(id, func(r *secassesssvc.Run) error { r.ProjectRootHash = "0000"; return nil }); err != nil {
				t.Fatal(err)
			}
		}, false, http.StatusConflict, codeProjectGone},
		{"a held run has no folder", func(h *relaxHarness, id string) {
			if _, _, err := h.runs.Mutate(id, func(r *secassesssvc.Run) error { r.Phase = secassesssvc.PhaseHeld; return nil }); err != nil {
				t.Fatal(err)
			}
		}, false, http.StatusConflict, codeModelNotStarted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, id := modelHarness(t, true)
			tc.setup(h, id)
			w := h.validate(id, tc.any, true)
			var out map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if w.Code != tc.code || out["code"] != tc.want {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
	t.Run("a run still running is validated only when asked", func(t *testing.T) {
		h, id := modelHarness(t, false)
		writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel)
		w := h.validate(id, false, true)
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != http.StatusConflict || out["code"] != codeRunStillRunning {
			t.Fatalf("not asked: %d %s", w.Code, w.Body)
		}
		if w := h.validate(id, true, true); w.Code != http.StatusOK {
			t.Fatalf("asked: %d %s", w.Code, w.Body)
		}
		if row := h.runRow(id); row.Validation == nil || !row.Validation.Anyway {
			t.Fatalf("the row does not say it was validated before the run ended: %+v", row.Validation)
		}
	})
	t.Run("a model nobody stored", func(t *testing.T) {
		h, id := modelHarness(t, true)
		if code, _ := h.model(id); code != http.StatusNotFound {
			t.Errorf("model before any validation: %d", code)
		}
	})
}

// TestSecurityAssessValidateRefusedFile: a file the validator refuses is an
// invalid model the row says plainly, not an error.
func TestSecurityAssessValidateRefusedFile(t *testing.T) {
	h, id := modelHarness(t, true)
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, "not json at all")
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	row := h.runRow(id)
	if row.State != "invalid" || row.Validation == nil || row.Validation.State != "invalid" || row.Validation.Fatal == "" {
		t.Fatalf("row = %q %+v", row.State, row.Validation)
	}
	// The stored copy carries the report and no model.
	code, m := h.model(id)
	if code != http.StatusOK || m.Record.Result.TM != nil || m.Record.Result.Report.Fatal == "" {
		t.Fatalf("model: %d %+v", code, m.Record.Result.Report)
	}
}

// TestSecurityAssessDeleteDataRemovesTheStoredModel: Delete evidence takes the
// stored copy with it, and the row's validation outcome (a scalar) stays.
func TestSecurityAssessDeleteDataRemovesTheStoredModel(t *testing.T) {
	h, id := modelHarness(t, true)
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel)
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d", w.Code)
	}
	if w := postAssess(t, h.s.handleSecurityAssessDeleteData, "/api/security/assessments/delete-data", map[string]any{"run": id}, true); w.Code != http.StatusOK {
		t.Fatalf("delete: %d", w.Code)
	}
	if code, _ := h.model(id); code != http.StatusNotFound {
		t.Errorf("the stored copy survived Delete: %d", code)
	}
	if row := h.runRow(id); row.Validation == nil || row.State != "validated" {
		t.Errorf("the validation outcome was lost with the evidence: %q %+v", row.State, row.Validation)
	}
}
