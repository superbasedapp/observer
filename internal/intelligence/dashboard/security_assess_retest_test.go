//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Tests of the retest and the red team objective on the dashboard side (depth
// plan W7.2 and W7.3, decision D38: labels only): the plan and launch choices,
// the refusals, the run's record, the audit line, validating a retest's file and
// joining its labels onto the earlier run's model answer.

const (
	retestEarlier = "0123456789abcdef" // the earlier pen test run (modelTestRun)
	retestLater   = "fedcba9876543210" // the retest run
)

// retestEarlierRun records a penetration test run whose checked model is stored
// (finding F-1 has a stored request and condition) and returns its id.
func retestEarlierRun(t *testing.T, h *relaxHarness) string {
	t.Helper()
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) {"
	writeModelTestFile(t, h.root, "cmd/api/main.go", strings.Join(lines, "\n")+"\n")
	if _, err := secassesssvc.PrepareRunDir(h.root, retestEarlier); err != nil {
		t.Fatal(err)
	}
	target, _ := secassess.ParseTarget("http://localhost:3000/")
	files, _, err := secassesssvc.WriteProbeFiles(h.root, secassesssvc.ProbeInput{RunID: retestEarlier, Target: target, Budget: 600, PaceRPS: 5})
	if err != nil {
		t.Fatal(err)
	}
	paths := secassess.ResultPaths(retestEarlier)
	writeModelTestFile(t, h.root, paths.ProbeLog, probeTestLine(1, 401, `{"error":"no"}`)+probeTestLine(2, 200, `{"token":"abc"}`))
	writeModelTestFile(t, h.root, paths.Model, probeTestPentest)
	run := secassesssvc.Run{
		ID: retestEarlier, Kind: "pentest_local", Tool: "claude-code", ProjectRootHash: h.hash, ProjectName: "api", Handle: "H-pt", Seeded: true,
		Contract: string(secassess.ContractPentest), Phase: secassesssvc.PhaseStarted, Target: "http://localhost:3000/", TimeBoxMinutes: 45,
		Audit: string(secassess.AuditOff), Helper: secassess.HelperOn, HelperSHA: files.Helper, ConfigSHA: files.Config,
		EndedAt: time.Now().Add(-time.Hour).UTC(), CreatedAt: time.Now().Add(-2 * time.Hour).UTC(),
	}
	if _, err := h.runs.Record(run, time.Now()); err != nil {
		t.Fatal(err)
	}
	if w := h.validate(retestEarlier, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate the earlier run: %d %s", w.Code, w.Body)
	}
	return retestEarlier
}

func (h *relaxHarness) retestQuery(of string, findings ...string) string {
	q := url.Values{}
	q.Set("target", "http://localhost:3000/")
	if of != "" {
		q.Set("of_run", of)
	}
	for _, f := range findings {
		q.Add("finding", f)
	}
	return "&" + q.Encode()
}

func (h *relaxHarness) retestLaunchBody(id, of string, findings ...string) map[string]any {
	b := h.launchBody(id, map[string]any{"assessment": "pentest_retest", "of_run": of, "finding_ids": findings})
	return b
}

func TestSecurityAssessRetestPlan(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	// F-1 of the earlier run carries a hidden value, so it is not chosen for the developer (the default is TestSecurityAssessRetestPlanDefaultSkipsHiddenValues); a stored body with nothing hidden is.
	retestSetStoredBody(t, h, earlier, "user=a&mode=b")
	p := h.planFor("pentest_retest", h.retestQuery(earlier))
	if !p.OK || p.Code != "" || p.Prompt == "" || p.PromptSHA256 != secassess.PromptSHA256(p.Prompt) {
		t.Fatalf("plan: ok %v code %q reason %q", p.OK, p.Code, p.Reason)
	}
	if !p.Kind.FromRun || p.Kind.Exercise || p.Kind.ID != "pentest_retest" {
		t.Errorf("kind = %+v", p.Kind)
	}
	r := p.Retest
	if r == nil || r.OfRun != earlier || r.OfKind != "pentest_local" || r.OfTarget != "http://localhost:3000/" || r.Max != secassess.MaxRetestFindings {
		t.Fatalf("retest block = %+v", r)
	}
	if len(r.Findings) != 1 || r.Findings[0].ID != "F-1" || r.Findings[0].Steps != 1 || !r.Findings[0].HasCondition ||
		!strings.Contains(r.Findings[0].Condition, "status 200") || r.Findings[0].Title != "Sign-in can be bypassed" {
		t.Errorf("findings = %+v", r.Findings)
	}
	// With none chosen the plan takes the findings it can replay in full.
	if len(r.Selected) != 1 || r.Selected[0] != "F-1" || len(r.Refused) != 0 {
		t.Errorf("selected %v refused %v", r.Selected, r.Refused)
	}
	for _, must := range []string{"REPLAY SET", "F-1 ATHN", "probe.py --replay", "observer.retest.v1", "Prompt version: re.2."} {
		if !strings.Contains(p.Prompt, must) {
			t.Errorf("the prompt lacks %q", must)
		}
	}
	if strings.Contains(p.Prompt, "Sign-in can be bypassed") {
		t.Error("the task carries a finding's title: it is built from the stored structure only")
	}
	if p.Model == nil || p.Model.PromptVersion != "re.2" || p.Model.Categories != "" || p.Limits == nil || p.Limits.TimeBoxMinutes != 20 {
		t.Errorf("model %+v limits %+v", p.Model, p.Limits)
	}
	if p.Probe == nil || p.Probe.State != secassess.HelperOn || p.Objective != nil {
		t.Errorf("probe %+v objective %+v", p.Probe, p.Objective)
	}
	// An explicit choice is kept, with the finding the earlier run does not have refused by name.
	p = h.planFor("pentest_retest", h.retestQuery(earlier, "F-1", "F-9"))
	if p.OK || p.Code != codeRetestFindings || p.Retest == nil || len(p.Retest.Refused) != 1 || p.Retest.Refused[0].Finding != "F-9" || p.Retest.Refused[0].Code != secassess.RetestUnknownFinding {
		t.Errorf("plan with F-9: ok %v code %q retest %+v", p.OK, p.Code, p.Retest)
	}
}

func TestSecurityAssessRetestPlanRefusals(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	// A pen test with no stored model, a threat model and a run of another project.
	other := "1111111111111111"
	for id, mut := range map[string]func(*secassesssvc.Run){
		other:              func(r *secassesssvc.Run) { r.Kind, r.Contract = "pentest_local", string(secassess.ContractPentest) },
		"2222222222222222": func(r *secassesssvc.Run) { r.Kind, r.Contract = "threat_model", string(secassess.ContractThreatModel) },
		"3333333333333333": func(r *secassesssvc.Run) {
			r.Kind, r.Contract, r.ProjectRootHash = "pentest_local", string(secassess.ContractPentest), "other-project"
		},
	} {
		run := secassesssvc.Run{ID: id, Tool: "claude-code", ProjectRootHash: h.hash, Phase: secassesssvc.PhaseStarted, Handle: "H" + id}
		mut(&run)
		if _, err := h.runs.Record(run, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		query string
		code  string
	}{
		{"no run named", h.retestQuery(""), codeRetestRunUnknown},
		{"a run that is not listed", h.retestQuery("ffffffffffffffff"), codeRetestRunUnknown},
		{"a threat model run", h.retestQuery("2222222222222222"), codeRetestRunMismatch},
		{"another project's run", h.retestQuery("3333333333333333"), codeRetestRunMismatch},
		{"a run with no stored model", h.retestQuery(other), codeRetestNoModel},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := h.planFor("pentest_retest", tc.query)
			if p.OK || p.Code != tc.code || p.Reason == "" || p.Prompt != "" {
				t.Fatalf("plan: ok %v code %q prompt %d bytes", p.OK, p.Code, len(p.Prompt))
			}
		})
	}
	t.Run("the helper is off", func(t *testing.T) {
		h.setConfig("probe_helper = false\n")
		p := h.planFor("pentest_retest", h.retestQuery(earlier, "F-1"))
		if p.OK || p.Code != codeRetestHelper || !strings.Contains(p.Reason, "request helper") {
			t.Errorf("plan: ok %v code %q reason %q", p.OK, p.Code, p.Reason)
		}
	})
	t.Run("the helper was left out for want of python3", func(t *testing.T) {
		h.setConfig("")
		stubTools(t, secassess.ToolFacts{"python3": false})
		if p := h.planFor("pentest_retest", h.retestQuery(earlier, "F-1")); p.OK || p.Code != codeRetestHelper {
			t.Errorf("plan: ok %v code %q", p.OK, p.Code)
		}
	})
}

// TestSecurityAssessRetestPlanNoStoredRequest: a finding whose reproduction has
// no request is listed as not replayable and refused when chosen.
func TestSecurityAssessRetestPlanNoStoredRequest(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	rec, ok := secassesssvc.ReadModel(h.runs.Side(), earlier)
	if !ok || rec.Result.PT == nil {
		t.Fatal("no stored model")
	}
	extra := rec.Result.PT.Findings[0]
	extra.ID, extra.Reproduction = "F-2", []secassess.PTRepro{{Step: "Read the code"}}
	rec.Result.PT.Findings = append(rec.Result.PT.Findings, extra)
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.runs.Side().Put(earlier, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}
	p := h.planFor("pentest_retest", h.retestQuery(earlier, "F-1"))
	if !p.OK || p.Retest == nil || len(p.Retest.Findings) != 1 || p.Retest.Findings[0].ID != "F-1" {
		t.Fatalf("the findings offered = %+v (ok %v)", p.Retest, p.OK)
	}
	p = h.planFor("pentest_retest", h.retestQuery(earlier, "F-2"))
	if p.OK || p.Code != codeRetestFindings || len(p.Retest.Refused) != 1 || p.Retest.Refused[0].Code != secassess.RetestNoRequest ||
		!strings.Contains(p.Reason, "F-2") {
		t.Errorf("plan: ok %v code %q reason %q retest %+v", p.OK, p.Code, p.Reason, p.Retest)
	}
}

// TestSecurityAssessRetestPlanTooLarge: stored requests that do not fit the
// helper's settings file are refused with their own code, in the plan and at the
// launch.
func TestSecurityAssessRetestPlanTooLarge(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	rec, _ := secassesssvc.ReadModel(h.runs.Side(), earlier)
	rec.Result.PT.Findings = nil
	var ids []string
	for i := 0; i < secassess.MaxRetestFindings; i++ {
		f := secassess.PTFinding{ID: fmt.Sprintf("F-%d", i+1), Title: "big", Category: "ATHN"}
		for j := 0; j < 8; j++ {
			req := &secassess.PTRequest{Method: "POST", Path: "/p", Body: strings.Repeat("b", 2048)}
			for k := 0; k < 8; k++ {
				req.Headers = append(req.Headers, secassess.PTHeader{Name: fmt.Sprintf("X-H-%d", k), Value: strings.Repeat("v", 256)})
			}
			f.Reproduction = append(f.Reproduction, secassess.PTRepro{Step: "s", Request: req})
		}
		rec.Result.PT.Findings = append(rec.Result.PT.Findings, f)
		ids = append(ids, f.ID)
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.runs.Side().Put(earlier, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}
	p := h.planFor("pentest_retest", h.retestQuery(earlier, ids...))
	if p.OK || p.Code != codeRetestTooLarge || !strings.Contains(p.Reason, "Choose fewer findings") {
		t.Fatalf("plan: ok %v code %q reason %q", p.OK, p.Code, p.Reason)
	}
	id := secassesssvc.NewRunID()
	code, out := h.launch(h.retestLaunchBody(id, earlier, ids...))
	if code != http.StatusConflict || out["code"] != codeRetestTooLarge {
		t.Fatalf("launch: %d %v", code, out)
	}
	if _, found := h.runs.Get(id); found {
		t.Error("a refused launch was recorded")
	}
	// One finding of the same kind fits.
	if p := h.planFor("pentest_retest", h.retestQuery(earlier, ids[0])); !p.OK {
		t.Errorf("one finding: code %q reason %q", p.Code, p.Reason)
	}
}

func TestSecurityAssessRetestLaunch(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "report_to_org = true\n")
	earlier := retestEarlierRun(t, h)
	t.Run("refused with no finding named", func(t *testing.T) {
		id := secassesssvc.NewRunID()
		code, out := h.launch(h.retestLaunchBody(id, earlier))
		if code != http.StatusConflict || out["code"] != codeRetestFindings || h.lm.lastFreshSpec.Tool != "" {
			t.Fatalf("launch: %d %v, started %q", code, out, h.lm.lastFreshSpec.Tool)
		}
		if _, found := h.runs.Get(id); found {
			t.Error("recorded")
		}
	})
	t.Run("refused with no earlier run", func(t *testing.T) {
		code, out := h.launch(h.retestLaunchBody(secassesssvc.NewRunID(), "", "F-1"))
		if code != http.StatusConflict || out["code"] != codeRetestRunUnknown {
			t.Fatalf("launch: %d %v", code, out)
		}
	})
	t.Run("refused when the helper is off", func(t *testing.T) {
		h.setConfig("probe_helper = false\n")
		defer h.setConfig("report_to_org = true\n")
		code, out := h.launch(h.retestLaunchBody(secassesssvc.NewRunID(), earlier, "F-1"))
		if code != http.StatusConflict || out["code"] != codeRetestHelper {
			t.Fatalf("launch: %d %v", code, out)
		}
	})
	t.Run("started: the record, the helper's replay settings and the task", func(t *testing.T) {
		before := h.auditRows()
		id := secassesssvc.NewRunID()
		code, out := h.launch(h.retestLaunchBody(id, earlier, "F-1"))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, out)
		}
		run, found := h.runs.Get(id)
		if !found {
			t.Fatal("the run was not recorded")
		}
		if run.Kind != "pentest_retest" || run.Contract != string(secassess.ContractRetest) || run.PromptVersion != "re.2" ||
			run.RetestOf != earlier || len(run.RetestFindings) != 1 || run.RetestFindings[0] != "F-1" || run.Objective != "" ||
			run.TimeBoxMinutes != 20 || !run.Sandboxed || run.Target != "http://localhost:3000/" || run.Helper != secassess.HelperOn {
			t.Errorf("run = %+v", run)
		}
		cfgBytes, err := readRunFile(t, h.root, secassess.ResultPaths(id).ProbeConfig)
		if err != nil {
			t.Fatal(err)
		}
		var cfg secassesssvc.ProbeConfig
		if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
			t.Fatal(err)
		}
		e, ok := cfg.Replay["F-1"]
		if !ok || len(cfg.Replay) != 1 || e.WSTG != "ATHN" || len(e.Steps) != 1 || e.Steps[0].Method != "POST" || e.Steps[0].Path != "/login" || e.Steps[0].Body != "user=a&password=[REDACTED]" {
			t.Errorf("replay settings = %+v", cfg.Replay)
		}
		if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "REPLAY SET") {
			t.Errorf("the task the agent got lacks the replay set")
		}
		// The audit line has counts and words only: no id, no objective.
		after := h.auditRows()
		if after["launch"] != before["launch"]+1 {
			t.Fatalf("audit rows %v then %v", before, after)
		}
		detail := h.lastLaunchAuditDetail()
		if !strings.Contains(detail, "retest_findings=1") || strings.Contains(detail, earlier) || strings.Contains(detail, "F-1") {
			t.Errorf("launch detail = %q", detail)
		}
		// The earlier run is untouched (D38: labels only).
		got, _ := h.runs.Get(earlier)
		if got.Import != nil || got.RetestOf != "" || got.Validation == nil || got.Validation.State == "" {
			t.Errorf("earlier run = %+v", got)
		}
		row := h.runRow(id)
		if row.RetestOf != earlier || len(row.RetestFindings) != 1 || row.Contract != "retest.v1" {
			t.Errorf("run row = %+v", row)
		}
	})
}

// lastLaunchAuditDetail is the detail of the newest launch audit row.
func (h *relaxHarness) lastLaunchAuditDetail() string {
	h.t.Helper()
	var detail string
	err := h.s.db().QueryRowContext(h.t.Context(), `SELECT reason FROM guard_events WHERE rule_id = ? AND tool = ? ORDER BY id DESC LIMIT 1`,
		store.SecAssessEventRuleID, store.SecAssessToolPrefix+"launch").Scan(&detail)
	if err != nil {
		h.t.Fatalf("audit detail: %v", err)
	}
	return detail
}

// retestResultJSON is a retest's assessment.json for the launched run.
func retestResultJSON(id string, result string, replayed bool) string {
	attack := "p2"
	if !replayed {
		attack = "p2"
	}
	return fmt.Sprintf(`{"schema":"observer.retest.v1","run_id":%q,"prompt_version":"re.2","generator":{"tool":"claude-code","model":"m"},
 "summary":"Replayed F-1.","started":true,
 "results":[{"finding":"F-1","result":%q,"attack":%q,"control":"p1","note":"Now answers 401."}],"limits":["Dev server only."]}`, id, result, attack)
}

func replayLine(n int, status int, body, replay string) string {
	line := probeTestLine(n, status, body)
	if replay == "" {
		return line
	}
	return strings.Replace(line, `"v":1,`, `"v":1,"replay":"`+replay+`",`, 1)
}

// TestSecurityAssessRetestValidateAndLabels: a retest run's file is held to the
// findings it replayed, its labels are Observer's reading of the helper's log,
// and they are joined onto the earlier run's model answer without changing it.
func TestSecurityAssessRetestValidateAndLabels(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	id := secassesssvc.NewRunID()
	if code, out := h.launch(h.retestLaunchBody(id, earlier, "F-1")); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	retestSetStoredBody(t, h, earlier, "user=a&password=x") // nothing hidden in the stored request
	paths := secassess.ResultPaths(id)
	// The run has not ended: validate anyway after writing the log and the file.
	// p1 is an ordinary request, p2 the replay: the stored condition no longer holds.
	writeModelTestFile(t, h.root, paths.ProbeLog, probeTestLine(1, 401, `{"error":"no"}`)+replayLine(2, 401, `{"error":"no"}`, "F-1"))
	writeModelTestFile(t, h.root, paths.Model, retestResultJSON(id, "not_reproduced", true))
	if w := h.validate(id, true, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	code, m := h.model(id)
	if code != http.StatusOK || m.Record.Result.RT == nil || len(m.Record.Result.RT.Results) != 1 {
		t.Fatalf("model: %d %+v", code, m.Record.Result.Report)
	}
	got := m.Record.Result.RT.Results[0]
	if got.Result != secassess.RetestNotReproduced || got.EvidenceState != secassess.EvidenceLogged || got.Title != "Sign-in can be bypassed" {
		t.Errorf("result = %+v (report %+v)", got, m.Record.Result.Report.Evidence)
	}
	if m.Retests != nil {
		t.Errorf("a retest run's own answer carries retests: %+v", m.Retests)
	}
	if len(m.Probes) != 2 || m.Probes[1].Replay != "F-1" {
		t.Errorf("the retest's cited records = %+v", m.Probes)
	}
	// The earlier run's answer carries the label, newest retest first.
	_, em := h.model(earlier)
	if len(em.Retests) != 1 || em.Retests[0].Run != id || !em.Retests[0].Started || len(em.Retests[0].Results) != 1 {
		t.Fatalf("retests = %+v", em.Retests)
	}
	rr := em.Retests[0].Results[0]
	if rr.Finding != "F-1" || rr.Result != "not_reproduced" || rr.EvidenceState != secassess.EvidenceLogged || rr.Note != "Now answers 401." {
		t.Errorf("label = %+v", rr)
	}
	// Labels only: the earlier model's finding keeps what it said and its evidence.
	f := em.Record.Result.PT.Findings[0]
	if f.ID != "F-1" || f.Status != "open" || f.EvidenceState != secassess.EvidenceLogged {
		t.Errorf("earlier finding = %+v", f)
	}
	if got, _ := h.runs.Get(earlier); got.Import != nil {
		t.Errorf("the earlier run's import record changed: %+v", got.Import)
	}
	// A retest cannot be exported, imported or turned into findings of its own.
	if w := getAssessRaw(t, h.s.handleSecurityAssessExport, "/api/security/assessments/export?run="+id+"&format=md"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), codeRetestNoExport) {
		t.Errorf("export of a retest: %d %s", w.Code, w.Body)
	}
	// A claim the log does not back is labelled as it is: the replay shows the weakness still.
	writeModelTestFile(t, h.root, paths.ProbeLog, probeTestLine(1, 401, `{"error":"no"}`)+replayLine(2, 200, `{"token":"abc"}`, "F-1"))
	if w := h.validate(id, true, true); w.Code != http.StatusOK {
		t.Fatalf("validate again: %d %s", w.Code, w.Body)
	}
	_, m = h.model(id)
	if r := m.Record.Result.RT.Results[0]; r.EvidenceState != secassess.EvidenceUnlogged || r.EvidenceReason != secassess.ReasonConditionStillHolds {
		t.Errorf("a not-reproduced claim the log contradicts reads %q/%q", r.EvidenceState, r.EvidenceReason)
	}
	// A request that was not the helper's replay backs nothing.
	writeModelTestFile(t, h.root, paths.ProbeLog, probeTestLine(1, 401, `{"error":"no"}`)+probeTestLine(2, 401, `{"error":"no"}`))
	if w := h.validate(id, true, true); w.Code != http.StatusOK {
		t.Fatalf("validate third: %d %s", w.Code, w.Body)
	}
	_, m = h.model(id)
	if r := m.Record.Result.RT.Results[0]; r.EvidenceState != secassess.EvidenceUnlogged || r.EvidenceReason != secassess.ReasonNotReplayed {
		t.Errorf("a request sent another way reads %q/%q", r.EvidenceState, r.EvidenceReason)
	}
}

// TestSecurityAssessRetestLoneEvidenceIsRead: the first live retest wrote one
// result's optional evidence as a lone probe id ("evidence": "p1") where the
// model asks for a list, and the whole file was refused (bad_shape). The file
// is read, the label is kept and backed, and validating the stored file again
// (what the dashboard does after a redeploy) answers the same.
func TestSecurityAssessRetestLoneEvidenceIsRead(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	id := secassesssvc.NewRunID()
	if code, out := h.launch(h.retestLaunchBody(id, earlier, "F-1")); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	retestSetStoredBody(t, h, earlier, "user=a&password=x")
	paths := secassess.ResultPaths(id)
	writeModelTestFile(t, h.root, paths.ProbeLog, probeTestLine(1, 401, `{"error":"no"}`)+replayLine(2, 401, `{"error":"no"}`, "F-1"))
	file := strings.Replace(retestResultJSON(id, "not_reproduced", true), `"note":"Now answers 401."`, `"evidence":"p1","note":"Now answers 401."`, 1)
	if !strings.Contains(file, `"evidence":"p1"`) {
		t.Fatal("the fixture does not carry the lone evidence")
	}
	writeModelTestFile(t, h.root, paths.Model, file)
	for pass := 1; pass <= 2; pass++ {
		if w := h.validate(id, true, true); w.Code != http.StatusOK {
			t.Fatalf("validate %d: %d %s", pass, w.Code, w.Body)
		}
		_, m := h.model(id)
		rep := m.Record.Result.Report
		if rep.State != secassess.ValidationValid || rep.Fatal != "" || m.Record.Result.RT == nil || len(m.Record.Result.RT.Results) != 1 {
			t.Fatalf("pass %d: the file was not read: %+v", pass, rep)
		}
		got := m.Record.Result.RT.Results[0]
		if got.Result != secassess.RetestNotReproduced || got.EvidenceState != secassess.EvidenceLogged || len(got.Evidence) != 1 || got.Evidence[0] != "p1" {
			t.Errorf("pass %d: result = %+v", pass, got)
		}
	}
}

// TestSecurityAssessRetestValidateRefusesWithoutABasis: a retest whose earlier
// model is gone is refused in words by the validator, never labelled against
// nothing.
func TestSecurityAssessRetestValidateRefusesWithoutABasis(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	id := secassesssvc.NewRunID()
	if code, out := h.launch(h.retestLaunchBody(id, earlier, "F-1")); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, retestResultJSON(id, "inconclusive", true))
	if err := h.runs.Side().Delete(earlier); err != nil {
		t.Fatal(err)
	}
	if w := h.validate(id, true, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	_, m := h.model(id)
	if m.Record.Result.Report.State != secassess.ValidationInvalid || m.Record.Result.Report.Fatal != "no_retest_basis" || m.Record.Result.RT != nil {
		t.Errorf("report = %+v", m.Record.Result.Report)
	}
}

// ---- the red team exercise's objective ------------------------------------

func TestSecurityAssessRedTeamObjective(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "report_to_org = true\n")
	q := "&target=http://localhost:3000/&objective=" + url.QueryEscape("  Read\nanother `user's` data  ")
	p := h.planFor("red_team_local", q)
	if !p.OK || p.Objective == nil || p.Objective.Text != "Read another user's data" || p.Objective.Max != secassess.MaxObjective || !p.Kind.Exercise || p.Retest != nil {
		t.Fatalf("plan: ok %v objective %+v kind %+v", p.OK, p.Objective, p.Kind)
	}
	if !strings.Contains(p.Prompt, `OBJECTIVE (developer's words): "Read another user's data"`) {
		t.Errorf("the task lacks the objective")
	}
	if p := h.planFor("red_team_local", "&target=http://localhost:3000/"); p.Objective == nil || p.Objective.Text != "" || strings.Contains(p.Prompt, "OBJECTIVE (developer's words)") {
		t.Errorf("with no objective: %+v", p.Objective)
	}
	if p := h.planFor("pentest_local", "&target=http://localhost:3000/&objective=anything"); p.Objective != nil || strings.Contains(p.Prompt, "OBJECTIVE (developer's words)") {
		t.Errorf("the pen test took an objective: %+v", p.Objective)
	}
	// The objective is bounded by characters, not bytes.
	long := strings.Repeat("é", secassess.MaxObjective+40)
	if p := h.planFor("red_team_local", "&target=http://localhost:3000/&objective="+url.QueryEscape(long)); p.Objective == nil || len([]rune(p.Objective.Text)) != secassess.MaxObjective {
		t.Errorf("long objective: %+v", p.Objective)
	}
	// A launch records it, the audit line says only that there is one, and a
	// validated model carries it as the developer's words.
	id := secassesssvc.NewRunID()
	body := h.launchBody(id, map[string]any{"assessment": "red_team_local", "objective": "Read another user's data"})
	if code, out := h.launch(body); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	run, _ := h.runs.Get(id)
	if run.Objective != "Read another user's data" || run.RetestOf != "" || run.PromptVersion != "pt.7" {
		t.Errorf("run = %+v", run)
	}
	if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, `OBJECTIVE (developer's words): "Read another user's data"`) {
		t.Error("the task the agent got lacks the objective")
	}
	detail := h.lastLaunchAuditDetail()
	if !strings.Contains(detail, "objective=yes") || strings.Contains(detail, "another user") {
		t.Errorf("launch detail = %q", detail)
	}
	if row := h.runRow(id); row.Objective != "Read another user's data" {
		t.Errorf("run row objective = %q", row.Objective)
	}
}

// TestSecurityAssessRedTeamExerciseIsCheckedAndShown: the exercise in a red team
// model is read through row V16 with the run's objective, and a penetration
// test's model never keeps one.
func TestSecurityAssessRedTeamExerciseIsCheckedAndShown(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) {"
	writeModelTestFile(t, h.root, "cmd/api/main.go", strings.Join(lines, "\n")+"\n")
	withExercise := strings.Replace(probeTestPentest, `"limits":["Only the dev server."]`,
		`"exercise":{"objective":"The agent's own","objective_by":"developer","chain":[{"step":"Sign in without a password","finding":"F-1","result":"achieved","stop":"A login throttle."},{"step":"Read orders","finding":"F-77","result":"blocked"}]},"limits":["Only the dev server."]`, 1)
	for _, tc := range []struct {
		kind, objective string
		want            bool
	}{{"red_team_local", "Take over an account", true}, {"pentest_local", "", false}} {
		t.Run(tc.kind, func(t *testing.T) {
			id := modelTestRunFor(tc.kind)
			if _, err := secassesssvc.PrepareRunDir(h.root, id); err != nil {
				t.Fatal(err)
			}
			writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, strings.Replace(withExercise, modelTestRun, id, 1))
			run := secassesssvc.Run{
				ID: id, Kind: tc.kind, Tool: "claude-code", ProjectRootHash: h.hash, ProjectName: "api", Handle: "H-" + tc.kind, Seeded: true,
				Contract: string(secassess.ContractPentest), Phase: secassesssvc.PhaseStarted, Target: "http://localhost:3000/", TimeBoxMinutes: 45,
				Audit: string(secassess.AuditOff), Objective: tc.objective, EndedAt: time.Now().Add(-5 * time.Minute).UTC(),
			}
			if _, err := h.runs.Record(run, time.Now()); err != nil {
				t.Fatal(err)
			}
			if w := h.validate(id, false, true); w.Code != http.StatusOK {
				t.Fatalf("validate: %d %s", w.Code, w.Body)
			}
			_, m := h.model(id)
			ex := m.Record.Result.PT.Exercise
			if !tc.want {
				if ex != nil {
					t.Errorf("a penetration test kept an exercise: %+v", ex)
				}
				return
			}
			if ex == nil || ex.Objective != tc.objective || ex.ObjectiveBy != secassess.ObjectiveByDeveloper || len(ex.Chain) != 2 {
				t.Fatalf("exercise = %+v", ex)
			}
			if ex.Chain[1].Finding != "" || ex.Chain[0].Finding != "F-1" || ex.Chain[0].Stop != "A login throttle." {
				t.Errorf("chain = %+v", ex.Chain)
			}
		})
	}
}

// modelTestRunFor is a run id per kind for the exercise test.
func modelTestRunFor(kind string) string {
	if kind == "red_team_local" {
		return "aaaaaaaaaaaaaaaa"
	}
	return "bbbbbbbbbbbbbbbb"
}

// getAssessRaw serves a GET and returns the recorder (for a refusal's body).
func getAssessRaw(t *testing.T, h http.HandlerFunc, url string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, url, nil))
	return w
}

// retestSetStoredBody changes the body of the first stored request of the
// earlier run's first finding in its stored model (the checked copy keeps a
// secret in a body as [REDACTED]; a test sets it to say what the finding
// does when nothing was hidden).
func retestSetStoredBody(t *testing.T, h *relaxHarness, runID, body string) {
	t.Helper()
	rec, ok := secassesssvc.ReadModel(h.runs.Side(), runID)
	if !ok || rec.Result.PT == nil {
		t.Fatal("no stored model")
	}
	rec.Result.PT.Findings[0].Reproduction[0].Request.Body = body
	blob, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.runs.Side().Put(runID, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}
}

// TestSecurityAssessRetestHiddenValuesBackNoNotReproduced: the earlier model
// keeps a secret in a request body as [REDACTED], so the replay is not the
// original request; the plan says so and a not reproduced label for the finding
// reads No log, whatever the log shows.
func TestSecurityAssessRetestHiddenValuesBackNoNotReproduced(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	p := h.planFor("pentest_retest", h.retestQuery(earlier, "F-1"))
	if !p.OK || p.Retest == nil || len(p.Retest.Findings) != 1 || !p.Retest.Findings[0].Hidden || !strings.Contains(p.Prompt, "some stored values were hidden") {
		t.Fatalf("plan: ok %v retest %+v", p.OK, p.Retest)
	}
	id := secassesssvc.NewRunID()
	if code, out := h.launch(h.retestLaunchBody(id, earlier, "F-1")); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	paths := secassess.ResultPaths(id)
	writeModelTestFile(t, h.root, paths.ProbeLog, probeTestLine(1, 401, `{"error":"no"}`)+replayLine(2, 401, `{"error":"no"}`, "F-1"))
	writeModelTestFile(t, h.root, paths.Model, retestResultJSON(id, "not_reproduced", true))
	if w := h.validate(id, true, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	_, m := h.model(id)
	if r := m.Record.Result.RT.Results[0]; r.EvidenceState != secassess.EvidenceUnlogged || r.EvidenceReason != secassess.ReasonReplayIncomplete {
		t.Errorf("a not-reproduced label for a finding with hidden values reads %q/%q", r.EvidenceState, r.EvidenceReason)
	}
}

// mustKind returns the kind with the id.
func mustKind(t *testing.T, id secassess.ID) secassess.Kind {
	t.Helper()
	k, ok := secassess.KindByID(string(id))
	if !ok {
		t.Fatalf("no kind %s", id)
	}
	return k
}

// seedRetestableRun records a finished penetration test run of the project whose
// checked model holds the given findings, each with one stored request, and
// returns its id.
func seedRetestableRun(t *testing.T, runs *secassesssvc.Store, projectHash string, findings []string) string {
	t.Helper()
	id := secassesssvc.NewRunID()
	run := secassesssvc.Run{
		ID: id, Kind: "pentest_local", Tool: "claude-code", ProjectRootHash: projectHash, ProjectName: "api", Handle: "H" + id, Seeded: true,
		Contract: string(secassess.ContractPentest), Phase: secassesssvc.PhaseStarted, Target: "http://localhost:3000/",
		EndedAt: time.Now().Add(-time.Hour).UTC(), CreatedAt: time.Now().Add(-2 * time.Hour).UTC(),
	}
	if _, err := runs.Record(run, time.Now()); err != nil {
		t.Fatal(err)
	}
	pt := &secassess.PentestDoc{}
	for _, f := range findings {
		pt.Findings = append(pt.Findings, secassess.PTFinding{
			ID: f, Title: "Finding " + f, Category: "ATHN",
			Reproduction: []secassess.PTRepro{{Step: "send", Request: &secassess.PTRequest{Method: "GET", Path: "/a/" + f}}},
		})
	}
	blob, err := json.Marshal(secassesssvc.ModelRecord{
		Schema: secassesssvc.ModelSchema, RunID: id, ValidatedAt: time.Now().UTC(), Contract: secassess.ContractPentest,
		Result: secassess.Result{Report: secassess.Report{State: secassess.ValidationValid, Contract: secassess.ContractPentest}, PT: pt},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runs.Side().Put(id, secassesssvc.SideModel, blob); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestSecurityAssessHeldRedTeamKeepsItsObjective: a red team run held for the
// organization keeps the developer's objective, and the plan that replays the
// held run carries it, so the run that starts is the run that was approved.
func TestSecurityAssessHeldRedTeamKeepsItsObjective(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "relax_red_team_local = true\nscoped_approval = true\n")
	h.managed(true)
	h.lockRule()
	id := secassesssvc.NewRunID()
	w := postAssess(t, h.s.handleSecurityAssessRequest, "/api/security/assessments/request", map[string]any{
		"assessment": "red_team_local", "project_root_hash": h.hash, "run_id": id, "target": "http://localhost:3000/",
		"relaxations": []string{secassess.RuleScanner}, "objective": "Read another user's data",
	}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	run, _ := h.runs.Get(id)
	if run.Phase != secassesssvc.PhaseHeld || run.Objective != "Read another user's data" || run.Kind != "red_team_local" {
		t.Fatalf("held run = %+v", run)
	}
	if row := h.runRow(id); row.Objective != "Read another user's data" {
		t.Errorf("run row objective = %q", row.Objective)
	}
	// The plan that replays the held run uses the held objective, whatever the query says.
	p := h.planFor("red_team_local", "&target=http://localhost:3000/&run="+id+"&objective=other")
	if p.Objective == nil || p.Objective.Text != "Read another user's data" || !strings.Contains(p.Prompt, `"Read another user's data"`) {
		t.Errorf("replay plan objective = %+v", p.Objective)
	}
}

// TestSecurityAssessRetestPlanDefaultSkipsHiddenValues (N-21): with none chosen
// the plan takes the findings the replay can send in full, not the first ones.
// A finding with a hidden value (a session header the helper cannot send, or a
// secret in a path or a body) is listed with that fact and left for the
// developer to choose; when every finding has one, none is chosen and the plan
// says to choose.
func TestSecurityAssessRetestPlanDefaultSkipsHiddenValues(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	earlier := retestEarlierRun(t, h)
	rec, ok := secassesssvc.ReadModel(h.runs.Side(), earlier)
	if !ok || rec.Result.PT == nil {
		t.Fatal("no stored model")
	}
	put := func(fs []secassess.PTFinding) {
		t.Helper()
		rec.Result.PT.Findings = fs
		blob, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.runs.Side().Put(earlier, secassesssvc.SideModel, blob); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(id string, req secassess.PTRequest) secassess.PTFinding {
		return secassess.PTFinding{ID: id, Title: "Finding " + id, Category: "ATHN", Reproduction: []secassess.PTRepro{{Step: "send", Request: &req}}}
	}
	header := secassess.PTRequest{Method: "GET", Path: "/a", Headers: []secassess.PTHeader{{Name: "Authorization", Value: "Bearer [REDACTED]"}}}
	body := secassess.PTRequest{Method: "POST", Path: "/b", Body: "password=[REDACTED]"}
	query := secassess.PTRequest{Method: "GET", Path: "/c?token=[REDACTED]"}
	plain := secassess.PTRequest{Method: "GET", Path: "/d"}
	plainHeader := secassess.PTRequest{Method: "GET", Path: "/e", Headers: []secassess.PTHeader{{Name: "Accept", Value: "application/json"}}}

	// Eleven findings: the hidden ones come first in the model, so "the first eight" would be mostly hidden ones.
	var fs []secassess.PTFinding
	fs = append(fs, mk("F-1", header), mk("F-2", body), mk("F-3", query))
	for i := 4; i <= 8; i++ {
		fs = append(fs, mk(fmt.Sprintf("F-%d", i), plain))
	}
	fs = append(fs, mk("F-9", plainHeader), mk("F-10", header), mk("F-11", plain))
	put(fs)
	p := h.planFor("pentest_retest", h.retestQuery(earlier))
	if !p.OK || p.Retest == nil {
		t.Fatalf("plan: ok %v code %q reason %q", p.OK, p.Code, p.Reason)
	}
	want := []string{"F-4", "F-5", "F-6", "F-7", "F-8", "F-9", "F-11"}
	if !equalStrings(p.Retest.Selected, want) {
		t.Errorf("selected %v, want %v (the findings the replay sends in full)", p.Retest.Selected, want)
	}
	// Every finding is still offered, with its hidden flag, so the picker lists the others with the reason.
	if len(p.Retest.Findings) != 11 {
		t.Fatalf("%d findings offered", len(p.Retest.Findings))
	}
	for _, f := range p.Retest.Findings {
		wantHidden := f.ID == "F-1" || f.ID == "F-2" || f.ID == "F-3" || f.ID == "F-10"
		if f.Hidden != wantHidden {
			t.Errorf("%s hidden = %v, want %v", f.ID, f.Hidden, wantHidden)
		}
	}
	if strings.Contains(p.Prompt, "some stored values were hidden") {
		t.Error("the task carries the hidden-value note for a finding that was not chosen")
	}

	// A finding with a hidden value can still be chosen by id, and is then replayed with its note.
	p = h.planFor("pentest_retest", h.retestQuery(earlier, "F-1", "F-4"))
	if !p.OK || !equalStrings(p.Retest.Selected, []string{"F-1", "F-4"}) || !strings.Contains(p.Prompt, "some stored values were hidden") {
		t.Errorf("a chosen hidden finding: ok %v selected %v", p.OK, p.Retest.Selected)
	}

	// Past the bound only the first eight replayable findings are taken.
	fs = nil
	for i := 1; i <= 10; i++ {
		fs = append(fs, mk(fmt.Sprintf("G-%d", i), plain))
	}
	put(fs)
	p = h.planFor("pentest_retest", h.retestQuery(earlier))
	if !p.OK || len(p.Retest.Selected) != secassess.MaxRetestFindings || p.Retest.Selected[0] != "G-1" || p.Retest.Selected[7] != "G-8" {
		t.Errorf("selected %v", p.Retest.Selected)
	}

	// Every finding has a hidden value: none is chosen for the developer, and the plan says to choose.
	put([]secassess.PTFinding{mk("H-1", header), mk("H-2", body)})
	p = h.planFor("pentest_retest", h.retestQuery(earlier))
	if p.OK || p.Code != codeRetestFindings || p.Reason != reasonRetestChoose || p.Retest == nil || len(p.Retest.Selected) != 0 || len(p.Retest.Findings) != 2 {
		t.Fatalf("all hidden: ok %v code %q reason %q retest %+v", p.OK, p.Code, p.Reason, p.Retest)
	}
	if !p.Retest.Findings[0].Hidden || !p.Retest.Findings[1].Hidden {
		t.Errorf("findings = %+v", p.Retest.Findings)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
