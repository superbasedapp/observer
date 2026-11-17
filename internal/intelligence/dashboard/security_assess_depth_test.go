//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// planFor reads the plan of a kind for the harness project, in the given
// settings (the harness config body).
func (h *relaxHarness) planFor(kind, query string) securityAssessPlanJS {
	h.t.Helper()
	var p securityAssessPlanJS
	url := "/api/security/assessments/plan?kind=" + kind + "&project=" + h.hash + query
	if code := getAssessJSON(h.t, h.s.handleSecurityAssessPlan, url, &p); code != http.StatusOK {
		h.t.Fatalf("plan %s: %d", kind, code)
	}
	return p
}

// setConfig rewrites the harness config body ([security.assessments] keys).
func (h *relaxHarness) setConfig(body string) {
	h.t.Helper()
	if err := os.WriteFile(h.s.opts.ConfigPath, []byte("[guard]\nenabled = true\nmode = \"enforce\"\n\n[security.assessments]\n"+body), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

// TestSecurityAssessPlanCarriesTheDigestAndSettings: the plan of a kind with a
// model contract names its prompt version and the sets in force, and carries
// the digest of the prompt it shows.
func TestSecurityAssessPlanCarriesTheDigestAndSettings(t *testing.T) {
	h := newRelaxHarness(t, "tm_frameworks = \"stride\"\ntm_method_extras = \"abuse_cases\"\nfindings_cap = 50\nimport_min_band = \"medium\"\nrerun_dedup = false\n")
	tm := h.planFor("threat_model", "")
	if !tm.OK || tm.Prompt == "" || tm.PromptSHA256 != secassess.PromptSHA256(tm.Prompt) {
		t.Fatalf("threat model plan: ok %v digest %q", tm.OK, tm.PromptSHA256)
	}
	m := tm.Model
	if m == nil || m.PromptVersion != "tm.7" || m.Frameworks != "stride" || m.MethodExtras != "abuse_cases" || m.Categories != "" ||
		!m.SelfCheck || m.ImportMinBand != "medium" || m.FindingsCap != 50 || m.RerunDedup {
		t.Fatalf("model block = %+v", m)
	}
	// The prompt follows the settings: STRIDE only, abuse cases but no tree.
	for _, must := range []string{"schema observer.threatmodel.v1", "Prompt version: tm.7.", "SELF-CHECK", "an abuse_case on the five"} {
		if !strings.Contains(tm.Prompt, must) {
			t.Errorf("the prompt lacks %q", must)
		}
	}
	for _, no := range []string{"framework linddun", "owasp_llm", "an attack_trees entry"} {
		if strings.Contains(tm.Prompt, no) {
			t.Errorf("the prompt has %q", no)
		}
	}
	// A pen test names its categories; a kind without a model has no block and
	// still carries a digest.
	pt := h.plan("")
	if pt.Model == nil || pt.Model.PromptVersion != "pt.7" || pt.Model.Categories != "all" || pt.Model.Frameworks != "" || pt.PromptSHA256 == "" {
		t.Fatalf("pen test plan: %+v", pt.Model)
	}
	cs := h.planFor("cspm_readonly", "")
	if cs.Model != nil || cs.Prompt == "" || cs.PromptSHA256 != secassess.PromptSHA256(cs.Prompt) || strings.Contains(cs.Prompt, "RESULT MODEL") {
		t.Fatalf("cloud review plan: model %+v", cs.Model)
	}
	// The settings change the words and so the digest.
	h.setConfig("")
	if again := h.planFor("threat_model", ""); again.PromptSHA256 == tm.PromptSHA256 || !strings.Contains(again.Prompt, "framework linddun") {
		t.Errorf("a changed setting left the prompt as it was")
	}
	h.setConfig("prompt_selfcheck = false\n")
	if off := h.planFor("threat_model", ""); strings.Contains(off.Prompt, "SELF-CHECK") || off.Model.SelfCheck {
		t.Errorf("the self-check is still named with the setting off")
	}
}

// TestSecurityAssessLaunchPlanChanged: a launch that sends the digest of the
// prompt the developer read starts only while that is still the prompt; when a
// setting changed in between nothing starts and the new prompt comes back.
func TestSecurityAssessLaunchPlanChanged(t *testing.T) {
	h := newRelaxHarness(t, "")
	p := h.plan("")
	if p.PromptSHA256 == "" {
		t.Fatal("no digest in the plan")
	}
	h.setConfig("pt_categories = \"api_only\"\n")
	id := secassesssvc.NewRunID()
	h.lm.lastFreshSpec = FreshLaunchSpec{}
	w := postAssess(t, h.s.handleSecurityAssessLaunch, "/api/security/assessments/launch", h.launchBody(id, map[string]any{"prompt_sha256": p.PromptSHA256}), true)
	var refusal map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &refusal)
	if w.Code != http.StatusConflict || refusal["code"] != codePlanChanged {
		t.Fatalf("a changed prompt: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(refusal["prompt"], "api") || refusal["prompt_sha256"] != secassess.PromptSHA256(refusal["prompt"]) || refusal["prompt_sha256"] == p.PromptSHA256 {
		t.Errorf("the refusal does not carry the new prompt: %v", refusal)
	}
	if h.lm.lastFreshSpec.Tool != "" {
		t.Errorf("a terminal was started: %+v", h.lm.lastFreshSpec)
	}
	if _, ok := h.runs.Get(id); ok {
		t.Error("a run was recorded for a launch that did not start")
	}
	// Sending the new digest starts it; so does sending none (an older dialog).
	if code, out := h.launch(h.launchBody(id, map[string]any{"prompt_sha256": refusal["prompt_sha256"]})); code != http.StatusOK || out["run_id"] != id {
		t.Fatalf("the new digest: %d %v", code, out)
	}
	id2 := secassesssvc.NewRunID()
	if code, _ := h.launch(h.launchBody(id2, nil)); code != http.StatusOK {
		t.Fatalf("no digest: %d", code)
	}
}

// TestSecurityAssessLaunchRecordsTheContract: a launch of a kind with a model
// contract records the contract, the prompt version and the sets it asked for;
// a kind without one records none.
func TestSecurityAssessLaunchRecordsTheContract(t *testing.T) {
	h := newRelaxHarness(t, "pt_categories = \"auth_access\"\n")
	id := secassesssvc.NewRunID()
	if code, out := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	run, ok := h.runs.Get(id)
	if !ok || run.Contract != "pentest.v1" || run.PromptVersion != "pt.7" || run.Sets == nil || run.Sets.Categories != "auth_access" || run.Sets.Frameworks != "all" {
		t.Fatalf("run = %+v", run)
	}
	// The prompt the agent was handed carries the contract and the settings.
	spec := h.lm.lastFreshSpec
	if !strings.Contains(spec.TaskPrompt, "schema observer.pentest.v1") || strings.Contains(spec.TaskPrompt, "CRYP ") {
		t.Errorf("task prompt: %.200s", spec.TaskPrompt)
	}
	// The sets recorded at launch are the ones the check holds the model to,
	// whatever the settings say later.
	h.setConfig("pt_categories = \"all\"\n")
	if o := h.s.securityAssessValidateOptions(run); len(o.Categories) != 4 {
		t.Errorf("the check uses %v, not the four categories the prompt asked for", o.Categories)
	}
	// A run recorded without sets (before them) follows the settings now.
	run.Sets = nil
	if o := h.s.securityAssessValidateOptions(run); len(o.Categories) != 12 || len(o.Frameworks) == 0 {
		t.Errorf("a run without recorded sets: categories %v", o.Categories)
	}
}

// TestSecurityAssessValidateHoldsTheModelToTheRecordedSets: a threat model
// launched for STRIDE only is checked for STRIDE only.
func TestSecurityAssessValidateHoldsTheModelToTheRecordedSets(t *testing.T) {
	h, id := modelHarness(t, true)
	if _, _, err := h.runs.Mutate(id, func(r *secassesssvc.Run) error {
		r.Sets = &secassesssvc.RunSets{Frameworks: "stride", MethodExtras: "neither", Categories: "all"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel)
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	_, m := h.model(id)
	sets := m.Record.Result.Report.Sets
	if len(sets.Frameworks) != 1 || sets.Frameworks[0] != "stride" || len(sets.MethodExtras) != 0 {
		t.Fatalf("sets = %+v", sets)
	}
}

// importHarness is a model harness with the SARIF import selected and a seam
// that remembers what it was handed.
func importHarness(t *testing.T, ended bool) (*relaxHarness, string, *[]byte) {
	t.Helper()
	h, id := modelHarness(t, ended)
	var got []byte
	h.s.opts.SARIFImport = &dashapi.SARIFImport{
		Tools: []dashapi.SARIFImportTool{{ID: "other", Label: "Another tool"}}, MaxBytes: 1 << 20,
		Import: func(_ context.Context, _, _ string, data []byte) (any, error) {
			got = data
			return map[string]any{"findings": 1, "new": 1, "with_lineage": 0}, nil
		},
	}
	h.s.opts.SecuritySelected = sarifRule("security.code", "security.scan.sarif-import")
	h.s.comps.svc = sarifSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	return h, id, &got
}

func (h *relaxHarness) importRun(id string) (*httptest.ResponseRecorder, securityAssessRunJS) {
	h.t.Helper()
	w := postAssess(h.t, h.s.handleSecurityAssessImport, "/api/security/assessments/import", map[string]any{"run": id}, true)
	var out struct{ Run securityAssessRunJS }
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out.Run
}

// TestSecurityAssessImportOfAModelRun: the import of a run under a model
// contract needs a current check, takes the findings Observer derives, says
// how many it left out and why, and records no_findings (never clean) when it
// derives none.
func TestSecurityAssessImportOfAModelRun(t *testing.T) {
	h, id, got := importHarness(t, true)
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel)
	// Not checked yet: a conflict, with its machine code, and nothing imported.
	w, _ := h.importRun(id)
	var refusal map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &refusal)
	if w.Code != http.StatusConflict || refusal["code"] != codeNotValidated || *got != nil {
		t.Fatalf("before the check: %d %s", w.Code, w.Body)
	}
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	if row := h.runRow(id); row.State != "validated" {
		t.Fatalf("state = %q", row.State)
	}
	w, row := h.importRun(id)
	if w.Code != http.StatusOK || row.State != "imported" || row.Import == nil || row.Import.Derived == nil {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	d := row.Import.Derived
	if d.Considered != 1 || d.Kept != 1 || row.Import.Findings != 1 || d.Dedup != true || d.MinBand != "low" {
		t.Errorf("derived = %+v", d)
	}
	// Defaults: stable rule id (rerun_dedup is on), and no agent prose.
	if !strings.Contains(string(*got), `"assess.tm.cwe-307"`) || strings.Contains(string(*got), "Rate limit") {
		t.Errorf("the seam got %s", *got)
	}
	// The agent rewrites its model: the outcome is not shown against a file it
	// does not describe, and the import is refused until the check is repeated.
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel+"\n ")
	if row := h.runRow(id); row.State != "model_ready" {
		t.Fatalf("after a change: state %q", row.State)
	}
	if w, _ := h.importRun(id); w.Code != http.StatusConflict {
		t.Fatalf("a stale model imported: %d", w.Code)
	}
}

// TestSecurityAssessImportDerivesNothing: a minimum band above every item
// records no_findings and says how many were under it.
func TestSecurityAssessImportDerivesNothing(t *testing.T) {
	h, id, got := importHarness(t, true)
	h.setConfig("import_min_band = \"critical\"\n")
	writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel)
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	w, row := h.importRun(id)
	if w.Code != http.StatusOK || row.State != "no_findings" || row.Import == nil || row.Import.Derived == nil || *got != nil {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	if d := row.Import.Derived; d.UnderMinBand != 1 || d.Kept != 0 || d.MinBand != "critical" {
		t.Errorf("derived = %+v", d)
	}
	// With the band lowered the same run imports.
	h.setConfig("")
	if w, row := h.importRun(id); w.Code != http.StatusOK || row.State != "imported" {
		t.Fatalf("re-import: %d state %q", w.Code, row.State)
	}
}

// TestSecurityAssessValidatedAuditRow: the check writes one content-free row
// for a reported run when the setting is on; an individual node's switch turns
// it off, a managed node's does not.
func TestSecurityAssessValidatedAuditRow(t *testing.T) {
	cases := []struct {
		name    string
		cfg     string
		tenancy secassess.Tenancy
		report  bool
		want    int
	}{
		{"reported, switch on", "", secassess.TenancyIndividual, true, 1},
		{"reported, switch off", "report_validation_to_org = false\n", secassess.TenancyIndividual, true, 0},
		{"not reported", "", secassess.TenancyIndividual, false, 0},
		{"managed ignores the switch", "report_validation_to_org = false\n", secassess.TenancyManaged, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, id := modelHarness(t, true)
			h.setConfig(tc.cfg)
			if _, _, err := h.runs.Mutate(id, func(r *secassesssvc.Run) error {
				r.Reported, r.Tenancy = tc.report, string(tc.tenancy)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			writeModelTestFile(t, h.root, secassess.ResultPaths(id).Model, modelTestThreatModel)
			if w := h.validate(id, false, true); w.Code != http.StatusOK {
				t.Fatalf("validate: %d %s", w.Code, w.Body)
			}
			if got := h.auditRows()["validated"]; got != tc.want {
				t.Fatalf("validated rows = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestSecurityAssessAuditDetailsAreContentFree: the audit lines carry ids and
// numbers only.
func TestSecurityAssessAuditDetailsAreContentFree(t *testing.T) {
	v := securityAssessValidatedDetail("0123456789abcdef", secassesssvc.ValidationRecord{
		State: "partial", Refs: secassess.RefTally{Found: 3, Missing: 1}, Issues: 4, Refused: 2, At: time.Now(),
	})
	if v != "run 0123456789abcdef state partial; refs found 3 exists 0 claimed_not_found 0 missing 1 invalid 0 unchecked 0; issues 4 refused 2" {
		t.Errorf("validated detail = %q", v)
	}
	i := securityAssessImportDetail("0123456789abcdef", secassesssvc.ImportRecord{
		Outcome: "imported", Findings: 2, New: 1, Derived: &secassesssvc.DerivedRecord{Considered: 5, Kept: 2, NoLocation: 2, UnderMinBand: 1},
	})
	if !strings.Contains(i, "derived 2 of 5 (no_location 2, under_min_band 1, duplicate 0, over_cap 0, over_ceiling 0)") || len(i) > 480 {
		t.Errorf("import detail = %q", i)
	}
}

// TestSecurityAssessPresetsResolve: every preset the settings offer resolves in
// the pure tables, and an unknown id falls back to the widest preset.
func TestSecurityAssessPresetsResolve(t *testing.T) {
	for _, id := range config.SecurityAssessmentsFrameworkPresets {
		if fw, _, _ := securityAssessResolveSets(secassesssvc.RunSets{Frameworks: id, MethodExtras: "both", Categories: "all"}); len(fw) == 0 {
			t.Errorf("framework preset %q resolved to nothing", id)
		}
	}
	for _, id := range config.SecurityAssessmentsCategoryPresets {
		if _, _, cat := securityAssessResolveSets(secassesssvc.RunSets{Frameworks: "all", MethodExtras: "both", Categories: id}); len(cat) == 0 {
			t.Errorf("category preset %q resolved to nothing", id)
		}
	}
	fw, ex, cat := securityAssessResolveSets(secassesssvc.RunSets{Frameworks: "pasta", MethodExtras: "nope", Categories: "mobile"})
	if len(fw) != 4 || len(ex) != 2 || len(cat) != 12 {
		t.Errorf("unknown ids resolved to %v %v %v", fw, ex, cat)
	}
	if got := securityAssessModelLimitsView(mustKind(t, secassess.CSPMReadonly), config.DefaultSecurityAssessmentsConfig()); got != nil {
		t.Errorf("a kind without a model contract has a model block: %+v", got)
	}
}

// useDaemonBinary replaces what the dashboard reads of its own executable: the
// path the operating system reports and whether a regular file stands there.
func useDaemonBinary(t *testing.T, path string, err error, isFile bool) {
	t.Helper()
	oldExe, oldFile := osExecutable, securityAssessIsFile
	osExecutable = func() (string, error) { return path, err }
	securityAssessIsFile = func(string) bool { return isFile }
	t.Cleanup(func() { osExecutable, securityAssessIsFile = oldExe, oldFile })
}

// TestSecurityAssessSelfCheckNamesTheDaemonBinary: the self-check line of a
// task names the daemon's own binary by its path (the first live runs found the
// bare command not on the agent's PATH, in both the penetration test and the
// retest). The plan the developer reads and the launch the agent is handed carry
// the same line; and when the daemon cannot give a usable path (it cannot read
// it, the file is gone, or it is not the folder-and-name the guard reads as
// Observer's) the line names the bare command as before.
func TestSecurityAssessSelfCheckNamesTheDaemonBinary(t *testing.T) {
	const exe = "/home/marmu/sbo-scratch/tr-grants/bin/observer"
	cases := []struct {
		name  string
		path  string
		err   error
		isFil bool
		want  string // the command word the line starts with
	}{
		{"a development build", exe, nil, true, exe},
		{"the path cannot be read", "", errors.New("no executable"), true, "observer"},
		{"the file is gone", exe, nil, false, "observer"},
		{"replaced while the daemon ran", exe + " (deleted)", nil, false, "observer"},
		{"a path with a space", "/home/u/My Tools/observer", nil, true, "observer"},
		{"a differently named binary", "/home/u/bin/observer-dev", nil, true, "observer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			useDaemonBinary(t, tc.path, tc.err, tc.isFil)
			h := newRelaxHarness(t, "")
			for _, kind := range []string{"threat_model", "pentest_local"} {
				var p securityAssessPlanJS
				url := "/api/security/assessments/plan?kind=" + kind + "&project=" + h.hash + "&target=http://localhost:3000/"
				if code := getAssessJSON(t, h.s.handleSecurityAssessPlan, url, &p); code != http.StatusOK {
					t.Fatalf("plan %s: %d", kind, code)
				}
				if line := secassess.SelfCheckCommand(tc.want, p.RunID); !strings.Contains(p.Prompt, "run `"+line+"`") {
					t.Errorf("%s: the plan's task does not tell the agent to run %q", kind, line)
				}
			}
			// The launch hands the agent the same spelling.
			id := secassesssvc.NewRunID()
			if code, out := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
				t.Fatalf("launch: %d %v", code, out)
			}
			if line := secassess.SelfCheckCommand(tc.want, id); !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "run `"+line+"`") {
				t.Errorf("the launched task does not tell the agent to run %q", line)
			}
		})
	}
}

// TestSelfCheckCommandPassesTheGuard: the command the prompt names for the
// agent's self-check is allowed by the guard's whole rule set (not merely not
// matched by one rule): an agent told to run it must not be asked or stopped.
// Every spelling the prompt could produce is evaluated, and the three verbs that
// stay the developer's are still denied beside it.
func TestSelfCheckCommandPassesTheGuard(t *testing.T) {
	const home, root = "/home/u", "/home/u/proj"
	evaluate := func(mode policy.Mode, line string) policy.Verdict {
		e, err := policy.New(policy.Config{Mode: mode, Home: home})
		if err != nil {
			t.Fatalf("policy.New: %v", err)
		}
		return e.Evaluate(policy.Event{
			Kind: policy.KindShellExec, Target: line, Cwd: root, ProjectRoot: root, SessionID: "s1",
			Now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC),
		})
	}
	// The command word is the bare command or the daemon's own path (the
	// self-check line names the path since the first live runs found the bare
	// command not on the agent's PATH): a development build, an installed copy
	// and a copy under a long path.
	bins := []string{
		"",
		"/home/marmu/sbo-scratch/tr-grants/bin/observer",
		"/mnt/d/programsx/superbased-observer/bin/observer",
		"/usr/local/bin/observer",
		"/home/u/.local/pipx/venvs/superbased-observer/lib/python3.12/site-packages/superbased_observer/bin/observer",
	}
	for _, mode := range []policy.Mode{policy.ModeObserve, policy.ModeEnforce} {
		for _, bin := range bins {
			cmd := secassess.SelfCheckCommand(bin, "3fa9c2d17b0e4a56")
			for _, line := range []string{cmd, cmd + " --json", "cd " + root + " && " + cmd} {
				if v := evaluate(mode, line); v.Decision != policy.DecisionAllow {
					t.Errorf("%s: %q is %s by %s (%s)", mode, line, v.Decision, v.RuleID, v.Reason)
				}
			}
		}
	}
	// The three verbs that stay the developer's are denied under every
	// spelling of the command word, the path included: naming the binary by its
	// path opens nothing the bare name kept shut.
	for _, bin := range bins {
		word := bin
		if word == "" {
			word = "observer"
		}
		for _, verb := range []string{"security trust accept --all", "security exception add F-1", "guard disable"} {
			line := word + " " + verb
			if v := evaluate(policy.ModeEnforce, line); v.Decision != policy.DecisionDeny {
				t.Errorf("%q is %s, want deny", line, v.Decision)
			}
		}
	}
}
