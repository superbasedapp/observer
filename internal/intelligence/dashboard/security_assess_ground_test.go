//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// writeProjectFiles lays out a project in the harness folder; a path with a
// slash gets its folders.
func (h *relaxHarness) writeProjectFiles(files map[string]string) {
	h.t.Helper()
	for rel, body := range files {
		p := filepath.Join(h.root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
}

// depthProject is a small Node project with an AI SDK, two start scripts, an
// example environment file and a real one.
var depthProject = map[string]string{
	"package.json":      `{"name":"app","scripts":{"dev":"vite --port 5173","start":"node server/index.js"},"dependencies":{"express":"4.19.0","openai":"4.0.0"}}`,
	"package-lock.json": `{}`,
	"server/index.js":   "console.log('hi')\n",
	"src/main.js":       "console.log('ui')\n",
	".env":              "TOKEN=not-read\n",
	".env.example":      "TOKEN=\n",
}

// planQuery is the plan route's query for the choices.
func planQuery(c securityAssessChoices) string {
	q := url.Values{}
	for _, p := range c.ScopePaths {
		q.Add("scope_path", p)
	}
	if c.ScopeNote != "" {
		q.Set("scope_note", c.ScopeNote)
	}
	if c.PreviousRun != "" {
		q.Set("previous_run", c.PreviousRun)
	}
	if c.Start != "" {
		q.Set("start", c.Start)
	}
	if c.Prepare {
		q.Set("prepare", "yes")
	}
	if len(q) == 0 {
		return ""
	}
	return "&" + q.Encode()
}

func (h *relaxHarness) tmLaunchBody(id string, extra map[string]any) map[string]any {
	b := map[string]any{"assessment": "threat_model", "project_root_hash": h.hash, "run_id": id, "tool": "claude-code"}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func (h *relaxHarness) launchRaw(body map[string]any) (int, map[string]any) {
	h.t.Helper()
	h.lm.lastFreshSpec = FreshLaunchSpec{}
	w := postAssess(h.t, h.s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, true)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// TestSecurityAssessPlanDepthBlocks: each kind's plan carries the blocks that
// apply to it and none that do not.
func TestSecurityAssessPlanDepthBlocks(t *testing.T) {
	h := newRelaxHarness(t, "")
	h.writeProjectFiles(depthProject)

	t.Run("a threat model: scope, grounding, earlier runs", func(t *testing.T) {
		p := h.planFor("threat_model", "")
		if !p.OK || p.Scope == nil || p.Grounding == nil || p.Previous == nil {
			t.Fatalf("blocks: scope %v grounding %v previous %v", p.Scope, p.Grounding, p.Previous)
		}
		if p.Start != nil || p.Preflight != nil || p.Tools != nil || p.Env != nil || p.Safety != nil {
			t.Errorf("a threat model carries a pen test block: %+v", p)
		}
		if got := strings.Join(p.Scope.Dirs, ","); got != "server,src" || len(p.Scope.Paths) != 0 || p.Scope.MaxPath != secassess.MaxScopeChoices || p.Scope.MaxNote != secassess.MaxScopeNote {
			t.Errorf("scope = %+v", p.Scope)
		}
		if p.Grounding.Mode != "full" || len(p.Grounding.Sections) == 0 || p.Grounding.Bytes == 0 || !p.Grounding.AIApp {
			t.Errorf("grounding = %+v", p.Grounding)
		}
		if p.Previous.Options == nil || len(p.Previous.Options) != 0 || p.Previous.Selected != "" || !strings.Contains(p.Previous.Note, "gives the agent nothing from the earlier run") || !strings.Contains(p.Previous.Note, "a request, not a barrier") {
			t.Errorf("previous = %+v", p.Previous)
		}
		if !strings.Contains(p.Prompt, "BEGIN PROJECT FACTS") || !strings.Contains(p.Prompt, "AI application: this project calls a model") {
			t.Errorf("the task lacks the digest or the AI step")
		}
		if p.Model == nil || p.Model.Grounding != "full" || p.Model.SecretMode != "" {
			t.Errorf("model block = %+v", p.Model)
		}
	})
	t.Run("a pen test: start, preflight, tools, environment, safety, limits", func(t *testing.T) {
		p := h.plan("")
		if p.Start == nil || p.Env == nil || p.Safety == nil || p.Tools == nil || p.Preflight == nil || p.Grounding == nil {
			t.Fatalf("blocks: %+v", p)
		}
		if p.Scope != nil || p.Previous != nil {
			t.Errorf("a pen test carries a threat model block")
		}
		if len(p.Start.Plans) == 0 || p.Start.NoneFound || p.Start.SelectedCommand != p.Start.Plans[0].Command || p.Start.Edited || p.Start.Edit != p.Start.SelectedCommand {
			t.Errorf("start = %+v", p.Start)
		}
		if p.Start.Plans[0].Command != "npm run dev" || p.Start.Plans[0].Port != 5173 {
			t.Errorf("first plan = %+v", p.Start.Plans[0])
		}
		if !strings.Contains(p.Prompt, "npm run dev") {
			t.Error("the task does not name the start command in force")
		}
		if p.Env.Count != 1 || strings.Join(p.Env.Files, ",") != ".env" || p.Env.Configured != "mask" || p.Env.Effective != "warn" || p.Env.Line == "" {
			t.Errorf("env = %+v", p.Env)
		}
		if p.Model.SecretMode != "mask" || p.Model.SecretModeEffective != "warn" || p.Model.RequestBudget != 600 || p.Model.PaceRPS != 5 {
			t.Errorf("model block = %+v", p.Model)
		}
		if p.Limits.RequestBudget != 600 || p.Limits.PaceRPS != 5 {
			t.Errorf("limits = %+v", p.Limits)
		}
		if len(p.Tools) != len(secassess.ToolRows) || len(p.Safety) != len(secassess.SafetyRows) {
			t.Errorf("tools %d safety %d", len(p.Tools), len(p.Safety))
		}
		for i, tool := range p.Tools {
			if tool.ID != secassess.ToolRows[i].ID || tool.Guarded != secassess.ToolRows[i].Guarded {
				t.Errorf("tool %d = %+v", i, tool)
			}
			// Only a Linux daemon can look; anywhere else every tool is unknown.
			if runtime.GOOS != "linux" && tool.Present != nil {
				t.Errorf("%s claims to know", tool.ID)
			}
		}
		ids := map[string]bool{}
		for _, n := range p.Preflight {
			ids[n.ID] = true
		}
		if !ids["env_files"] || ids["no_start_command"] {
			t.Errorf("preflight = %+v", p.Preflight)
		}
	})
	t.Run("a cloud review has none of them", func(t *testing.T) {
		p := h.planFor("cspm_readonly", "")
		if p.Scope != nil || p.Grounding != nil || p.Previous != nil || p.Start != nil || p.Preflight != nil || p.Tools != nil || p.Env != nil || p.Safety != nil {
			t.Fatalf("plan = %+v", p)
		}
		if strings.Contains(p.Prompt, "PROJECT FACTS") {
			t.Error("the cloud review carries a digest")
		}
	})
	t.Run("an unreadable project folder is no error", func(t *testing.T) {
		other := newRelaxHarness(t, "")
		if err := os.RemoveAll(other.root); err != nil {
			t.Fatal(err)
		}
		p := other.planFor("threat_model", "")
		if p.Scope == nil || len(p.Scope.Dirs) != 0 || p.Scope.Dirs == nil {
			t.Errorf("scope = %+v", p.Scope)
		}
	})
}

// TestSecurityAssessScopeRoundTrip: a typed scope is checked on the plan, the
// launch refuses what the plan refused, and the run records what was asked.
func TestSecurityAssessScopeRoundTrip(t *testing.T) {
	h := newRelaxHarness(t, "")
	h.writeProjectFiles(depthProject)
	choices := securityAssessChoices{ScopePaths: []string{"server", "../etc", "server/api"}, ScopeNote: "the `billing` flow"}
	p := h.planFor("threat_model", planQuery(choices))
	if !p.OK || p.Scope == nil || strings.Join(p.Scope.Paths, ",") != "server" || len(p.Scope.Refused) != 1 || p.Scope.Refused[0].Path != "../etc" || p.Scope.Refused[0].Reason == "" {
		t.Fatalf("scope = %+v", p.Scope)
	}
	if strings.Contains(p.Scope.Note, "`") || !strings.Contains(p.Scope.Note, "billing") {
		t.Errorf("note = %q", p.Scope.Note)
	}
	for _, must := range []string{"SCOPE (set by the developer", "  - server", "Scope: this run covers only the paths"} {
		if !strings.Contains(p.Prompt, must) {
			t.Errorf("the task lacks %q", must)
		}
	}
	if strings.Contains(p.Prompt, "etc") && strings.Contains(p.Prompt, "../") {
		t.Error("a refused place reached the task")
	}
	t.Run("the launch refuses a place the plan refused", func(t *testing.T) {
		id := secassesssvc.NewRunID()
		code, out := h.launchRaw(h.tmLaunchBody(id, map[string]any{"scope_paths": []string{"server", "../etc"}}))
		if code != http.StatusConflict || out["code"] != codeScopeInvalid || !strings.Contains(out["error"].(string), "../etc") {
			t.Fatalf("launch: %d %v", code, out)
		}
		if h.lm.lastFreshSpec.Tool != "" {
			t.Error("a terminal was started")
		}
		if _, ok := h.runs.Get(id); ok {
			t.Error("a run was recorded")
		}
	})
	t.Run("the launch of what the plan accepted starts the task the plan showed", func(t *testing.T) {
		code, out := h.launchRaw(h.tmLaunchBody(p.RunID, map[string]any{
			"scope_paths": p.Scope.Paths, "scope_note": choices.ScopeNote, "prompt_sha256": p.PromptSHA256,
		}))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, out)
		}
		if h.lm.lastFreshSpec.TaskPrompt != p.Prompt {
			t.Error("the task that started is not the task the plan showed")
		}
		run, ok := h.runs.Get(p.RunID)
		if !ok || strings.Join(run.ScopePaths, ",") != "server" || run.ScopeNote != p.Scope.Note || run.Grounding != "full" || run.Sets == nil || !run.Sets.AIApp {
			t.Fatalf("run = %+v", run)
		}
		if o := h.s.securityAssessValidateOptions(run); strings.Join(o.ScopePaths, ",") != "server" || !o.AIApp {
			t.Errorf("the check does not hold the model to the scope: %+v", o)
		}
		if v := h.runView(p.RunID); v.Scope == nil || strings.Join(v.Scope.Paths, ",") != "server" || v.Scope.Note != p.Scope.Note {
			t.Errorf("run view scope = %+v", v.Scope)
		}
	})
	t.Run("a ninth place is refused by name, not dropped", func(t *testing.T) {
		var many []string
		for _, d := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"} {
			many = append(many, d)
		}
		q := h.planFor("threat_model", planQuery(securityAssessChoices{ScopePaths: many}))
		if len(q.Scope.Paths) != 8 || len(q.Scope.Refused) != 1 || q.Scope.Refused[0].Path != "i" {
			t.Errorf("scope = %+v", q.Scope)
		}
	})
}

// TestSecurityAssessGroundingSetting: the digest follows the setting, and a
// launch of the task the developer read is refused when the setting changed.
func TestSecurityAssessGroundingSetting(t *testing.T) {
	h := newRelaxHarness(t, "")
	h.writeProjectFiles(depthProject)
	full := h.planFor("threat_model", "")
	h.setConfig("grounding = \"off\"\n")
	off := h.planFor("threat_model", "")
	if off.Grounding == nil || off.Grounding.Mode != "off" || off.Grounding.Bytes != 0 || len(off.Grounding.Sections) != 0 || strings.Contains(off.Prompt, "PROJECT FACTS") {
		t.Fatalf("grounding off = %+v", off.Grounding)
	}
	if off.PromptSHA256 == full.PromptSHA256 {
		t.Error("the digest of the task did not change with the setting")
	}
	// The developer read the full digest; the setting is now off.
	code, out := h.launchRaw(h.tmLaunchBody(full.RunID, map[string]any{"prompt_sha256": full.PromptSHA256}))
	if code != http.StatusConflict || out["code"] != codePlanChanged {
		t.Fatalf("a changed setting: %d %v", code, out)
	}
	// A project fact that changes the digest is the same case.
	h.setConfig("")
	read := h.planFor("threat_model", "")
	h.writeProjectFiles(map[string]string{"Dockerfile": "FROM scratch\n"})
	code, out = h.launchRaw(h.tmLaunchBody(read.RunID, map[string]any{"prompt_sha256": read.PromptSHA256}))
	if code != http.StatusConflict || out["code"] != codePlanChanged {
		t.Fatalf("a changed project: %d %v", code, out)
	}
	h.setConfig("grounding = \"without_findings\"\n")
	if w := h.planFor("threat_model", ""); w.Grounding.Mode != "without_findings" || !strings.Contains(w.Prompt, "PROJECT FACTS") {
		t.Errorf("without findings = %+v", w.Grounding)
	}
}

// putOpenFinding records one open finding of the harness project.
func (h *relaxHarness) putOpenFinding(key, rule string, cat policy.FindingCategory, rel string, line int) {
	h.t.Helper()
	if _, _, err := store.New(h.s.db()).UpsertSecFinding(context.Background(), secfinding.Normalize(secfinding.Finding{
		LocalKey: key, Rule: secfinding.Rule{ID: rule}, Category: cat,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Project: secfinding.Project{RootHash: h.hash}, Location: secfinding.Location{RelPath: rel, StartLine: line},
		Status: policy.FindingStatusOpen,
	}), time.Now()); err != nil {
		h.t.Fatal(err)
	}
}

// TestSecurityAssessGroundingFindings: the open findings reach the digest by
// rule id and place, Observer's own assessment findings do not, and the
// without-findings setting leaves them all out.
func TestSecurityAssessGroundingFindings(t *testing.T) {
	h := newRelaxHarness(t, "")
	h.writeProjectFiles(depthProject)
	h.putOpenFinding("k1", "S-100", policy.FindingCodeVuln, "server/index.js", 7)
	h.putOpenFinding("k2", "other/assess.tm.weak_session", policy.FindingCodeVuln, "server/session.js", 3)
	p := h.planFor("threat_model", "")
	if !strings.Contains(p.Prompt, "S-100") || !strings.Contains(p.Prompt, "server/index.js") {
		t.Errorf("the open finding is not in the digest")
	}
	if strings.Contains(p.Prompt, "weak_session") {
		t.Errorf("an earlier assessment's own finding was given back to the next one")
	}
	h.setConfig("grounding = \"without_findings\"\n")
	if q := h.planFor("threat_model", ""); strings.Contains(q.Prompt, "S-100") {
		t.Errorf("findings in a digest set to leave them out")
	}
}

// TestSecurityAssessStartChoices: the start command is read from the project,
// typed, declared none, refused when it cannot be written as an argv, and the
// launch sends the same task.
func TestSecurityAssessStartChoices(t *testing.T) {
	h := newRelaxHarness(t, "")
	h.writeProjectFiles(depthProject)
	t.Run("a typed command is in force and in the task", func(t *testing.T) {
		p := h.plan(planQuery(securityAssessChoices{Start: "python3 serve.py --port 8000"}))
		if !p.OK || p.Start.SelectedCommand != "python3 serve.py --port 8000" || !p.Start.Edited || p.Start.Error != "" || !strings.Contains(p.Prompt, "python3 serve.py --port 8000") {
			t.Fatalf("start = %+v ok %v", p.Start, p.OK)
		}
	})
	t.Run("a command that cannot be written is refused with its own code and no task", func(t *testing.T) {
		p := h.plan(planQuery(securityAssessChoices{Start: "npm run dev | tee log"}))
		if p.OK || p.Code != codeStartInvalid || p.Reason == "" || p.Prompt != "" || p.PromptSHA256 != "" || p.Start.Error != p.Reason || !p.Start.Edited || p.Start.SelectedCommand != "" || p.Start.Edit != "npm run dev | tee log" {
			t.Fatalf("plan = ok %v code %q reason %q start %+v", p.OK, p.Code, p.Reason, p.Start)
		}
		code, out := h.launchRaw(h.launchBody(secassesssvc.NewRunID(), map[string]any{"start": "npm run dev | tee log"}))
		if code != http.StatusConflict || out["code"] != codeStartInvalid || h.lm.lastFreshSpec.Tool != "" {
			t.Fatalf("launch: %d %v", code, out)
		}
	})
	t.Run("none declares no command and is recorded as none", func(t *testing.T) {
		p := h.plan(planQuery(securityAssessChoices{Start: securityAssessNone}))
		if !p.OK || p.Start.SelectedCommand != "" || p.Start.Edit != "" || len(p.Start.Plans) == 0 {
			t.Fatalf("start = %+v", p.Start)
		}
		code, out := h.launchRaw(h.launchBody(p.RunID, map[string]any{"start": securityAssessNone, "prompt_sha256": p.PromptSHA256}))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, out)
		}
		if run, _ := h.runs.Get(p.RunID); run.Start != "" || run.Contract != "pentest.v1" {
			t.Fatalf("run = %+v", run)
		}
	})
	t.Run("a launch that chose nothing takes the default and records it", func(t *testing.T) {
		p := h.plan("")
		code, out := h.launchRaw(h.launchBody(p.RunID, map[string]any{"prompt_sha256": p.PromptSHA256}))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, out)
		}
		if run, _ := h.runs.Get(p.RunID); run.Start != "npm run dev" || run.Grounding != "full" {
			t.Fatalf("run = %+v", run)
		}
		if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "npm run dev") {
			t.Error("the task does not name the command")
		}
	})
	t.Run("a project that names none says so", func(t *testing.T) {
		bare := newRelaxHarness(t, "")
		p := bare.plan("")
		if !p.OK || !p.Start.NoneFound || len(p.Start.Plans) != 0 || p.Start.Plans == nil || p.Start.SelectedCommand != "" {
			t.Fatalf("start = %+v", p.Start)
		}
	})
}

// TestSecurityAssessEnvFilesRefuse: with the Refuse setting an open secret in
// an environment or key file refuses the plan and the launch, with its own code;
// a secret in an ordinary source file, a closed one and another project's do
// not.
func TestSecurityAssessEnvFilesRefuse(t *testing.T) {
	cases := []struct {
		name   string
		cfg    string
		file   string
		refuse bool
	}{
		{"refuse with an open secret in .env", "workspace_secret_mode = \"refuse\"\n", ".env", true},
		{"refuse with an open secret in a key file", "workspace_secret_mode = \"refuse\"\n", "deploy/server.pem", true},
		{"refuse with an open secret in source", "workspace_secret_mode = \"refuse\"\n", "src/main.js", false},
		{"warn with an open secret in .env", "workspace_secret_mode = \"warn\"\n", ".env", false},
		{"off with an open secret in .env", "workspace_secret_mode = \"off\"\n", ".env", false},
		{"mask is a warning here", "workspace_secret_mode = \"mask\"\n", ".env", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newRelaxHarness(t, c.cfg)
			h.writeProjectFiles(depthProject)
			h.putOpenFinding("s1", "S-721", policy.FindingSecret, c.file, 1)
			p := h.plan("")
			code, out := h.launchRaw(h.launchBody(p.RunID, nil))
			if c.refuse {
				if p.OK || p.Code != codeSecretFilesOpen || p.Reason != secassess.ReasonSecretFilesOpen || p.Prompt != "" || p.Env.Effective != "refuse" {
					t.Fatalf("plan = ok %v code %q env %+v", p.OK, p.Code, p.Env)
				}
				if code != http.StatusConflict || out["code"] != codeSecretFilesOpen || h.lm.lastFreshSpec.Tool != "" {
					t.Fatalf("launch: %d %v", code, out)
				}
				return
			}
			if !p.OK || p.Prompt == "" {
				t.Fatalf("plan = ok %v code %q", p.OK, p.Code)
			}
			if code != http.StatusOK {
				t.Fatalf("launch: %d %v", code, out)
			}
		})
	}
	t.Run("a secret in a closed finding does not refuse", func(t *testing.T) {
		h := newRelaxHarness(t, "workspace_secret_mode = \"refuse\"\n")
		h.writeProjectFiles(depthProject)
		h.putOpenFinding("s2", "S-721", policy.FindingSecret, ".env", 1)
		if _, err := h.s.db().ExecContext(context.Background(), `UPDATE sec_findings SET status = 'fixed_verified'`); err != nil {
			t.Fatal(err)
		}
		if p := h.plan(""); !p.OK {
			t.Fatalf("plan = %q %q", p.Code, p.Reason)
		}
	})
}

// TestSecurityAssessPreviousRuns: the earlier checked threat models are
// offered, the one with the same scope is the default, none is a choice, and
// the launch records what was in force.
func TestSecurityAssessPreviousRuns(t *testing.T) {
	h := newRelaxHarness(t, "")
	h.writeProjectFiles(depthProject)
	keep := func(id string, scope []string, age time.Duration) {
		t.Helper()
		run := secassesssvc.Run{
			ID: id, Kind: "threat_model", ProjectRootHash: h.hash, ProjectName: "app", Phase: secassesssvc.PhaseStarted,
			ScopePaths: scope, Validation: &secassesssvc.ValidationRecord{State: "valid"},
		}
		if _, err := h.runs.Record(run, time.Now().Add(-age)); err != nil {
			t.Fatal(err)
		}
		rec := secassesssvc.ModelRecord{Schema: secassesssvc.ModelSchema, RunID: id, Contract: secassess.ContractThreatModel}
		rec.Result.TM = &secassess.ThreatModelDoc{}
		blob, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.runs.Side().Put(id, secassesssvc.SideModel, blob); err != nil {
			t.Fatal(err)
		}
	}
	keep("00000000000000a1", nil, 3*time.Hour)
	keep("00000000000000a2", []string{"server"}, 2*time.Hour)

	whole := h.planFor("threat_model", "")
	if got := len(whole.Previous.Options); got != 2 || whole.Previous.Options[0].ID != "00000000000000a2" || whole.Previous.Default != "00000000000000a1" || whole.Previous.Selected != "00000000000000a1" {
		t.Fatalf("whole project: %+v", whole.Previous)
	}
	scoped := h.planFor("threat_model", planQuery(securityAssessChoices{ScopePaths: []string{"server"}}))
	if scoped.Previous.Default != "00000000000000a2" || scoped.Previous.Selected != "00000000000000a2" {
		t.Fatalf("same scope: %+v", scoped.Previous)
	}
	other := h.planFor("threat_model", planQuery(securityAssessChoices{ScopePaths: []string{"src"}}))
	if other.Previous.Default != "" || other.Previous.Selected != "" {
		t.Fatalf("a different scope is a different model: %+v", other.Previous)
	}
	none := h.planFor("threat_model", planQuery(securityAssessChoices{PreviousRun: securityAssessNone}))
	if none.Previous.Selected != "" || none.Previous.Default != "00000000000000a1" {
		t.Fatalf("none: %+v", none.Previous)
	}
	named := h.planFor("threat_model", planQuery(securityAssessChoices{PreviousRun: "00000000000000a2"}))
	if named.Previous.Selected != "00000000000000a2" {
		t.Fatalf("named: %+v", named.Previous)
	}
	// A run id the developer named that is no longer an option is KEPT, so the check
	// says the earlier copy is gone; it is not dropped in silence (lane A review fix
	// W3-4). A string that is no run id at all is no choice and the default stands.
	gone := h.planFor("threat_model", planQuery(securityAssessChoices{PreviousRun: "00000000000000ff"}))
	if gone.Previous.Selected != "00000000000000ff" {
		t.Fatalf("a named run that is no longer an option was dropped: %+v", gone.Previous)
	}
	junk := h.planFor("threat_model", planQuery(securityAssessChoices{PreviousRun: "not a run id; drop table"}))
	if junk.Previous.Selected != junk.Previous.Default {
		t.Fatalf("a string that is no run id was selected: %+v", junk.Previous)
	}

	t.Run("the launch records the default, an explicit pick and none", func(t *testing.T) {
		for _, c := range []struct {
			name string
			body map[string]any
			want string
		}{
			{"default", nil, "00000000000000a1"},
			{"picked", map[string]any{"previous_run": "00000000000000a2"}, "00000000000000a2"},
			{"none", map[string]any{"previous_run": securityAssessNone}, ""},
			{"named, no longer an option (kept: the check says the copy is gone)", map[string]any{"previous_run": "00000000000000ff"}, "00000000000000ff"},
		} {
			id := secassesssvc.NewRunID()
			if code, out := h.launchRaw(h.tmLaunchBody(id, c.body)); code != http.StatusOK {
				t.Fatalf("%s: launch %d %v", c.name, code, out)
			}
			if run, _ := h.runs.Get(id); run.PreviousRun != c.want {
				t.Errorf("%s: previous = %q, want %q", c.name, run.PreviousRun, c.want)
			}
		}
	})
}

// TestSecurityAssessHeldRunKeepsItsStart: a run held for the organization keeps
// the start command it was held with, the plan that replays it shows that
// command, and the launch that starts it sends the same task whatever the body
// says.
func TestSecurityAssessHeldRunKeepsItsStart(t *testing.T) {
	h := newRelaxHarness(t, relaxOn)
	h.managed(true)
	h.lockRule()
	h.writeProjectFiles(depthProject)
	id := secassesssvc.NewRunID()
	w := postAssess(t, h.s.handleSecurityAssessRequest, "/api/security/assessments/request", map[string]any{
		"assessment": "pentest_local", "project_root_hash": h.hash, "run_id": id, "target": "http://localhost:3000/",
		"relaxations": []string{secassess.RuleScanner}, "start": "npm run start",
	}, true)
	if w.Code != http.StatusCreated {
		t.Fatalf("request: %d %s", w.Code, w.Body)
	}
	held, _ := h.runs.Get(id)
	if held.Start != "npm run start" {
		t.Fatalf("held run start = %q", held.Start)
	}
	h.reqs.held = []accessgrant.Held{grantFor(31, h.hash, 2)}
	rp := h.plan("&run=" + id)
	if rp.Start == nil || rp.Start.SelectedCommand != "npm run start" || rp.Start.Edited || !strings.Contains(rp.Prompt, "npm run start") {
		t.Fatalf("replayed plan start = %+v", rp.Start)
	}
	// The body says something else, or nothing: the held run's command stands.
	code, out := h.launchRaw(h.launchBody(id, map[string]any{
		"relaxations": []string{secassess.RuleScanner}, "start": "node other.js", "prompt_sha256": rp.PromptSHA256,
	}))
	if code != http.StatusOK {
		t.Fatalf("start: %d %v", code, out)
	}
	if h.lm.lastFreshSpec.TaskPrompt != rp.Prompt {
		t.Error("the task that started is not the task the replayed plan showed")
	}
	if run, _ := h.runs.Get(id); run.Start != "npm run start" || run.Phase != secassesssvc.PhaseStarted {
		t.Fatalf("started run = %+v", run)
	}
}

// TestSecurityAssessHeldRequestRefusals: the request route refuses a start
// command that cannot be used and an open secret under the Refuse setting before
// anything is filed with the organization.
func TestSecurityAssessHeldRequestRefusals(t *testing.T) {
	h := newRelaxHarness(t, relaxOn+"workspace_secret_mode = \"refuse\"\n")
	h.managed(true)
	h.lockRule()
	h.writeProjectFiles(depthProject)
	ask := func(extra map[string]any) (int, map[string]any) {
		body := map[string]any{
			"assessment": "pentest_local", "project_root_hash": h.hash, "run_id": secassesssvc.NewRunID(), "target": "http://localhost:3000/",
			"relaxations": []string{secassess.RuleScanner},
		}
		for k, v := range extra {
			body[k] = v
		}
		w := postAssess(t, h.s.handleSecurityAssessRequest, "/api/security/assessments/request", body, true)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	if code, out := ask(map[string]any{"start": "a && b"}); code != http.StatusConflict || out["code"] != codeStartInvalid {
		t.Fatalf("bad start: %d %v", code, out)
	}
	h.putOpenFinding("s1", "S-721", policy.FindingSecret, ".env", 1)
	if code, out := ask(nil); code != http.StatusConflict || out["code"] != codeSecretFilesOpen {
		t.Fatalf("open secret: %d %v", code, out)
	}
	if len(h.reqs.sent) != 0 {
		t.Errorf("%d requests were filed for a run that cannot start", len(h.reqs.sent))
	}
}

// TestSecurityAssessToolFacts: only a Linux daemon looks, and it says what it
// found in the given folders; every other system says nothing about any tool.
func TestSecurityAssessToolFacts(t *testing.T) {
	if runtime.GOOS == "windows" {
		// A Windows file has no execute bit; the probe is for a Linux daemon, so the
		// stand-in takes every regular file as executable and the bit itself is
		// tested on the platforms that have one (the row below).
		old := securityAssessExecutable
		securityAssessExecutable = func(os.FileMode) bool { return true }
		t.Cleanup(func() { securityAssessExecutable = old })
	}
	dir := t.TempDir()
	for _, name := range []string{"curl", "nmap"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "node"), 0o700); err != nil { // a folder is not a tool
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		// A plain file named like a tool is not the tool: no execute bit.
		if err := os.WriteFile(filepath.Join(dir, "sqlmap"), []byte("not a program"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := securityAssessToolFacts("linux", []string{filepath.Join(dir, "missing"), dir})
	if len(got) != len(secassess.ToolRows) || !got["curl"] || !got["nmap"] || got["python3"] || got["node"] || got["sqlmap"] {
		t.Fatalf("facts = %v", got)
	}
	for _, goos := range []string{"windows", "darwin", ""} {
		if f := securityAssessToolFacts(goos, []string{dir}); f != nil {
			t.Errorf("%s: facts = %v, want none", goos, f)
		}
	}
}

// TestToolGuardedColumnMatchesR179 is the drift test the tool table names: it
// evaluates "<tool> http://localhost:3000" through the guard's whole rule set
// for every row of the table and asserts that rule R-179 asks exactly for the
// rows marked Guarded. A scanner the rule covers that is missing from the table,
// or a row marked Guarded that the rule does not cover, fails here by name.
func TestToolGuardedColumnMatchesR179(t *testing.T) {
	const home, root = "/home/u", "/home/u/proj"
	e, err := policy.New(policy.Config{Mode: policy.ModeEnforce, Home: home})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}
	fires := func(base string) (bool, policy.Verdict) {
		v := e.Evaluate(policy.Event{
			Kind: policy.KindShellExec, Target: base + " http://localhost:3000", Cwd: root, ProjectRoot: root, SessionID: "s1",
			Now: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC),
		})
		return v.RuleID == "R-179", v
	}
	inTable := map[string]bool{}
	for _, row := range secassess.ToolRows {
		inTable[row.Command] = true
		got, v := fires(row.Command)
		if got != row.Guarded {
			t.Errorf("%s: Guarded is %v but R-179 %s (decision %s by %s)", row.Command, row.Guarded, map[bool]string{true: "asks", false: "does not ask"}[got], v.Decision, v.RuleID)
		}
		if row.Guarded && v.Decision != policy.DecisionAsk {
			t.Errorf("%s: a guarded tool is %s, want ask", row.Command, v.Decision)
		}
	}
	// Every well-known scanner R-179 asks about is in the table, guarded. The
	// names the rule does not cover stay out of the table on purpose: a fuzzer or
	// a credential guesser makes thousands of requests against a budget of
	// hundreds, so listing one as unguarded would invite it (decision D33).
	for _, name := range []string{
		"nmap", "masscan", "zmap", "rustscan", "naabu", "unicornscan", "hping3", "nikto", "nuclei", "sqlmap",
		"ffuf", "gobuster", "feroxbuster", "hydra", "wfuzz", "zaproxy", "zap-cli", "wpscan", "dirb", "dirbuster",
		"amass", "subfinder", "httpx", "whatweb", "arachni", "skipfish", "w3af", "openvas", "testssl.sh", "medusa", "john", "hashcat",
	} {
		got, _ := fires(name)
		switch {
		case got && !inTable[name]:
			t.Errorf("R-179 asks about %s but the tool table does not list it as Guarded", name)
		case !got && inTable[name] && name != "curl" && name != "python3" && name != "node":
			t.Errorf("the tool table lists %s but R-179 does not ask about it", name)
		}
	}
	// zap.sh and zap-baseline.py are launchers of the zaproxy row's tool: R-179
	// asks about both, they have no row of their own (a presence check in the
	// standard directories would call a box that has ZAP one without it), and
	// the zaproxy row, which is Guarded, names them.
	for _, alias := range []string{"zap.sh", "zap-baseline.py"} {
		if got, v := fires(alias); !got {
			t.Errorf("R-179 does not ask about %s (decision %s by %s)", alias, v.Decision, v.RuleID)
		}
		if inTable[alias] {
			t.Errorf("%s is a launcher of zaproxy and has no row of its own", alias)
		}
		named := false
		for _, row := range secassess.ToolRows {
			if row.Command == "zaproxy" && row.Guarded && strings.Contains(row.Purpose, alias) {
				named = true
			}
		}
		if !named {
			t.Errorf("the zaproxy row does not name %s", alias)
		}
	}
}
