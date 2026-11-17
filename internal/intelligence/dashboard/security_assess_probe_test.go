//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
)

// The request helper's dashboard side (depth plan W5b): the plan block and the
// task that follow the setting and the tool inventory, the two files written
// into the run folder at launch, what the run records, and the stored log
// records the model answer carries.

// stubTools makes the daemon's tool inventory say what a Linux daemon would.
func stubTools(t *testing.T, facts secassess.ToolFacts) {
	t.Helper()
	old := securityAssessToolsNow
	securityAssessToolsNow = func() secassess.ToolFacts { return facts }
	t.Cleanup(func() { securityAssessToolsNow = old })
}

func readRunFile(t *testing.T, root, rel string) ([]byte, error) {
	t.Helper()
	return os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
}

func TestSecurityAssessPlanHelperBlock(t *testing.T) {
	withPython := secassess.ToolFacts{"python3": true, "curl": true}
	noPython := secassess.ToolFacts{"python3": false, "curl": true}
	cases := []struct {
		name  string
		cfg   string
		tools secassess.ToolFacts
		state string
	}{
		{"on by default", "", withPython, secassess.HelperOn},
		{"on when the inventory is unknown", "", nil, secassess.HelperOn},
		{"off by the setting", "probe_helper = false\n", withPython, secassess.HelperOff},
		{"off by the setting, python3 absent too", "probe_helper = false\n", noPython, secassess.HelperOff},
		{"withheld when python3 is known to be absent", "", noPython, secassess.HelperWithheld},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stubTools(t, tc.tools)
			h := newRelaxHarness(t, tc.cfg)
			p := h.plan("")
			if !p.OK || p.Probe == nil {
				t.Fatalf("plan ok %v, probe %+v", p.OK, p.Probe)
			}
			run := secassess.ResultPaths(p.RunID)
			pr := p.Probe
			if pr.State != tc.state || pr.Dir != run.Dir || pr.Budget != 600 || pr.PaceRPS != 5 {
				t.Fatalf("probe = %+v", pr)
			}
			on := tc.state == secassess.HelperOn
			if on != (len(pr.Files) == 2) || (on && (pr.Files[0] != "probe.py" || pr.Files[1] != "probe.json")) {
				t.Errorf("files = %v with the helper %s", pr.Files, tc.state)
			}
			if (tc.state == secassess.HelperWithheld) != (pr.WithheldReason != "") {
				t.Errorf("withheld reason %q with the helper %s", pr.WithheldReason, tc.state)
			}
			// The task names the helper exactly when it is written.
			for _, must := range []string{"REQUEST HELPER", "probe.py", `"indicator"`} {
				if strings.Contains(p.Prompt, must) != on {
					t.Errorf("prompt has %q: %v, helper %s", must, !on, tc.state)
				}
			}
			// The safety table's Helper column follows it.
			table := map[string]secassess.SafetyRow{}
			for _, r := range secassess.SafetyRows {
				table[r.ID] = r
			}
			for _, r := range p.Safety {
				want := "-"
				if on {
					want = table[r.ID].Helper
				}
				if r.Helper != want {
					t.Errorf("safety row %s helper cell %q with the helper %s, want %q", r.ID, r.Helper, tc.state, want)
				}
				if r.ID == "pace_budget" && (r.Observer != "-") != on {
					t.Errorf("pace_budget observer cell %q with the helper %s", r.Observer, tc.state)
				}
			}
		})
	}
	t.Run("a kind that does not probe has no helper block", func(t *testing.T) {
		stubTools(t, withPython)
		h := newRelaxHarness(t, "")
		if p := h.planFor("threat_model", ""); p.Probe != nil || len(p.Safety) != 0 {
			t.Errorf("threat model plan: probe %+v, safety %d rows", p.Probe, len(p.Safety))
		}
	})
	t.Run("a red team plan carries it too", func(t *testing.T) {
		stubTools(t, withPython)
		h := newRelaxHarness(t, "")
		p := h.planFor("red_team_local", "&target=http://localhost:3000/")
		if p.Probe == nil || p.Probe.State != secassess.HelperOn || !strings.Contains(p.Prompt, "REQUEST HELPER") {
			t.Errorf("red team plan: probe %+v", p.Probe)
		}
	})
}

func TestSecurityAssessLaunchWritesTheHelper(t *testing.T) {
	t.Run("on: both files, hashes and the mode are recorded", func(t *testing.T) {
		stubTools(t, secassess.ToolFacts{"python3": true})
		h := newRelaxHarness(t, "pentest_request_budget = 200\npentest_pace_rps = 2\nreport_to_org = true\n")
		id := secassesssvc.NewRunID()
		code, body := h.launch(h.launchBody(id, nil))
		if code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		p := secassess.ResultPaths(id)
		py, err := readRunFile(t, h.root, p.ProbeHelper)
		if err != nil || string(py) == "" || secassesssvc.ProbeHelperSize() != len(py) {
			t.Fatalf("probe.py: %d bytes, %v", len(py), err)
		}
		cfgBytes, err := readRunFile(t, h.root, p.ProbeConfig)
		if err != nil {
			t.Fatal(err)
		}
		var cfg secassesssvc.ProbeConfig
		if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
			t.Fatal(err)
		}
		want := secassesssvc.ProbeConfig{Schema: secassess.ProbeConfigSchema, RunID: id, Origin: "http://localhost:3000", Budget: 200, PaceRPS: 2, MaxBytes: secassesssvc.ProbeMaxBytes}
		if !reflect.DeepEqual(cfg, want) {
			t.Errorf("probe.json = %+v, want %+v", cfg, want)
		}
		run, _ := h.runs.Get(id)
		if run.Helper != secassess.HelperOn || run.HelperSHA != secassesssvc.ProbeHelperSHA256() || run.ConfigSHA == "" {
			t.Fatalf("run = helper %q %q %q", run.Helper, run.HelperSHA, run.ConfigSHA)
		}
		if !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "REQUEST HELPER") || !strings.Contains(h.lm.lastFreshSpec.TaskPrompt, p.ProbeHelper) {
			t.Errorf("the prompt does not name the helper at %s", p.ProbeHelper)
		}
		// The launch audit row says the mode in force, content-free.
		var detail string
		if err := h.s.db().QueryRow(`SELECT COALESCE(reason,'') FROM guard_events WHERE event_kind = 'audit' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		for _, w := range []string{"probe_helper=on", "helper=on"} {
			if !strings.Contains(detail, w) {
				t.Errorf("launch audit detail lacks %q: %s", w, detail)
			}
		}
	})
	for _, tc := range []struct {
		name, cfg string
		tools     secassess.ToolFacts
		mode      string
	}{
		{"off writes nothing", "probe_helper = false\n", secassess.ToolFacts{"python3": true}, secassess.HelperOff},
		{"withheld writes nothing", "", secassess.ToolFacts{"python3": false}, secassess.HelperWithheld},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubTools(t, tc.tools)
			h := newRelaxHarness(t, tc.cfg)
			id := secassesssvc.NewRunID()
			if code, body := h.launch(h.launchBody(id, nil)); code != http.StatusOK {
				t.Fatalf("launch: %d %v", code, body)
			}
			p := secassess.ResultPaths(id)
			for _, rel := range []string{p.ProbeHelper, p.ProbeConfig, p.ProbeLog} {
				if _, err := readRunFile(t, h.root, rel); err == nil {
					t.Errorf("%s was written with the helper %s", rel, tc.mode)
				}
			}
			run, _ := h.runs.Get(id)
			if run.Helper != tc.mode || run.HelperSHA != "" || run.ConfigSHA != "" {
				t.Errorf("run = helper %q %q %q", run.Helper, run.HelperSHA, run.ConfigSHA)
			}
			if strings.Contains(h.lm.lastFreshSpec.TaskPrompt, "probe.py") {
				t.Error("the task names a helper that was not written")
			}
		})
	}
	t.Run("a threat model records no helper", func(t *testing.T) {
		stubTools(t, secassess.ToolFacts{"python3": true})
		h := newRelaxHarness(t, "")
		id := secassesssvc.NewRunID()
		if code, body := h.launchRaw(h.tmLaunchBody(id, nil)); code != http.StatusOK {
			t.Fatalf("launch: %d %v", code, body)
		}
		if run, _ := h.runs.Get(id); run.Helper != "" || run.HelperSHA != "" {
			t.Errorf("run = %+v", run)
		}
		if _, err := readRunFile(t, h.root, secassess.ResultPaths(id).ProbeHelper); err == nil {
			t.Error("a threat model run folder holds a helper")
		}
	})
}

// TestSecurityAssessLaunchRefusesWithoutTheHelper: the task the developer read
// says the helper is in the run folder, so a launch that cannot put it there
// does not start, leaves what it found alone and records no run.
func TestSecurityAssessLaunchRefusesWithoutTheHelper(t *testing.T) {
	stubTools(t, secassess.ToolFacts{"python3": true})
	h := newRelaxHarness(t, "")
	id := secassesssvc.NewRunID()
	p := secassess.ResultPaths(id)
	dir := filepath.Join(h.root, filepath.FromSlash(p.Dir))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "probe.json")
	if err := os.WriteFile(other, []byte(`{"origin":"http://example.com"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	h.lm.lastFreshSpec = FreshLaunchSpec{}
	w := postAssess(t, h.s.handleSecurityAssessLaunch, "/api/security/assessments/launch", h.launchBody(id, nil), true)
	var out map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != http.StatusConflict || out["code"] != codeHelperExists || !strings.Contains(out["error"], "already holds a different probe.py or probe.json") {
		t.Fatalf("launch: %d %v", w.Code, out)
	}
	if h.lm.lastFreshSpec.Tool != "" {
		t.Error("a terminal was started")
	}
	if _, found := h.runs.Get(id); found {
		t.Error("the refused launch was recorded as a run")
	}
	if b, _ := os.ReadFile(other); string(b) != `{"origin":"http://example.com"}` {
		t.Errorf("the file already there was changed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "probe.py")); err == nil {
		t.Error("probe.py, written by the refused launch, was left behind")
	}
}

// TestSecurityAssessHelperRefusal: each cause of a helper that could not be
// written has its own status, code and sentence, and none quotes the error.
func TestSecurityAssessHelperRefusal(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		status int
		code   string
		words  string
	}{
		{"a different file is there", fmt.Errorf("wrapped: %w", secassesssvc.ErrProbeExists), http.StatusConflict, codeHelperExists, "already holds a different probe.py or probe.json"},
		{"the folder is not there", fmt.Errorf("x: %w", secassesssvc.ErrProbeRun), http.StatusInternalServerError, codeHelperNotWritten, "the folder is not there"},
		{"the write failed", errors.New("open /home/u/secret/path: permission denied"), http.StatusInternalServerError, codeHelperNotWritten, "the write failed"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, code, msg := securityAssessHelperRefusal(c.err)
			if status != c.status || code != c.code || !strings.Contains(msg, c.words) {
				t.Fatalf("%d %s %q", status, code, msg)
			}
			if strings.Contains(msg, "/home/u") || strings.Contains(msg, "permission denied") {
				t.Errorf("the sentence quotes the error: %q", msg)
			}
		})
	}
}

const probeTestPentest = `{
 "schema":"observer.pentest.v1","run_id":"0123456789abcdef","prompt_version":"pt.7","generator":{"tool":"claude-code"},"summary":"Tested the dev server.",
 "target":{"url":"http://localhost:3000/","start":{"argv":["npm","run","dev"],"source":"package.json scripts.dev","started":true,"startup_seconds":6}},
 "method":{"standard":"wstg"},
 "coverage":[{"category":"ATHN","status":"tested","probes":["p1","p2"],"notes":"Tried the login."}],
 "findings":[{"id":"F-1","title":"Sign-in can be bypassed","category":"ATHN","cwe":["CWE-287"],"rating":{"likelihood":4,"impact":3},"basis":"observed",
   "where":{"refs":[{"path":"cmd/api/main.go","line":12,"needle":"func Login("}]},"route":"/login","evidence":["p1","p2"],
   "indicator":{"control":"p1","attack":"p2","when":{"status":200,"body_contains":["token"]}},
   "reproduction":[{"step":"Sign in with a crafted password","request":{"method":"POST","path":"/login","body":"user=a&password=x"}}],
   "impact":"Anyone can sign in as any user.","fix":"Use a parameterised query.","status":"open"}],
 "limits":["Only the dev server."]
}`

func probeTestLine(n int, status int, body string) string {
	rec := map[string]any{
		"v": 1, "id": "p" + string(rune('0'+n)), "ts": "2026-11-14T10:00:0" + string(rune('0'+n)) + ".000Z", "role": "attack", "wstg": "ATHN", "account": "", "note": "",
		"method": "POST", "path": "/login", "req_headers": []any{}, "req_body_bytes": 0, "req_body_excerpt": "", "sent": true, "refused": "", "error": "",
		"status": status, "resp_headers": []any{map[string]string{"n": "Content-Type", "v": "application/json"}}, "body_bytes": len(body), "body_truncated": false, "body_excerpt": body,
		"ms": 4, "hops": 0, "redirect_to": "", "redirect_blocked": false, "cost": 1,
	}
	b, _ := json.Marshal(rec)
	return string(b) + "\n"
}

// TestSecurityAssessModelAnswerCarriesProbes: the log records a model cites come
// back in the model answer, redacted, with how much of the log they are, and the
// finding carries Observer's evidence word and reason, never the agent's.
func TestSecurityAssessModelAnswerCarriesProbes(t *testing.T) {
	h := newRelaxHarness(t, "")
	lines := make([]string, 30)
	for i := range lines {
		lines[i] = "x := 1"
	}
	lines[11] = "func Login(w http.ResponseWriter, r *http.Request) {"
	writeModelTestFile(t, h.root, "cmd/api/main.go", strings.Join(lines, "\n")+"\n")
	id := modelTestRun
	if _, err := secassesssvc.PrepareRunDir(h.root, id); err != nil {
		t.Fatal(err)
	}
	target, _ := secassess.ParseTarget("http://localhost:3000/")
	files, _, err := secassesssvc.WriteProbeFiles(h.root, secassesssvc.ProbeInput{RunID: id, Target: target, Budget: 600, PaceRPS: 5})
	if err != nil {
		t.Fatal(err)
	}
	paths := secassess.ResultPaths(id)
	log := probeTestLine(1, 401, `{"error":"no"}`) + probeTestLine(2, 200, `{"token":"abc","password":"hunter2hunter2"}`) + probeTestLine(3, 200, `{"extra":1}`)
	writeModelTestFile(t, h.root, paths.ProbeLog, log)
	writeModelTestFile(t, h.root, paths.Model, probeTestPentest)
	run := secassesssvc.Run{
		ID: id, Kind: "pentest_local", Tool: "claude-code", ProjectRootHash: h.hash, ProjectName: "api", Handle: "H-pt", Seeded: true,
		Contract: string(secassess.ContractPentest), Phase: secassesssvc.PhaseStarted, Target: "http://localhost:3000/", TimeBoxMinutes: 45,
		Audit: string(secassess.AuditOff), Helper: secassess.HelperOn, HelperSHA: files.Helper, ConfigSHA: files.Config,
		EndedAt: time.Now().Add(-5 * time.Minute).UTC(),
	}
	if _, err := h.runs.Record(run, time.Now()); err != nil {
		t.Fatal(err)
	}
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate: %d %s", w.Code, w.Body)
	}
	code, m := h.model(id)
	if code != http.StatusOK || m.Record.Result.PT == nil || len(m.Record.Result.PT.Findings) != 1 {
		t.Fatalf("model: %d %+v", code, m.Record.Result.Report)
	}
	f := m.Record.Result.PT.Findings[0]
	if f.EvidenceState != secassess.EvidenceLogged || f.EvidenceReason != "" {
		t.Fatalf("evidence = %q (%q); report %+v", f.EvidenceState, f.EvidenceReason, m.Record.Result.Report.Evidence)
	}
	ev := m.Record.Result.Report.Evidence
	if ev == nil || ev.Helper != secassess.HelperIntact || ev.Log != secassess.LogFileOK || ev.Records != 3 || ev.Logged != 1 {
		t.Fatalf("evidence report = %+v", ev)
	}
	// Two records are cited; the third is in the log and in no finding.
	if len(m.Probes) != 2 || m.ProbeLog == nil || m.ProbeLog.Records != 3 || m.ProbeLog.Shown != 2 || m.ProbeLog.Truncated {
		t.Fatalf("probes %d, log %+v", len(m.Probes), m.ProbeLog)
	}
	if m.Probes[0].ID != "p1" || m.Probes[1].ID != "p2" || m.Probes[1].Status != 200 {
		t.Errorf("probes = %+v", m.Probes)
	}
	if strings.Contains(m.Probes[1].BodyExcerpt, "hunter2hunter2") {
		t.Errorf("a secret reached the answer: %q", m.Probes[1].BodyExcerpt)
	}
	if !m.Redaction.On || !strings.Contains(m.Probes[1].BodyExcerpt, "[REDACTED") {
		t.Errorf("redaction %+v, excerpt %q", m.Redaction, m.Probes[1].BodyExcerpt)
	}
	// A run whose helper was off reads No log, whatever sits in the folder.
	if _, _, err := h.runs.Mutate(id, func(r *secassesssvc.Run) error { r.Helper = secassess.HelperOff; return nil }); err != nil {
		t.Fatal(err)
	}
	if w := h.validate(id, false, true); w.Code != http.StatusOK {
		t.Fatalf("validate again: %d %s", w.Code, w.Body)
	}
	_, m = h.model(id)
	if f := m.Record.Result.PT.Findings[0]; f.EvidenceState != secassess.EvidenceUnlogged || f.EvidenceReason != secassess.ReasonHelperOff {
		t.Errorf("with the helper off the finding is %q (%q)", f.EvidenceState, f.EvidenceReason)
	}
}
