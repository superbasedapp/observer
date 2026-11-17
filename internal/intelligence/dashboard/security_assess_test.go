//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// assessProbe is a sandbox probe a pen test can use: bwrap, local, not beta,
// the proxy_only tier live and full capture on it, the live source, and the
// named tools sandboxable.
func assessProbe(tier string, tools ...string) SandboxAvailability {
	av := SandboxAvailability{
		Available: true, Verdict: "available", Backend: "bwrap", Egress: tier,
		Sources: []SandboxSourceAvail{{ID: "live", Available: true}, {ID: "clone-local", Available: true}},
		Tools:   map[string]SandboxToolAvail{},
		Backends: []SandboxBackendAvail{{
			ID: "bwrap", Label: "Bubblewrap", Location: "local", Available: true, Maturity: "shipped",
			Egress: []string{"internet", "proxy_only", "none", "host"}, CaptureByTier: map[string]string{"proxy_only": "full (relay)", "internet": "full (gateway-guarded)"},
		}},
	}
	for _, t := range tools {
		av.Tools[t] = SandboxToolAvail{Available: true}
	}
	return av
}

func assessTestServer(t *testing.T, av *SandboxAvailability) (*Server, *fakeLaunchManager, string) {
	t.Helper()
	s, root := newTestServer(t)
	lm := &fakeLaunchManager{}
	s.opts.LaunchManager = lm
	s.opts.ProxyPort = 8820
	// cmd injects internal/sandbox's own answer (pinned in cmd/observer); 8820 is
	// not the sandbox gateway's default port, so the gateway sits on 3128.
	s.opts.SandboxGatewayPort = func(int) int { return 3128 }
	if av != nil {
		s.opts.SandboxProber = &fakeSandboxProber{avail: *av}
	}
	return s, lm, root
}

func getAssessJSON(t *testing.T, h http.HandlerFunc, url string, out any) int {
	t.Helper()
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest(http.MethodGet, url, nil))
	if out != nil && w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: %v (%s)", url, err, w.Body)
		}
	}
	return w.Code
}

func postAssess(t *testing.T, h http.HandlerFunc, path string, body map[string]any, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if confirm {
		r.Header.Set(remoteConfirmHeader, "tok")
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: "tok"})
	}
	w := httptest.NewRecorder()
	h(w, r)
	return w
}

func TestSecurityAssessList(t *testing.T) {
	good := assessProbe("proxy_only", "claude-code")
	s, _, _ := assessTestServer(t, &good)
	var out securityAssessListJS
	if code := getAssessJSON(t, s.handleSecurityAssess, "/api/security/assessments", &out); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if len(out.Kinds) != 7 || !out.Launch || len(out.Runs) != 0 || out.ImportAvailable {
		t.Fatalf("list = %+v", out)
	}
	byID := map[string]securityAssessKindJS{}
	for _, k := range out.Kinds {
		byID[k.ID] = k
	}
	if k := byID["rasp"]; k.Launchable || k.Reason == "" || k.Pointer == "" {
		t.Errorf("rasp = %+v", k)
	}
	if k := byID["pentest_local"]; k.Blocked != "" || k.Sandbox != "required" || k.Target != "required" {
		t.Errorf("pentest on a good machine = %+v", k)
	}
	// No probe at all: a sandbox-required kind says why it cannot start; the
	// read-only kinds do not.
	bare, _, _ := assessTestServer(t, nil)
	out = securityAssessListJS{}
	getAssessJSON(t, bare.handleSecurityAssess, "/api/security/assessments", &out)
	for _, k := range out.Kinds {
		switch k.ID {
		case "pentest_local", "red_team_local", "pentest_retest":
			if k.BlockedCode != secassess.CodeSandboxUnavailable || k.Blocked == "" {
				t.Errorf("%s without a probe: %+v", k.ID, k)
			}
		default:
			if k.Blocked != "" {
				t.Errorf("%s blocked: %+v", k.ID, k)
			}
		}
	}
	// The internet tier is refused with the tier's own sentence.
	open := assessProbe("internet", "claude-code")
	s2, _, _ := assessTestServer(t, &open)
	out = securityAssessListJS{}
	getAssessJSON(t, s2.handleSecurityAssess, "/api/security/assessments", &out)
	for _, k := range out.Kinds {
		if k.ID == "red_team_local" && k.BlockedCode != secassess.CodeTierNotConfined {
			t.Errorf("red team on the internet tier: %+v", k)
		}
	}
	if code := getAssessJSON(t, func(w http.ResponseWriter, r *http.Request) {
		s.handleSecurityAssess(w, httptest.NewRequest(http.MethodPost, "/x", nil))
	}, "/x", nil); code != http.StatusMethodNotAllowed {
		t.Errorf("POST list: %d", code)
	}
}

func TestSecurityAssessPlan(t *testing.T) {
	good := assessProbe("proxy_only", "claude-code")
	s, _, root := assessTestServer(t, &good)
	hash := secposture.ProjectRootHash(root)
	plan := func(q string) (securityAssessPlanJS, int) {
		var p securityAssessPlanJS
		code := getAssessJSON(t, s.handleSecurityAssessPlan, "/api/security/assessments/plan?"+q, &p)
		return p, code
	}
	t.Run("a threat model plan has a run id and a prompt that names its files", func(t *testing.T) {
		p, code := plan("kind=threat_model&project=" + hash)
		if code != http.StatusOK || !p.OK || p.ConfirmToken == "" || !secassess.ValidRunID(p.RunID) || p.Project.RootPath != root || !p.Project.OnDisk {
			t.Fatalf("plan = %+v (%d)", p, code)
		}
		if !strings.Contains(p.Prompt, ".observer/assessments/"+p.RunID+"/") || len(p.Boundary) < 5 || p.Seeds["claude-code"] != "leading_positional" {
			t.Errorf("prompt or boundary: %+v", p)
		}
		if p.AllowedTools != nil || p.Residual != "" {
			t.Errorf("an unconfined kind carries a tool filter or a residual: %+v", p)
		}
	})
	t.Run("rasp has a reason and no prompt", func(t *testing.T) {
		p, code := plan("kind=rasp&project=" + hash)
		if code != http.StatusOK || p.OK || p.Code != secassess.CodeNotLaunchable || p.Prompt != "" || p.Kind.Pointer == "" {
			t.Fatalf("plan = %+v (%d)", p, code)
		}
	})
	t.Run("a pen test plan lists the launch.json candidates and waits for a target", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, ".claude", "launch.json"), []byte(`{"configurations":[{"name":"web","port":3000}]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		p, _ := plan("kind=pentest_local&project=" + hash)
		if !p.OK || p.TargetTyped || len(p.Candidates) != 1 || p.Candidates[0].URL != "http://localhost:3000/" || p.Prompt != "" {
			t.Fatalf("untyped plan = %+v", p)
		}
		if len(p.AllowedTools) != 1 || p.AllowedTools[0] != "claude-code" || p.Residual == "" || p.Backend != "bwrap" || p.Tier != "proxy_only" {
			t.Errorf("confined facts = %+v", p)
		}
		p, _ = plan("kind=pentest_local&project=" + hash + "&target=http://127.0.0.1:5173/app")
		if !p.OK || !p.TargetTyped || p.Target != "http://127.0.0.1:5173/app" || !strings.Contains(p.Prompt, "http://127.0.0.1:5173/app") {
			t.Fatalf("typed plan = %+v", p)
		}
		p, _ = plan("kind=pentest_local&project=" + hash + "&target=http://example.com:80/")
		if p.OK || p.Code != secassess.CodeTargetRequired || p.Prompt != "" {
			t.Fatalf("remote target plan = %+v", p)
		}
	})
	t.Run("the proxy port is reserved", func(t *testing.T) {
		p, _ := plan("kind=red_team_local&project=" + hash + "&target=http://localhost:8820/")
		if p.OK || p.Code != secassess.CodeTargetReservedPort {
			t.Fatalf("plan = %+v", p)
		}
	})
	t.Run("no agent can run a confined kind", func(t *testing.T) {
		none := assessProbe("proxy_only") // no tool is sandboxable
		s2, _, root2 := assessTestServer(t, &none)
		var p securityAssessPlanJS
		getAssessJSON(t, s2.handleSecurityAssessPlan, "/api/security/assessments/plan?kind=pentest_local&project="+secposture.ProjectRootHash(root2)+"&target=http://localhost:3000/", &p)
		if p.OK || p.Rule != "E8b" || len(p.AllowedTools) != 0 || p.AllowedTools == nil {
			t.Fatalf("plan = %+v", p)
		}
	})
	t.Run("bad requests", func(t *testing.T) {
		if _, code := plan("kind=nope&project=" + hash); code != http.StatusBadRequest {
			t.Errorf("unknown kind: %d", code)
		}
		if _, code := plan("kind=threat_model&project=nohash"); code != http.StatusNotFound {
			t.Errorf("unknown project: %d", code)
		}
	})
}

func TestSecurityAssessLaunch(t *testing.T) {
	good := assessProbe("proxy_only", "claude-code")
	s, lm, root := assessTestServer(t, &good)
	hash := secposture.ProjectRootHash(root)
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	launch := func(body map[string]any, confirm bool) *httptest.ResponseRecorder {
		lm.lastFreshSpec = FreshLaunchSpec{}
		return postAssess(t, s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, confirm)
	}
	t.Run("a threat model starts in the project's folder with the server's prompt", func(t *testing.T) {
		id := secassesssvc.NewRunID()
		w := launch(map[string]any{"assessment": "threat_model", "project_root_hash": hash, "run_id": id, "tool": "claude-code", "project_root": "/elsewhere"}, true)
		if w.Code != http.StatusOK {
			t.Fatalf("launch: %d %s", w.Code, w.Body)
		}
		var out securityAssessLaunchJS
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		spec := lm.lastFreshSpec
		if !out.Seeded || out.Prompt != "" || out.RunID != id || out.Token != "FRESH-abc" {
			t.Fatalf("response = %+v", out)
		}
		if spec.Tool != "claude-code" || spec.ProjectRoot != root || spec.Sandbox || !strings.Contains(spec.TaskPrompt, "Directory: .observer/assessments/"+id+"/") {
			t.Fatalf("spec = %+v", spec)
		}
		run, ok := runs.Get(id)
		if !ok || run.Kind != "threat_model" || run.Handle != "FRESH-abc" || run.Sandboxed || run.Tool != "claude-code" || run.ConfirmedAt.IsZero() {
			t.Fatalf("run = %+v %v", run, ok)
		}
	})
	t.Run("an agent that cannot take a first prompt gets it to paste", func(t *testing.T) {
		id := secassesssvc.NewRunID()
		w := launch(map[string]any{"assessment": "cspm_readonly", "project_root_hash": hash, "run_id": id, "tool": "hermes"}, true)
		if w.Code != http.StatusOK {
			t.Fatalf("launch: %d %s", w.Code, w.Body)
		}
		var out securityAssessLaunchJS
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if out.Seeded || !strings.Contains(out.Prompt, "commands.txt") || lm.lastFreshSpec.TaskPrompt != "" || lm.lastFreshSpec.Tool != "hermes" {
			t.Fatalf("response %+v spec %+v", out, lm.lastFreshSpec)
		}
	})
	t.Run("a pen test is forced into the live sandbox on the grounded backend", func(t *testing.T) {
		id := secassesssvc.NewRunID()
		w := launch(map[string]any{
			"assessment": "pentest_local", "project_root_hash": hash, "run_id": id, "tool": "claude-code", "sandbox": true,
			"target": "http://localhost:3000", "confirm_target": "http://localhost:3000/", "workspace_source": "live",
		}, true)
		if w.Code != http.StatusOK {
			t.Fatalf("launch: %d %s", w.Code, w.Body)
		}
		spec := lm.lastFreshSpec
		if !spec.Sandbox || spec.WorkspaceSource != "live" || spec.Backend != "bwrap" || spec.ProjectRoot != root || !strings.Contains(spec.TaskPrompt, "http://localhost:3000/") {
			t.Fatalf("spec = %+v", spec)
		}
		run, _ := runs.Get(id)
		if !run.Sandboxed || run.Backend != "bwrap" || run.Tier != "proxy_only" || run.Target != "http://localhost:3000/" {
			t.Fatalf("run = %+v", run)
		}
	})
	refusals := []struct {
		name string
		body map[string]any
		conf bool
		code int
		rule string
	}{
		{"no confirm token", map[string]any{"assessment": "threat_model", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code"}, false, http.StatusForbidden, ""},
		{"gui launch shape", map[string]any{"kind": "gui", "assessment": "threat_model", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code"}, true, http.StatusBadRequest, ""},
		{"plain shell", map[string]any{"assessment": "threat_model", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "shell"}, true, http.StatusBadRequest, ""},
		{"unknown tool", map[string]any{"assessment": "threat_model", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "nope"}, true, http.StatusBadRequest, ""},
		{"unknown kind", map[string]any{"assessment": "nope", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code"}, true, http.StatusBadRequest, ""},
		{"rasp has no launch", map[string]any{"assessment": "rasp", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code"}, true, http.StatusConflict, "E1"},
		{"bad run id", map[string]any{"assessment": "threat_model", "project_root_hash": hash, "run_id": "../../x", "tool": "claude-code"}, true, http.StatusBadRequest, ""},
		{"unknown project", map[string]any{"assessment": "threat_model", "project_root_hash": "nohash", "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code"}, true, http.StatusNotFound, ""},
		{"pen test without a target", map[string]any{"assessment": "pentest_local", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code", "sandbox": true}, true, http.StatusConflict, "E3"},
		{"pen test of a remote host", map[string]any{"assessment": "red_team_local", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code", "sandbox": true, "target": "http://example.com:80/", "confirm_target": "http://example.com:80/"}, true, http.StatusConflict, "E3"},
		{"pen test with a different confirmation", map[string]any{"assessment": "pentest_local", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code", "sandbox": true, "target": "http://localhost:3000/", "confirm_target": "http://localhost:3001/"}, true, http.StatusConflict, "E4"},
		{"pen test on a clone workspace", map[string]any{"assessment": "pentest_local", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code", "sandbox": true, "target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/", "workspace_source": "clone-local"}, true, http.StatusConflict, "E10"},
		{"pen test with an agent that cannot be sandboxed", map[string]any{"assessment": "pentest_local", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "hermes", "sandbox": true, "target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/"}, true, http.StatusConflict, "E7"},
		{"pen test on a backend that is not grounded", map[string]any{"assessment": "pentest_local", "project_root_hash": hash, "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code", "sandbox": true, "backend": "oci-runc", "target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/"}, true, http.StatusConflict, "E9"},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			w := launch(tc.body, tc.conf)
			if w.Code != tc.code {
				t.Fatalf("code %d, want %d (%s)", w.Code, tc.code, w.Body)
			}
			if tc.rule != "" {
				var body map[string]string
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				if body["rule"] != tc.rule || body["error"] == "" || body["code"] == "" {
					t.Fatalf("refusal = %v", body)
				}
			}
			if lm.lastFreshSpec.Tool != "" {
				t.Fatalf("the launcher was reached: %+v", lm.lastFreshSpec)
			}
		})
	}
	t.Run("a pen test is refused on the internet tier and on the host tier", func(t *testing.T) {
		for _, tier := range []string{"internet", "host", "none", ""} {
			av := assessProbe(tier, "claude-code")
			s2, lm2, root2 := assessTestServer(t, &av)
			w := postAssess(t, s2.handleSecurityAssessLaunch, "/api/security/assessments/launch", map[string]any{
				"assessment": "pentest_local", "project_root_hash": secposture.ProjectRootHash(root2), "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code", "sandbox": true,
				"target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/",
			}, true)
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), secassess.CodeTierNotConfined) || lm2.lastFreshSpec.Tool != "" {
				t.Errorf("tier %q: %d %s (launched %+v)", tier, w.Code, w.Body, lm2.lastFreshSpec)
			}
		}
	})
	t.Run("a pen test is refused with no sandbox probe, and nothing is launched", func(t *testing.T) {
		s2, lm2, root2 := assessTestServer(t, nil)
		w := postAssess(t, s2.handleSecurityAssessLaunch, "/api/security/assessments/launch", map[string]any{
			"assessment": "pentest_local", "project_root_hash": secposture.ProjectRootHash(root2), "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code", "sandbox": true,
			"target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/",
		}, true)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), secassess.CodeSandboxUnavailable) || lm2.lastFreshSpec.Tool != "" {
			t.Errorf("%d %s (launched %+v)", w.Code, w.Body, lm2.lastFreshSpec)
		}
	})
	t.Run("an agent without a proxy route is refused for a confined kind", func(t *testing.T) {
		tool := ""
		for _, c := range launchableTools() {
			if cap, ok := integration.For(c); ok && cap.Proxy == nil {
				tool = c
				break
			}
		}
		if tool == "" {
			t.Skip("every launchable agent is proxy-routed")
		}
		av := assessProbe("proxy_only", tool)
		s2, lm2, root2 := assessTestServer(t, &av)
		w := postAssess(t, s2.handleSecurityAssessLaunch, "/api/security/assessments/launch", map[string]any{
			"assessment": "pentest_local", "project_root_hash": secposture.ProjectRootHash(root2), "run_id": "3fa9c2d17b0e4a56", "tool": tool, "sandbox": true,
			"target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/",
		}, true)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), secassess.CodeToolNotProxyRouted) || lm2.lastFreshSpec.Tool != "" {
			t.Errorf("%s: %d %s", tool, w.Code, w.Body)
		}
	})
	t.Run("a run id is used once", func(t *testing.T) {
		id := secassesssvc.NewRunID()
		body := map[string]any{"assessment": "threat_model", "project_root_hash": hash, "run_id": id, "tool": "claude-code"}
		if w := launch(body, true); w.Code != http.StatusOK {
			t.Fatalf("first: %d %s", w.Code, w.Body)
		}
		if w := launch(body, true); w.Code != http.StatusConflict || lm.lastFreshSpec.Tool != "" {
			t.Fatalf("second: %d %s", w.Code, w.Body)
		}
	})
	t.Run("the org's terminal gate reads the sandbox flag the launch will carry", func(t *testing.T) {
		var seen []bool
		s.opts.TerminalFeatureGate = func(sandbox bool) (bool, string) {
			seen = append(seen, sandbox)
			return false, "terminals are off for this machine"
		}
		defer func() { s.opts.TerminalFeatureGate = nil }()
		w := launch(map[string]any{
			"assessment": "pentest_local", "project_root_hash": hash, "run_id": secassesssvc.NewRunID(), "tool": "claude-code", "sandbox": true,
			"target": "http://localhost:3000/", "confirm_target": "http://localhost:3000/",
		}, true)
		if w.Code != http.StatusForbidden || len(seen) != 1 || !seen[0] || lm.lastFreshSpec.Tool != "" {
			t.Fatalf("%d %s seen %v", w.Code, w.Body, seen)
		}
	})
	t.Run("no launch manager is a 503", func(t *testing.T) {
		s2, _, root2 := assessTestServer(t, &good)
		s2.opts.LaunchManager = nil
		w := postAssess(t, s2.handleSecurityAssessLaunch, "/api/security/assessments/launch", map[string]any{
			"assessment": "threat_model", "project_root_hash": secposture.ProjectRootHash(root2), "run_id": "3fa9c2d17b0e4a56", "tool": "claude-code",
		}, true)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%d", w.Code)
		}
	})
	t.Run("a launch creates no guard approval and no other state", func(t *testing.T) {
		// The module's only writes are the run record and the terminal the
		// launch manager starts; the guard's approvals are not reachable from
		// it (the import pin in secassesssvc forbids the packages).
		var rows int
		if err := s.db().QueryRowContext(context.Background(), `SELECT COUNT(*) FROM guard_approvals`).Scan(&rows); err == nil && rows != 0 {
			t.Errorf("guard_approvals holds %d rows", rows)
		}
	})
}

func TestSecurityAssessReportAndImport(t *testing.T) {
	good := assessProbe("proxy_only", "claude-code")
	s, _, root := assessTestServer(t, &good)
	hash := secposture.ProjectRootHash(root)
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	id := secassesssvc.NewRunID()
	if _, err := runs.Record(secassesssvc.Run{ID: id, Kind: "cspm_readonly", Tool: "claude-code", ProjectRootHash: hash, ProjectName: "app"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	report := func(run string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.handleSecurityAssessReport(w, httptest.NewRequest(http.MethodGet, "/api/security/assessments/report?run="+run, nil))
		return w
	}
	if w := report(id); w.Code != http.StatusNotFound {
		t.Fatalf("before the file: %d", w.Code)
	}
	if w := report("0000000000000000"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown run: %d", w.Code)
	}
	dir := filepath.Join(root, ".observer", "assessments", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("report.md", "# Report\n<script>alert(1)</script>\n")
	w := report(id)
	if w.Code != http.StatusOK || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/plain") || !strings.Contains(w.Body.String(), "<script>") {
		t.Fatalf("report: %d %q %s", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
	// The list shows the run with its derived state and the cloud counts.
	write("commands.txt", "aws ec2 describe-instances\naws ec2 terminate-instances --instance-ids i\n")
	var list securityAssessListJS
	getAssessJSON(t, s.handleSecurityAssess, "/api/security/assessments", &list)
	if len(list.Runs) != 1 || list.Runs[0].State != "report_ready" || !list.Runs[0].Files.Report || list.Runs[0].Cloud == nil || !list.Runs[0].BoundaryCrossed {
		t.Fatalf("runs = %+v", list.Runs)
	}

	// Import: the seam is the existing SARIF import; the selection rule is the
	// upload route's own.
	var seamTool string
	var seamData []byte
	seam := &dashapi.SARIFImport{
		Tools: []dashapi.SARIFImportTool{{ID: "other", Label: "Another tool"}}, MaxBytes: 1 << 20,
		Import: func(_ context.Context, r, tool string, data []byte) (any, error) {
			if r != root {
				return nil, fmt.Errorf("root %q", r)
			}
			if strings.Contains(string(data), "refuseme") {
				return nil, fmt.Errorf("%w: refused", dashapi.ErrSARIFImportInput)
			}
			seamTool, seamData = tool, data
			return map[string]any{"findings": 2, "new": 2, "with_lineage": 1, "refused": map[string]int{"no_location": 1}}, nil
		},
	}
	doImport := func(run string) *httptest.ResponseRecorder {
		return postAssess(t, s.handleSecurityAssessImport, "/api/security/assessments/import", map[string]any{"run": run}, true)
	}
	write("findings.sarif", `{"version":"2.1.0","runs":[{"results":[{"ruleId":"open-bucket","level":"high","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"infra/main.tf"},"region":{"startLine":4}}}]}]}]}`)

	s.opts.SARIFImport = seam
	s.opts.SecuritySelected = sarifRule("security.code")
	s.comps.svc = sarifSnapSvc{snap: componentstate.Snapshot{Configured: true}}
	var imp struct{ Run securityAssessRunJS }
	w = doImport(id)
	_ = json.Unmarshal(w.Body.Bytes(), &imp)
	if w.Code != http.StatusOK || imp.Run.State != "import_unavailable" || imp.Run.Import == nil || imp.Run.Import.Reason != secassesssvc.ReasonNotSelected || seamTool != "" {
		t.Fatalf("component not selected: %d %s", w.Code, w.Body)
	}

	s.opts.SecuritySelected = sarifRule("security.code", "security.scan.sarif-import")
	w = doImport(id)
	imp = struct{ Run securityAssessRunJS }{}
	_ = json.Unmarshal(w.Body.Bytes(), &imp)
	if w.Code != http.StatusOK || imp.Run.State != "imported" || imp.Run.Import == nil || imp.Run.Import.Findings != 2 || imp.Run.Import.New != 2 || imp.Run.Import.WithLineage != 1 || imp.Run.Import.Refused["no_location"] != 1 {
		t.Fatalf("import: %d %s", w.Code, w.Body)
	}
	if seamTool != "other" || !strings.Contains(string(seamData), "assess.cspm."+id+".open-bucket") || strings.Contains(string(seamData), `"x"`) {
		t.Fatalf("the seam got tool %q data %s", seamTool, seamData)
	}
	if r, _ := runs.Get(id); r.Import == nil || r.Import.Outcome != "imported" {
		t.Errorf("the outcome was not recorded: %+v", r.Import)
	}

	// A file the import refuses is a recorded failure, not a crash.
	write("findings.sarif", `{"version":"2.1.0","runs":[{"results":[{"ruleId":"refuseme","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"}}}]}]}]}`)
	w = doImport(id)
	imp = struct{ Run securityAssessRunJS }{}
	_ = json.Unmarshal(w.Body.Bytes(), &imp)
	if w.Code != http.StatusOK || imp.Run.State != "import_failed" || imp.Run.Import.Reason != secassesssvc.ReasonImportRefused {
		t.Fatalf("refused import: %d %s", w.Code, w.Body)
	}

	for name, tc := range map[string]struct {
		run  string
		code int
	}{"unknown run": {"0000000000000000", http.StatusNotFound}} {
		if w := doImport(tc.run); w.Code != tc.code {
			t.Errorf("%s: %d", name, w.Code)
		}
	}
	// No findings file yet is a conflict; a missing token is refused.
	id2 := secassesssvc.NewRunID()
	if _, err := runs.Record(secassesssvc.Run{ID: id2, Kind: "threat_model", ProjectRootHash: hash}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if w := doImport(id2); w.Code != http.StatusConflict {
		t.Errorf("no findings file: %d", w.Code)
	}
	if w := postAssess(t, s.handleSecurityAssessImport, "/x", map[string]any{"run": id}, false); w.Code != http.StatusForbidden {
		t.Errorf("no token: %d", w.Code)
	}
}

// TestSecurityAssessReportRefusesALink: a report that is a link is not read.
func TestSecurityAssessReportRefusesALink(t *testing.T) {
	good := assessProbe("proxy_only", "claude-code")
	s, _, root := assessTestServer(t, &good)
	id := secassesssvc.NewRunID()
	if _, err := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath)).Record(secassesssvc.Run{ID: id, Kind: "threat_model", ProjectRootHash: secposture.ProjectRootHash(root)}, time.Now()); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("TOP SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, ".observer", "assessments", id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "report.md")); err != nil {
		t.Skipf("cannot create a symlink here: %v", err)
	}
	w := httptest.NewRecorder()
	s.handleSecurityAssessReport(w, httptest.NewRequest(http.MethodGet, "/api/security/assessments/report?run="+id, nil))
	if w.Code != http.StatusUnprocessableEntity || strings.Contains(w.Body.String(), "TOP SECRET") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// TestSecurityAssessSeamErrors: the seam adapter maps the import's own input
// refusal and keeps a node error distinct.
func TestSecurityAssessSeamErrors(t *testing.T) {
	if securityAssessSeam(nil) != nil || securityAssessSeam(&dashapi.SARIFImport{}) != nil {
		t.Error("a missing seam must adapt to nil")
	}
	seam := securityAssessSeam(&dashapi.SARIFImport{Import: func(context.Context, string, string, []byte) (any, error) {
		return nil, dashapi.ErrSARIFImportInput
	}})
	if _, err := seam(context.Background(), "/r", nil); !errors.Is(err, secassesssvc.ErrInputRefused) {
		t.Errorf("input refusal: %v", err)
	}
}
