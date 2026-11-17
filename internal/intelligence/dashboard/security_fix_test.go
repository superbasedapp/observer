//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedFixFindings stores, in the test server's project: two open findings
// (a critical dependency and a high code finding), one suppressed one, and an
// open one in a project with no projects row. It returns the project hash and
// the open ids.
func seedFixFindings(t *testing.T, s *Server, root string) (string, []string) {
	t.Helper()
	st := store.New(s.db())
	hash := secposture.ProjectRootHash(root)
	ctx := context.Background()
	now := time.Now()
	add := func(key, rule string, cat policy.FindingCategory, sev policy.FindingSeverity, status policy.FindingStatus, project string) string {
		id, _, err := st.UpsertSecFinding(ctx, secfinding.Normalize(secfinding.Finding{
			LocalKey: key, Rule: secfinding.Rule{ID: rule}, Category: cat, Severity: sev,
			Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
			Project: secfinding.Project{RootHash: project}, Location: secfinding.Location{RelPath: "pkg/a.go", StartLine: 7},
			Message: "Known issue " + rule, FixHint: "Do the safe thing.", Status: status,
		}), now)
		if err != nil {
			t.Fatal(err)
		}
		if status != policy.FindingStatusOpen {
			if err := st.SetSecFindingStatus(ctx, id, status, "", now); err != nil {
				t.Fatal(err)
			}
		}
		return id
	}
	a := add("k1", "CVE-2026-73501", policy.FindingVulnerableDependency, policy.FindingSeverityCritical, policy.FindingStatusOpen, hash)
	b := add("k2", "go.sql-string-concat", policy.FindingCodeVuln, policy.FindingSeverityHigh, policy.FindingStatusOpen, hash)
	add("k3", "S-721", policy.FindingSecret, policy.FindingSeverityHigh, policy.FindingStatusSuppressed, hash)
	add("k4", "CVE-2026-1", policy.FindingVulnerableDependency, policy.FindingSeverityLow, policy.FindingStatusOpen, "nohash")
	return hash, []string{a, b}
}

func getFixPlan(t *testing.T, s *Server, query string) securityFixPlanJS {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSecurityFixPlan(w, httptest.NewRequest(http.MethodGet, "/api/security/fix/plan?"+query, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("plan %s: %d %s", query, w.Code, w.Body)
	}
	var p securityFixPlanJS
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSecurityFixPlan: the plan holds only open findings of known projects,
// one prompt per project built from the server's rows, and every launchable
// tool's seed.
func TestSecurityFixPlan(t *testing.T) {
	s, root := newTestServer(t)
	hash, ids := seedFixFindings(t, s, root)
	// The suppressed finding is dropped (status forced open) and the finding
	// of a project with no projects row has no folder to work in.
	p := getFixPlan(t, s, "status=")
	if p.ConfirmToken == "" {
		t.Error("no confirm token")
	}
	if p.Total != 3 || len(p.Projects) != 1 {
		t.Fatalf("plan = %+v", p)
	}
	pr := p.Projects[0]
	if pr.Hash != hash || pr.RootPath != root || !pr.OnDisk || pr.Findings != 2 || pr.Listed != 2 {
		t.Fatalf("project = %+v", pr)
	}
	for _, want := range []string{"CVE-2026-73501", "go.sql-string-concat", "pkg/a.go:7", "Do not suppress", "id: " + ids[0]} {
		if !strings.Contains(pr.Prompt, want) {
			t.Errorf("prompt lacks %q", want)
		}
	}
	if strings.Contains(pr.Prompt, "S-721") {
		t.Error("a suppressed finding reached the prompt")
	}
	if p.Seeds["claude-code"] != "leading_positional" || p.Seeds["hermes"] != "none" {
		t.Errorf("seeds = %v", p.Seeds)
	}

	one := getFixPlan(t, s, "finding="+ids[1])
	if one.Total != 1 || len(one.Projects) != 1 || one.Projects[0].Listed != 1 || strings.Contains(one.Projects[0].Prompt, "CVE-2026-73501") {
		t.Fatalf("single-finding plan = %+v", one)
	}
	if none := getFixPlan(t, s, "rule=nothing"); len(none.Projects) != 0 || none.Projects == nil {
		t.Fatalf("empty plan = %+v", none)
	}
}

func postFixLaunch(t *testing.T, s *Server, body map[string]any, confirm bool) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/security/fix/launch", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	if confirm {
		r.Header.Set(remoteConfirmHeader, "tok")
		r.AddCookie(&http.Cookie{Name: remoteConfirmCookie, Value: "tok"})
	}
	w := httptest.NewRecorder()
	s.handleSecurityFixLaunch(w, r)
	return w
}

// TestSecurityFixLaunch: a seeded tool gets the server-built prompt in the
// project's own folder (a client project_root is ignored), the attempt is
// recorded and reads cleared once its findings close; a tool with no seed
// starts bare and the answer carries the prompt to paste.
func TestSecurityFixLaunch(t *testing.T) {
	s, root := newTestServer(t)
	lm := &fakeLaunchManager{}
	s.opts.LaunchManager = lm
	hash, ids := seedFixFindings(t, s, root)
	query := ""

	w := postFixLaunch(t, s, map[string]any{"query": query, "project_root_hash": hash, "tool": "claude-code", "project_root": "/elsewhere"}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("launch: %d %s", w.Code, w.Body)
	}
	var out securityFixLaunchJS
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if !out.Seeded || out.Prompt != "" || out.AttemptID == "" || out.Token != "FRESH-abc" {
		t.Fatalf("response = %+v", out)
	}
	spec := lm.lastFreshSpec
	if spec.Tool != "claude-code" || spec.ProjectRoot != root || !strings.Contains(spec.TaskPrompt, "CVE-2026-73501") || spec.Shell {
		t.Fatalf("fresh spec = %+v", spec)
	}

	lm.lastFreshSpec = FreshLaunchSpec{}
	w = postFixLaunch(t, s, map[string]any{"finding": ids[1], "project_root_hash": hash, "tool": "hermes"}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("hermes launch: %d %s", w.Code, w.Body)
	}
	out = securityFixLaunchJS{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out.Seeded || !strings.Contains(out.Prompt, "go.sql-string-concat") || lm.lastFreshSpec.TaskPrompt != "" || lm.lastFreshSpec.Tool != "hermes" {
		t.Fatalf("hermes: response %+v spec %+v", out, lm.lastFreshSpec)
	}

	attempts := func() []securityFixAttemptJS {
		w := httptest.NewRecorder()
		s.handleSecurityFixAttempts(w, httptest.NewRequest(http.MethodGet, "/api/security/fix/attempts", nil))
		var body struct {
			Attempts []securityFixAttemptJS `json:"attempts"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.Attempts
	}
	got := attempts()
	if len(got) != 2 || got[0].Tool != "hermes" || got[1].Total != 2 || got[1].Open != 2 || got[1].Cleared {
		t.Fatalf("attempts = %+v", got)
	}
	st := store.New(s.db())
	for _, id := range ids {
		if _, err := st.CloseSecFindingNotReproduced(context.Background(), id, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	got = attempts()
	if !got[1].Cleared || got[1].Open != 0 || got[1].Findings[0].Status != string(policy.FindingStatusNotReproduced) {
		t.Fatalf("after rescan: %+v", got[1])
	}
}

// TestSecurityFixLaunchRefusals: one row per refusal, none reaching the
// launcher.
func TestSecurityFixLaunchRefusals(t *testing.T) {
	s, root := newTestServer(t)
	lm := &fakeLaunchManager{}
	s.opts.LaunchManager = lm
	hash, _ := seedFixFindings(t, s, root)
	cases := []struct {
		name    string
		body    map[string]any
		confirm bool
		code    int
	}{
		{"no confirm token", map[string]any{"project_root_hash": hash, "tool": "claude-code"}, false, http.StatusForbidden},
		{"project not in selection", map[string]any{"project_root_hash": "nohash", "tool": "claude-code"}, true, http.StatusConflict},
		{"gui kind", map[string]any{"project_root_hash": hash, "tool": "claude-code", "kind": "gui"}, true, http.StatusBadRequest},
		{"plain shell", map[string]any{"project_root_hash": hash, "tool": "shell"}, true, http.StatusBadRequest},
		{"unknown tool", map[string]any{"project_root_hash": hash, "tool": "nope"}, true, http.StatusBadRequest},
		{"bad query", map[string]any{"query": "%zz", "project_root_hash": hash, "tool": "claude-code"}, true, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lm.lastFreshSpec = FreshLaunchSpec{}
			w := postFixLaunch(t, s, tc.body, tc.confirm)
			if w.Code != tc.code {
				t.Fatalf("code %d, want %d (%s)", w.Code, tc.code, w.Body)
			}
			if lm.lastFreshSpec.Tool != "" {
				t.Fatalf("launcher reached: %+v", lm.lastFreshSpec)
			}
		})
	}
}
