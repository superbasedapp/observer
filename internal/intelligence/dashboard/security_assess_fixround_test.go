//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The lane A review fixes (W3 and W4 reviews, 2026-11-14) that live in the
// dashboard: the refuse setting fails closed, the digest's list is paged and
// leaves out what it must, the launch row and the run carry the environment-files
// mode in force, the preparation steps are opt-in, and the earlier run's words
// are true.

// fakeFindings is a findings source whose answers a test scripts.
type fakeFindings struct {
	secrets    [][]secfinding.Finding // one slice per page of the secret query
	open       [][]secfinding.Finding // one slice per page of the severity-ordered query
	groups     []store.SecFindingGroup
	listErr    error
	groupErr   error
	scanErr    error
	last       time.Time
	pagesAsked int
	endless    bool // every secret page is full of source-file findings
}

func (f *fakeFindings) ListSecFindings(_ context.Context, q store.SecFindingFilter) ([]secfinding.Finding, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	page := 0
	if q.Limit > 0 {
		page = q.Offset / q.Limit
	}
	f.pagesAsked++
	secret := len(q.Categories) == 1 && q.Categories[0] == string(policy.FindingSecret)
	if secret {
		if f.endless {
			rows := make([]secfinding.Finding, q.Limit)
			for i := range rows {
				rows[i] = finding("S-721", fmt.Sprintf("src/f%d.go", page*q.Limit+i), 1)
			}
			return rows, nil
		}
		if page < len(f.secrets) {
			return f.secrets[page], nil
		}
		return nil, nil
	}
	if page < len(f.open) {
		return f.open[page], nil
	}
	return nil, nil
}

func (f *fakeFindings) SecFindingGroups(_ context.Context, _ store.SecFindingFilter, q store.SecGroupQuery) (store.SecFindingGroupsPage, error) {
	if f.groupErr != nil {
		return store.SecFindingGroupsPage{}, f.groupErr
	}
	if q.Offset > 0 {
		return store.SecFindingGroupsPage{}, nil
	}
	return store.SecFindingGroupsPage{Groups: f.groups}, nil
}

func (f *fakeFindings) SecLastScan(context.Context, string) (time.Time, error) {
	return f.last, f.scanErr
}

func finding(rule, rel string, line int) secfinding.Finding {
	var x secfinding.Finding
	x.Rule.ID, x.Location.RelPath, x.Location.StartLine = rule, rel, line
	return x
}

func fullPage(n int, mk func(i int) secfinding.Finding) []secfinding.Finding {
	rows := make([]secfinding.Finding, n)
	for i := range rows {
		rows[i] = mk(i)
	}
	return rows
}

// TestSecurityAssessSecretStateFailsClosed: one row per way the findings store
// can fail to answer, and per way it answers.
func TestSecurityAssessSecretStateFailsClosed(t *testing.T) {
	boom := errors.New("database is locked")
	scanned := time.Date(2026, 11, 12, 9, 30, 0, 0, time.UTC)
	cases := []struct {
		name       string
		src        securityAssessFindingsSource
		hash       string
		openSecret bool
		unreadable bool
		scan       string
		last       string
	}{
		{"no store", nil, "h", false, true, "", ""},
		{"no project hash", &fakeFindings{}, "", false, true, "", ""},
		{"a read error", &fakeFindings{listErr: boom}, "h", false, true, "", ""},
		{"a secret in .env", &fakeFindings{secrets: [][]secfinding.Finding{{finding("S-721", ".env", 1)}}, last: scanned}, "h", true, false, secassess.ScanDone, "2026-11-12"},
		{"a secret in prod.env (the plan counts it too)", &fakeFindings{secrets: [][]secfinding.Finding{{finding("S-721", "config/prod.env", 3)}}, last: scanned}, "h", true, false, secassess.ScanDone, "2026-11-12"},
		{"a secret in a service account file", &fakeFindings{secrets: [][]secfinding.Finding{{finding("S-721", "deploy/service-account.json", 1)}}, last: scanned}, "h", true, false, secassess.ScanDone, "2026-11-12"},
		{"a secret in .env.example (a real key pasted into the example)", &fakeFindings{secrets: [][]secfinding.Finding{{finding("S-721", ".env.example", 1)}}}, "h", true, false, secassess.ScanNever, ""},
		{"a secret in source only", &fakeFindings{secrets: [][]secfinding.Finding{{finding("S-721", "src/main.go", 1)}}, last: scanned}, "h", false, false, secassess.ScanDone, "2026-11-12"},
		{"nothing open, never scanned", &fakeFindings{}, "h", false, false, secassess.ScanNever, ""},
		{"nothing open, scanned", &fakeFindings{last: scanned}, "h", false, false, secassess.ScanDone, "2026-11-12"},
		{"the scan time cannot be read", &fakeFindings{scanErr: boom}, "h", false, true, "", ""},
		{"an env file's secret past the 500th row is found (no window)", &fakeFindings{
			secrets: [][]secfinding.Finding{
				fullPage(securityAssessSecretsPage, func(i int) secfinding.Finding { return finding("S-721", fmt.Sprintf("src/f%d.go", i), 1) }),
				{finding("S-721", "api/.env.production", 2)},
			}, last: scanned,
		}, "h", true, false, secassess.ScanDone, "2026-11-12"},
		{"more rows than the bounded read covers, none of them an env file: not 'none'", &fakeFindings{endless: true, last: scanned}, "h", false, true, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := securityAssessReadSecretState(context.Background(), c.src, c.hash)
			if got.OpenSecret != c.openSecret || got.Unreadable != c.unreadable || got.Scan != c.scan || got.LastScan != c.last {
				t.Fatalf("state = %+v, want open %v unreadable %v scan %q last %q", got, c.openSecret, c.unreadable, c.scan, c.last)
			}
		})
	}
}

// TestSecurityAssessSecretStateTruncatedReadIsBounded: the bounded read stops at
// its page count (it does not loop for ever on a store that never ends).
func TestSecurityAssessSecretStateTruncatedReadIsBounded(t *testing.T) {
	f := &fakeFindings{endless: true}
	_ = securityAssessReadSecretState(context.Background(), f, "h")
	if f.pagesAsked != securityAssessSecretsPages {
		t.Fatalf("asked %d pages, want %d", f.pagesAsked, securityAssessSecretsPages)
	}
}

// TestSecurityAssessOpenList: the digest's list is paged (the module's own
// findings fill the first page and do not hide the real ones), leaves out
// secrets and findings in environment or key files, and counts the whole.
func TestSecurityAssessOpenList(t *testing.T) {
	own := func(i int) secfinding.Finding {
		return finding("assess.threat_model.x", fmt.Sprintf("src/a%d.go", i), 1)
	}
	real := func(i int) secfinding.Finding { return finding("G101", fmt.Sprintf("src/r%d.go", i), i+1) }
	t.Run("own findings fill the first page and the real ones follow", func(t *testing.T) {
		f := &fakeFindings{
			open: [][]secfinding.Finding{
				fullPage(securityAssessFindingsPage, own),
				append(fullPage(30, real), finding("G102", "deploy/prod.env", 4)),
			},
			groups: []store.SecFindingGroup{{RuleID: "assess.threat_model.x", Count: 200}, {RuleID: "other/assess.pentest.y", Count: 7}, {RuleID: "G101", Count: 30}, {RuleID: "G102", Count: 1}},
		}
		got := securityAssessReadOpenList(context.Background(), f, "h")
		if len(got.Refs) != securityAssessMaxGroundFindings || got.Refs[0].RuleID != "G101" {
			t.Fatalf("refs = %d, first %+v", len(got.Refs), got.Refs[0])
		}
		if got.Total != 31 {
			t.Fatalf("total = %d, want 31 (the module's own findings are not counted)", got.Total)
		}
	})
	t.Run("a finding in an environment file is not listed (its path is the secret's address)", func(t *testing.T) {
		f := &fakeFindings{open: [][]secfinding.Finding{{finding("G102", "deploy/prod.env", 4), finding("G103", "keys/server.pem", 1), finding("G104", "src/ok.go", 9)}}, groups: []store.SecFindingGroup{{RuleID: "G104", Count: 1}}}
		got := securityAssessReadOpenList(context.Background(), f, "h")
		if len(got.Refs) != 1 || got.Refs[0].Path != "src/ok.go" {
			t.Fatalf("refs = %+v", got.Refs)
		}
	})
	t.Run("the secret category is not read at all", func(t *testing.T) {
		cats := securityAssessNonSecretCategories()
		if len(cats) == 0 {
			t.Fatal("no categories")
		}
		for _, c := range cats {
			if c == string(policy.FindingSecret) {
				t.Fatal("secret is among the digest's categories")
			}
		}
	})
	t.Run("an error gives an empty list, never a wrong one", func(t *testing.T) {
		for _, f := range []*fakeFindings{{listErr: errors.New("x")}, {groupErr: errors.New("x")}} {
			got := securityAssessReadOpenList(context.Background(), f, "h")
			if len(got.Refs) != 0 || got.Total != 0 {
				t.Fatalf("list = %+v", got)
			}
		}
		if got := securityAssessReadOpenList(context.Background(), nil, "h"); len(got.Refs) != 0 {
			t.Fatalf("no store: %+v", got)
		}
	})
}

// TestSecurityAssessSecretModeInForce: under every mode the run record and the
// launch audit row carry the mode IN FORCE (mask acts as warn today), beside the
// configured one the settings section carries.
func TestSecurityAssessSecretModeInForce(t *testing.T) {
	for _, c := range []struct{ configured, inForce string }{
		{"off", "off"},
		{"warn", "warn"},
		{"mask", "warn"},
		{"refuse", "refuse"},
	} {
		t.Run(c.configured, func(t *testing.T) {
			h := newRelaxHarness(t, "report_to_org = true\nworkspace_secret_mode = \""+c.configured+"\"\n")
			h.writeProjectFiles(depthProject)
			p := h.plan("")
			if !p.OK {
				t.Fatalf("plan = %q %q", p.Code, p.Reason)
			}
			if p.Env.Configured != c.configured || p.Env.Effective != c.inForce {
				t.Fatalf("env = %+v", p.Env)
			}
			if code, out := h.launchRaw(h.launchBody(p.RunID, map[string]any{"prompt_sha256": p.PromptSHA256})); code != http.StatusOK {
				t.Fatalf("launch: %d %v", code, out)
			}
			run, _ := h.runs.Get(p.RunID)
			if run.SecretMode != c.inForce {
				t.Fatalf("run.SecretMode = %q, want %q", run.SecretMode, c.inForce)
			}
			reason := auditLaunchReason(t, h)
			for _, want := range []string{"secret_mode_in_force=" + c.inForce, "workspace_secret_mode=" + c.configured} {
				if !strings.Contains(reason, want) {
					t.Errorf("the launch row lacks %q: %s", want, reason)
				}
			}
		})
	}
}

// TestSecurityAssessRefuseFailsClosedInThePlan: under Refuse a findings store that
// cannot be read refuses the plan and the launch with its own code, and a project
// nobody has scanned says so instead of "none is open now".
func TestSecurityAssessRefuseFailsClosedInThePlan(t *testing.T) {
	t.Run("an unreadable findings store refuses", func(t *testing.T) {
		h := newRelaxHarness(t, "workspace_secret_mode = \"refuse\"\n")
		h.writeProjectFiles(depthProject)
		if _, err := h.s.db().ExecContext(context.Background(), `ALTER TABLE sec_findings RENAME TO sec_findings_gone`); err != nil {
			t.Fatal(err)
		}
		p := h.plan("")
		if p.OK || p.Code != codeFindingsUnreadable || p.Reason != secassess.ReasonFindingsUnreadable || p.Prompt != "" {
			t.Fatalf("plan = ok %v code %q reason %q", p.OK, p.Code, p.Reason)
		}
		code, out := h.launchRaw(h.launchBody(p.RunID, nil))
		if code != http.StatusConflict || out["code"] != codeFindingsUnreadable || h.lm.lastFreshSpec.Tool != "" {
			t.Fatalf("launch: %d %v", code, out)
		}
	})
	t.Run("an unreadable findings store does not refuse under warn", func(t *testing.T) {
		h := newRelaxHarness(t, "workspace_secret_mode = \"warn\"\n")
		h.writeProjectFiles(depthProject)
		if _, err := h.s.db().ExecContext(context.Background(), `ALTER TABLE sec_findings RENAME TO sec_findings_gone`); err != nil {
			t.Fatal(err)
		}
		if p := h.plan(""); !p.OK {
			t.Fatalf("plan = %q %q", p.Code, p.Reason)
		}
	})
	t.Run("a project nobody has scanned does not read as none open", func(t *testing.T) {
		h := newRelaxHarness(t, "workspace_secret_mode = \"refuse\"\n")
		h.writeProjectFiles(depthProject)
		p := h.plan("")
		if !p.OK || !strings.Contains(p.Env.Line, "never scanned this project") || strings.Contains(strings.ToLower(p.Env.Line), "none is open") {
			t.Fatalf("env line = %q (ok %v)", p.Env.Line, p.OK)
		}
	})
}

// TestSecurityAssessEnvCanaryNeverReachesThePlan: the value in a real environment
// file reaches neither the plan's JSON nor the task, however the plan is read.
func TestSecurityAssessEnvCanaryNeverReachesThePlan(t *testing.T) {
	const canary = "CANARY-env-value-9f3a"
	h := newRelaxHarness(t, "workspace_secret_mode = \"warn\"\n")
	files := map[string]string{}
	for k, v := range depthProject {
		files[k] = v
	}
	files[".env"] = "TOKEN=" + canary + "\n"
	files["prod.env"] = "DB_PASSWORD=" + canary + "\n"
	files[".env.example"] = "TOKEN=\n"
	h.writeProjectFiles(files)
	for _, kind := range []string{"pentest_local", "threat_model"} {
		raw := h.planRaw(kind, "")
		if strings.Contains(raw, canary) {
			t.Errorf("%s: the plan carries an environment file's value", kind)
		}
	}
	p := h.plan("")
	if p.Env == nil || p.Env.Count != 2 {
		t.Fatalf("env = %+v (both .env and prod.env are environment files)", p.Env)
	}
}

// TestSecurityAssessPrepareIsOptIn: a plan with preparation steps does not put them
// in the task unless the developer ticks them, and the tick round-trips through
// the launch and the record.
func TestSecurityAssessPrepareIsOptIn(t *testing.T) {
	h := newRelaxHarness(t, "report_to_org = true\n")
	h.writeProjectFiles(map[string]string{
		"manage.py":        `os.environ.setdefault("DJANGO_SETTINGS_MODULE", "x")  # django` + "\n",
		"requirements.txt": "django\n",
	})
	off := h.plan("")
	if !off.OK || off.Start == nil || off.Start.Prepare || !planHasPrepare(off) || strings.Contains(off.Prompt, "manage.py migrate") {
		t.Fatalf("default: start %+v prompt has migrate %v", off.Start, strings.Contains(off.Prompt, "manage.py migrate"))
	}
	on := h.plan(planQuery(securityAssessChoices{Prepare: true}))
	if !on.OK || !on.Start.Prepare || !strings.Contains(on.Prompt, "manage.py migrate") || on.PromptSHA256 == off.PromptSHA256 {
		t.Fatalf("ticked: start %+v", on.Start)
	}
	if code, out := h.launchRaw(h.launchBody(on.RunID, map[string]any{"prepare": true, "prompt_sha256": on.PromptSHA256})); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	run, _ := h.runs.Get(on.RunID)
	if !run.Prepare || !strings.Contains(auditLaunchReason(t, h), "prepare=yes") {
		t.Fatalf("run.Prepare = %v; audit %s", run.Prepare, auditLaunchReason(t, h))
	}
}

func planHasPrepare(p securityAssessPlanJS) bool {
	for _, plan := range p.Start.Plans {
		if len(plan.Prepare) > 0 {
			return true
		}
	}
	return false
}

// TestSecurityAssessEarlierRunNeverReachesTheTask: the task and its digest are
// byte-identical whatever earlier run is chosen, because nothing of an earlier
// run is an input of the prompt (the leak guarantee of D24 is structural).
func TestSecurityAssessEarlierRunNeverReachesTheTask(t *testing.T) {
	h := newRelaxHarness(t, "")
	h.writeProjectFiles(depthProject)
	base := h.planFor("threat_model", "")
	if !base.OK || base.Prompt == "" {
		t.Fatalf("plan = %q", base.Code)
	}
	for _, choice := range []string{securityAssessNone, "00000000000000ff", "00000000000000a1"} {
		p := h.planFor("threat_model", planQuery(securityAssessChoices{PreviousRun: choice}))
		// The run id is minted per plan and stands in the task; nothing else may differ.
		if strings.ReplaceAll(p.Prompt, p.RunID, "RUN") != strings.ReplaceAll(base.Prompt, base.RunID, "RUN") {
			t.Errorf("previous_run=%q changed the task", choice)
		}
	}
}

// planRaw is the plan route's body as text, for a test that must prove a string
// is absent from every field.
func (h *relaxHarness) planRaw(kind, query string) string {
	h.t.Helper()
	w := httptest.NewRecorder()
	url := "/api/security/assessments/plan?kind=" + kind + "&project=" + h.hash + "&target=http://localhost:3000/" + query
	h.s.handleSecurityAssessPlan(w, httptest.NewRequest(http.MethodGet, url, nil))
	if w.Code != http.StatusOK {
		h.t.Fatalf("plan %s: %d", kind, w.Code)
	}
	return w.Body.String()
}
