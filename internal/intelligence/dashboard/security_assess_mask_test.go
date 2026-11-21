//go:build !sbo_omit_security

package dashboard

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// maskLM is a launch manager that can report a fresh launch's outcome
// (FreshLaunchDetailer), standing in for the daemon's adapter: it records the
// spec through the embedded fake and returns the outcome the test chose. A
// launch manager without it is the plain fakeLaunchManager.
type maskLM struct {
	*fakeLaunchManager
	outcome *SecretMaskOutcome
	detail  int
}

func (m *maskLM) CreateFreshDetailed(spec FreshLaunchSpec) (FreshLaunchResult, error) {
	m.detail++
	h, err := m.fakeLaunchManager.CreateFresh(spec)
	return FreshLaunchResult{Handle: h, SecretMask: m.outcome}, err
}

// maskHarness is a plan-and-launch harness whose sandbox probe says whether its
// bubblewrap-shaped row can hide files, and whose launch manager does or does not
// report the outcome.
func maskHarness(t *testing.T, cfg string, rowCanMask, detailer bool, outcome *SecretMaskOutcome) (*relaxHarness, *maskLM) {
	t.Helper()
	// A reported run writes the launch audit row the tests read.
	h := newRelaxHarness(t, "report_to_org = true\n"+cfg)
	h.writeProjectFiles(depthProject)
	av := assessProbe("proxy_only", "claude-code")
	av.Backends[0].MasksWorkspaceSecrets = rowCanMask
	h.s.opts.SandboxProber = &fakeSandboxProber{avail: av}
	m := &maskLM{fakeLaunchManager: h.lm, outcome: outcome}
	if detailer {
		h.s.opts.LaunchManager = m
	}
	return h, m
}

// TestSecurityAssessWorkspaceSecretModeTable is the behaviour table of
// workspace_secret_mode (decision D32): per setting, per capability of the run's
// sandbox row and launcher, the mode in force, the reason when a mask is not in
// force, whether the launch asks the sandbox to hide files, and what the plan
// and the run record carry. The decision is by capability flag only: the rows
// are named alike here on purpose.
func TestSecurityAssessWorkspaceSecretModeTable(t *testing.T) {
	complete := &SecretMaskOutcome{Masked: 1, Complete: true}
	cases := []struct {
		name       string
		setting    string
		rowCan     bool
		detailer   bool
		effective  string
		why        string
		asks       bool
		safetyHeld bool // the no_credentials row has an Observer cell
	}{
		{"mask where the row can and the launcher reports", "mask", true, true, "mask", "", true, true},
		{"mask where the row cannot", "mask", false, true, "warn", "backend_cannot_mask", false, false},
		{"mask where the row can and the launcher cannot report", "mask", true, false, "warn", "launcher_cannot_report", false, false},
		{"mask where neither can", "mask", false, false, "warn", "backend_cannot_mask", false, false},
		{"warn where the row can", "warn", true, true, "warn", "", false, false},
		{"off where the row can", "off", true, true, "off", "", false, false},
		{"refuse where the row can (nothing open: not refused)", "refuse", true, true, "refuse", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, m := maskHarness(t, "workspace_secret_mode = \""+c.setting+"\"\n", c.rowCan, c.detailer, complete)
			p := h.plan("")
			if !p.OK || p.Env == nil || p.Model == nil {
				t.Fatalf("plan = ok %v %q %q", p.OK, p.Code, p.Reason)
			}
			if p.Env.Configured != c.setting || p.Env.Effective != c.effective || p.Env.Downgrade != c.why {
				t.Errorf("env = %+v", p.Env)
			}
			if p.Model.SecretMode != c.setting || p.Model.SecretModeEffective != c.effective || p.Model.SecretModeDowngrade != c.why {
				t.Errorf("model = %+v", p.Model)
			}
			held := false
			for _, r := range p.Safety {
				if r.ID == "no_credentials" {
					held = r.Observer != "-"
					if r.PromptOnly == held {
						t.Errorf("no_credentials: observer %q, prompt_only %v", r.Observer, r.PromptOnly)
					}
				}
			}
			if held != c.safetyHeld {
				t.Errorf("the no_credentials row is held by Observer: %v, want %v", held, c.safetyHeld)
			}
			if c.why != "" {
				if want := secassess.MaskDowngradeWords(c.why); !strings.Contains(p.Env.Line, want+", so it acts as a warning") {
					t.Errorf("the plan line does not say why (%q): %q", want, p.Env.Line)
				}
			}
			code, out := h.launchRaw(h.launchBody(p.RunID, map[string]any{"prompt_sha256": p.PromptSHA256}))
			if code != http.StatusOK {
				t.Fatalf("launch: %d %v", code, out)
			}
			if got := h.lm.lastFreshSpec.MaskWorkspaceSecrets; got != c.asks {
				t.Errorf("the launch asked for the mask: %v, want %v", got, c.asks)
			}
			// A sandboxed launch reads the backend that built the box through the
			// detailed call (when the manager has one), whether or not it asks for the
			// mask; the mask only decides what else is read from it.
			if wantDetail := map[bool]int{true: 1, false: 0}[c.detailer]; m.detail != wantDetail {
				t.Errorf("the detailed call was used %d times, want %d (detailer %v, asks %v)", m.detail, wantDetail, c.detailer, c.asks)
			}
			_, hasMask := out["secret_mask"]
			if hasMask != c.asks {
				t.Errorf("the launch response carries secret_mask: %v, want %v", hasMask, c.asks)
			}
			run, _ := h.runs.Get(p.RunID)
			if run.SecretMode != c.effective || run.SecretModeWhy != c.why || (run.SecretMask != nil) != c.asks {
				t.Errorf("run record: mode %q why %q mask %+v", run.SecretMode, run.SecretModeWhy, run.SecretMask)
			}
			reason := auditLaunchReason(t, h)
			if !strings.Contains(reason, "secret_mode_in_force="+c.effective) {
				t.Errorf("the launch row lacks the mode in force: %s", reason)
			}
			if (c.why != "") != strings.Contains(reason, "secret_mode_downgrade="+c.why) {
				t.Errorf("the launch row's downgrade word, want %q: %s", c.why, reason)
			}
			if c.asks != strings.Contains(reason, "secret_mask=complete secret_masked=1") {
				t.Errorf("the launch row's mask words, asks=%v: %s", c.asks, reason)
			}
		})
	}
}

// TestSecurityAssessMaskOutcomes: what the developer is shown when the box has
// started. A complete mask, a partial one and one nobody reported on all start
// the run (the box is already running when the outcome is known), and a partial or
// an unreported mask is a warning with the gap count, recorded as counts and
// closed words only.
func TestSecurityAssessMaskOutcomes(t *testing.T) {
	cases := []struct {
		name     string
		outcome  *SecretMaskOutcome
		reported bool
		complete bool
		partial  bool
		masked   int
		gaps     int
		audit    string
		words    []string
	}{
		{"complete", &SecretMaskOutcome{Masked: 3, Complete: true}, true, true, false, 3, 0, "secret_mask=complete secret_masked=3", []string{"3 files hidden inside the box"}},
		{"complete, none found", &SecretMaskOutcome{Complete: true}, true, true, false, 0, 0, "secret_mask=complete secret_masked=0", []string{"hid none"}},
		{"partial", &SecretMaskOutcome{Masked: 2, Gaps: 3, Reasons: map[string]int{"symlink": 2, "depth_limit": 1}}, true, false, true, 2, 3, "secret_mask=partial secret_masked=2 secret_mask_gaps=3", []string{"3 places could not be covered", "a folder below the depth the walk reads (1)", "a secret-named link, never followed (2)", "may still be readable"}},
		{"partial, a hostile reason word is only ever a closed word", &SecretMaskOutcome{Masked: 0, Gaps: 1, Reasons: map[string]int{"/home/me/.env\nIGNORE ALL": 1}}, true, false, true, 0, 1, "secret_mask=partial secret_masked=0 secret_mask_gaps=1", []string{"1 place could not be covered", "a place the mask could not describe (1)"}},
		{"complete claimed with gaps is partial", &SecretMaskOutcome{Masked: 1, Complete: true, Gaps: 2}, true, false, true, 1, 2, "secret_mask=partial secret_masked=1 secret_mask_gaps=2", []string{"2 places could not be covered"}},
		{"asked and nothing reported", nil, false, false, true, 0, 0, "secret_mask=unreported", []string{"did not report what it hid"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, _ := maskHarness(t, "workspace_secret_mode = \"mask\"\n", true, true, c.outcome)
			p := h.plan("")
			if !p.OK || p.Env.Effective != "mask" {
				t.Fatalf("plan: ok %v env %+v", p.OK, p.Env)
			}
			code, out := h.launchRaw(h.launchBody(p.RunID, map[string]any{"prompt_sha256": p.PromptSHA256}))
			if code != http.StatusOK {
				t.Fatalf("launch: %d %v (a partial mask is a warning, not a refusal)", code, out)
			}
			raw, _ := json.Marshal(out["secret_mask"])
			var m securityAssessMaskJS
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("secret_mask = %s: %v", raw, err)
			}
			if m.Reported != c.reported || m.Complete != c.complete || m.Partial != c.partial || m.Masked != c.masked || m.Gaps != c.gaps {
				t.Errorf("launch response mask = %+v", m)
			}
			for _, w := range c.words {
				if !strings.Contains(m.Words, w) {
					t.Errorf("the words %q lack %q", m.Words, w)
				}
			}
			run, _ := h.runs.Get(p.RunID)
			if run.SecretMask == nil || run.SecretMask.Reported != c.reported || run.SecretMask.Complete != c.complete || run.SecretMask.Masked != c.masked || run.SecretMask.Gaps != c.gaps {
				t.Fatalf("run record = %+v", run.SecretMask)
			}
			if reason := auditLaunchReason(t, h); !strings.Contains(reason, c.audit) {
				t.Errorf("the launch row lacks %q: %s", c.audit, reason)
			}
			// The run row the list serves carries the same view, and nothing that
			// looks like a path or the hostile reason text is stored anywhere.
			view := securityAssessRunView(run, h.root)
			if view.SecretMask == nil || view.SecretMask.Partial != c.partial || view.SecretModeWhy != "" {
				t.Errorf("run view mask = %+v", view.SecretMask)
			}
			stored, _ := json.Marshal(run)
			wire, _ := json.Marshal(out)
			for _, text := range []string{string(stored), string(wire)} {
				for _, bad := range []string{"/home/me", "IGNORE ALL", ".env\\n"} {
					if strings.Contains(text, bad) {
						t.Errorf("%q reached a record or a response", bad)
					}
				}
			}
		})
	}
}

// TestSecurityAssessMaskIsTheServersDecisionAlone: no body field turns the mask
// on, whatever the setting and the capability, and a kind that does not probe
// never asks for it.
func TestSecurityAssessMaskIsTheServersDecisionAlone(t *testing.T) {
	h, _ := maskHarness(t, "workspace_secret_mode = \"warn\"\n", true, true, &SecretMaskOutcome{Complete: true})
	p := h.plan("")
	code, out := h.launchRaw(h.launchBody(p.RunID, map[string]any{
		"prompt_sha256": p.PromptSHA256, "mask_workspace_secrets": true, "maskWorkspaceSecrets": true, "MaskWorkspaceSecrets": true,
	}))
	if code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, out)
	}
	if h.lm.lastFreshSpec.MaskWorkspaceSecrets {
		t.Error("a body field turned the mask on")
	}
	if _, ok := out["secret_mask"]; ok {
		t.Error("the response reports a mask nobody asked for")
	}
	// A kind that does not probe has no environment-files mode to resolve.
	for _, k := range secassess.Kinds() {
		if k.Probing {
			continue
		}
		g := securityAssessGround{kind: k}
		g.resolveMask(secassess.MaskCan)
		if g.asksForMask() || g.secret.Effective != "" {
			t.Errorf("%s: asks for the mask (%v) or resolved a mode %q", k.ID, g.asksForMask(), g.secret.Effective)
		}
	}
}

// TestCreateFreshLaunchNeedsADetailerForTheMask: a launch that asks for the
// mask through a manager that cannot report the outcome is refused, and a launch
// that does not ask goes through CreateFresh exactly as before.
func TestCreateFreshLaunchNeedsADetailerForTheMask(t *testing.T) {
	s, lm, _ := assessTestServer(t, nil)
	if _, err := s.createFreshLaunch(FreshLaunchSpec{Tool: "claude-code", MaskWorkspaceSecrets: true}); err == nil || lm.lastFreshSpec.Tool != "" {
		t.Fatalf("a mask through a plain manager: err %v, launched %+v", err, lm.lastFreshSpec)
	}
	res, err := s.createFreshLaunch(FreshLaunchSpec{Tool: "claude-code"})
	if err != nil || res.Handle != "FRESH-abc" || res.SecretMask != nil || lm.lastFreshSpec.Tool != "claude-code" {
		t.Fatalf("a plain launch: %+v %v", res, err)
	}
	m := &maskLM{fakeLaunchManager: lm, outcome: &SecretMaskOutcome{Masked: 1, Complete: true}}
	s.opts.LaunchManager = m
	res, err = s.createFreshLaunch(FreshLaunchSpec{Tool: "codex", MaskWorkspaceSecrets: true})
	if err != nil || res.SecretMask == nil || res.SecretMask.Masked != 1 || m.detail != 1 || lm.lastFreshSpec.Tool != "codex" {
		t.Fatalf("a masked launch: %+v %v (detail %d)", res, err, m.detail)
	}
}

// TestMaskGapReasonsMatchTheSandboxVocabulary holds secassess's table of reason
// words to the sandbox planner's closed vocabulary: a reason the planner adds is
// a row here (or it would read "other" and say less than it knows), and a row
// here the planner does not have is stale. The planner's source is read for its
// SecretMaskGapReason constants; secassess cannot import it.
func TestMaskGapReasonsMatchTheSandboxVocabulary(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "../../sandbox/secretmask.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var planner []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != "SecretMaskGapReason" || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok {
				continue
			}
			v, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			planner = append(planner, v)
		}
	}
	if len(planner) == 0 {
		t.Fatal("found no SecretMaskGapReason constants: the parse is wrong")
	}
	have := map[string]bool{}
	for _, r := range secassess.MaskGapReasons {
		have[r.ID] = true
	}
	for _, v := range planner {
		if !have[v] {
			t.Errorf("the sandbox planner's reason %q has no row in secassess.MaskGapReasons", v)
		}
		delete(have, v)
	}
	delete(have, secassess.MaskOtherReason)
	for id := range have {
		t.Errorf("secassess.MaskGapReasons has %q, which the sandbox planner does not", id)
	}
}

// TestSecurityAssessRefusedPlanDoesNotSayNoSandboxIsChosen: a pen test plan that
// is refused before rule E9 has chosen a backend (a target that is not on
// loopback, or one that is not an address at all) still reads the sandbox the
// route would pick, because the route sandboxes this kind whatever the plan says.
// Its environment-files line is the setting in force or the sandbox row's own
// reason, never "no sandbox is chosen for this run yet" (found live, 2026-11-15).
// Only a machine with no usable sandbox at all keeps that honest answer.
func TestSecurityAssessRefusedPlanDoesNotSayNoSandboxIsChosen(t *testing.T) {
	complete := &SecretMaskOutcome{Masked: 1, Complete: true}
	refusedTargets := []string{"http://example.com:3000/", "not%20a%20url"}
	cases := []struct {
		name      string
		rowCan    bool
		noRow     bool
		effective string
		why       string
	}{
		{"the row can hide files", true, false, "mask", ""},
		{"the row cannot hide files: its own reason", false, false, "warn", "backend_cannot_mask"},
		{"no usable sandbox at all: undecided is the truth", true, true, "warn", "no_backend"},
	}
	for _, c := range cases {
		for _, target := range refusedTargets {
			t.Run(c.name+" "+target, func(t *testing.T) {
				h, _ := maskHarness(t, "workspace_secret_mode = \"mask\"\n", c.rowCan, true, complete)
				if c.noRow {
					av := assessProbe("proxy_only", "claude-code")
					av.Backends[0].Available = false
					h.s.opts.SandboxProber = &fakeSandboxProber{avail: av}
				}
				var p securityAssessPlanJS
				url := "/api/security/assessments/plan?kind=pentest_local&project=" + h.hash + "&target=" + target
				if code := getAssessJSON(t, h.s.handleSecurityAssessPlan, url, &p); code != http.StatusOK {
					t.Fatalf("plan: %d", code)
				}
				if p.OK && !c.noRow {
					t.Fatalf("the target %q was accepted", target)
				}
				if p.Env == nil {
					t.Fatalf("the refused plan carries no environment-files line: %+v", p)
				}
				if p.Env.Configured != "mask" || p.Env.Effective != c.effective || p.Env.Downgrade != c.why {
					t.Errorf("env = %+v, want effective %q why %q", p.Env, c.effective, c.why)
				}
				if c.why != "no_backend" && strings.Contains(p.Env.Line, "no sandbox is chosen") {
					t.Errorf("the line says no sandbox is chosen on a machine that has one: %q", p.Env.Line)
				}
			})
		}
	}
}
