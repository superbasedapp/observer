//go:build !sbo_omit_security

package dashboard

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The first live run (2026-11-15) found the live-check kit's launch controls
// stale: `collect.sh negative core` sent the agent id "claude" (the id is
// claude-code), so E4, E6, E9 and E10 all answered 400 "not launchable" and
// never reached their rules, and since the route began deciding the sandbox the
// old "sandbox off" control would have STARTED a sandboxed terminal. The
// controls are now data (scripts/assess-livecheck/negative-controls.json) that
// the kit renders with jq and this test renders the same way and posts to the
// real launch handler. A renamed member, a new required member, a changed rule
// order or a control that gets past its rule fails here, not in an attended run.

// kitControl is one row of the kit's controls file.
type kitControl struct {
	ID       string         `json:"id"`
	Label    string         `json:"label"`
	Needs    string         `json:"needs"`
	SkipHint string         `json:"skip_hint"`
	Set      map[string]any `json:"set"`
	Status   int            `json:"status"`
	Rule     string         `json:"rule"`
	Code     string         `json:"code"`
}

// kitControlsFile is the whole file. Unknown members are refused so the test
// and the kit cannot read the file differently.
type kitControlsFile struct {
	Doc      []string          `json:"_doc"`
	Base     map[string]string `json:"base"`
	Controls []kitControl      `json:"controls"`
}

func readKitControls(t *testing.T) kitControlsFile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "scripts", "assess-livecheck", "negative-controls.json")
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("the live-check kit is not in this tree: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	var f kitControlsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return f
}

// kitTripwire is the kit's tripwire_digest: the plan's digest with its first
// character changed, so it can never be the digest of the prompt the launch
// rebuilds.
func kitTripwire(d string) string {
	if d == "" {
		return ""
	}
	first := "0"
	if strings.HasPrefix(d, "0") {
		first = "1"
	}
	return first + d[1:]
}

// kitTool is the kit's choice of agent: claude-code when the plan lists it,
// else the plan's first.
func kitTool(allowed []string) string {
	if slices.Contains(allowed, "claude-code") {
		return "claude-code"
	}
	if len(allowed) > 0 {
		return allowed[0]
	}
	return ""
}

// kitBody renders one control the way collect.sh's render_body does: the base
// with every @name filled from the values, then the control's set laid over it.
func kitBody(t *testing.T, f kitControlsFile, c kitControl, values map[string]string) map[string]any {
	t.Helper()
	fill := func(v any) any {
		s, ok := v.(string)
		if !ok || !strings.HasPrefix(s, "@") {
			return v
		}
		out, found := values[s[1:]]
		if !found || out == "" {
			t.Fatalf("control %s: no value for %s", c.ID, s)
		}
		return out
	}
	body := map[string]any{}
	for k, v := range f.Base {
		body[k] = fill(v)
	}
	for k, v := range c.Set {
		body[k] = fill(v)
	}
	return body
}

// TestAssessKitControlsMatchTheRoute: every launch control of the kit, row by
// row, through the real plan and launch handlers on a node that could start the
// run. Each answers the rule and code the file names, with the status it names;
// none reaches the launcher or records a run; BASE (the unmodified body) is
// accepted up to the tripwire digest, which is what makes every other row a
// change of exactly its own members from a body that would otherwise start.
func TestAssessKitControlsMatchTheRoute(t *testing.T) {
	f := readKitControls(t)
	h := newRelaxHarness(t, "")
	plan := h.plan("")
	if !plan.OK || plan.RunID == "" || plan.PromptSHA256 == "" || kitTool(plan.AllowedTools) == "" {
		t.Fatalf("the plan cannot start a run here: ok %v run %q digest %q tools %v (%s %s)", plan.OK, plan.RunID, plan.PromptSHA256, plan.AllowedTools, plan.Code, plan.Reason)
	}
	values := map[string]string{
		"project_root_hash": h.hash, "run_id": plan.RunID, "tool": kitTool(plan.AllowedTools),
		"target": "http://localhost:3000/", "tripwire_digest": kitTripwire(plan.PromptSHA256),
	}
	if values["tripwire_digest"] == plan.PromptSHA256 {
		t.Fatal("the tripwire digest is the plan's own digest: a control that passes its rule would start a terminal")
	}

	// The control that needs an agent the box cannot route is run against a
	// probe that offers one, when the registry has one (the same search the
	// existing launch test makes).
	unrouted := ""
	for _, c := range launchableTools() {
		if cap, ok := integration.For(c); ok && cap.Proxy == nil {
			unrouted = c
			break
		}
	}

	// BASE's premise: the members the dialog sends, no more. A member the route
	// reads that the file does not carry is a required member added later.
	for _, k := range []string{"assessment", "project_root_hash", "run_id", "tool", "target", "confirm_target", "prompt_sha256"} {
		if _, ok := f.Base[k]; !ok {
			t.Errorf("the base body has no %q member", k)
		}
	}
	ids := map[string]bool{}
	for _, c := range f.Controls {
		if ids[c.ID] {
			t.Errorf("control id %q is used twice", c.ID)
		}
		ids[c.ID] = true
	}
	for _, id := range []string{"BASE", "E4", "E6-flag", "E6-rules", "E9", "E10", "E8b"} {
		if !ids[id] {
			t.Errorf("the controls file has no %s row", id)
		}
	}

	for _, c := range f.Controls {
		t.Run(c.ID, func(t *testing.T) {
			vals := values
			if c.Needs != "" {
				if unrouted == "" {
					t.Skip("every launchable agent is proxy-routed")
				}
				vals = map[string]string{}
				for k, v := range values {
					vals[k] = v
				}
				vals["needs"] = unrouted
				av := assessProbe("proxy_only", "claude-code", unrouted)
				h.s.opts.SandboxProber = &fakeSandboxProber{avail: av}
			}
			body := kitBody(t, f, c, vals)

			// The body decodes into the real request type with no member the
			// route does not know (a renamed or invented member fails by name).
			raw, _ := json.Marshal(body)
			var req securityAssessLaunchRequest
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&req); err != nil {
				t.Fatalf("control %s is not a launch request: %v (%s)", c.ID, err, raw)
			}

			h.lm.lastFreshSpec = FreshLaunchSpec{}
			w := postAssess(t, h.s.handleSecurityAssessLaunch, "/api/security/assessments/launch", body, true)
			var out map[string]string
			_ = json.Unmarshal(w.Body.Bytes(), &out)
			if w.Code != c.Status || out["rule"] != c.Rule || out["code"] != c.Code {
				t.Fatalf("%s: HTTP %d rule %q code %q, want HTTP %d rule %q code %q (%s)", c.ID, w.Code, out["rule"], out["code"], c.Status, c.Rule, c.Code, w.Body)
			}
			if h.lm.lastFreshSpec.Tool != "" {
				t.Fatalf("%s reached the launcher: %+v", c.ID, h.lm.lastFreshSpec)
			}
			if _, recorded := h.runs.Get(plan.RunID); recorded {
				t.Fatalf("%s recorded a run for a launch that must not start", c.ID)
			}
			// A body that got past every rule is stopped by the tripwire digest, and says so
			// with the new prompt, never a started terminal.
			if c.Code == codePlanChanged && (out["prompt"] == "" || out["prompt_sha256"] == "" || out["prompt_sha256"] == values["tripwire_digest"]) {
				t.Fatalf("%s: the tripwire answer does not carry the new prompt: %v", c.ID, out)
			}
			// A rule's own refusal carries the rule's id and never the sandbox rule E6, which
			// this route no longer reaches for a kind that runs only in a sandbox.
			if c.Rule != "" && out["code"] == secassess.CodeSandboxRequired {
				t.Fatalf("%s: answered E6, which the route cannot reach for this kind", c.ID)
			}
		})
	}
}

// TestAssessKitControlsOnlyChangeTheirOwnMembers: BASE carries every member the
// launch needs and no control changes a member it does not declare, so the one
// field a control changes is the one its row names (E6-rules changes two, on
// purpose: the sandbox flag and a backend that is not grounded).
func TestAssessKitControlsOnlyChangeTheirOwnMembers(t *testing.T) {
	f := readKitControls(t)
	values := map[string]string{
		"project_root_hash": "h1", "run_id": "20261115-ab12cd", "tool": "claude-code",
		"target": "http://localhost:3000/", "tripwire_digest": "1" + strings.Repeat("a", 63), "needs": "some-tool",
	}
	var base map[string]any
	for _, c := range f.Controls {
		if c.ID == "BASE" {
			base = kitBody(t, f, c, values)
		}
	}
	if base == nil {
		t.Fatal("no BASE row")
	}
	want := map[string]int{"BASE": 0, "E4": 1, "E6-flag": 1, "E6-rules": 2, "E9": 1, "E10": 1, "E8b": 1}
	for _, c := range f.Controls {
		body := kitBody(t, f, c, values)
		changed := 0
		for k, v := range body {
			if bv, ok := base[k]; !ok || bv != v {
				changed++
			}
		}
		for k := range base {
			if _, ok := body[k]; !ok {
				t.Errorf("control %s drops the member %q", c.ID, k)
			}
		}
		if n, known := want[c.ID]; !known || changed != n {
			t.Errorf("control %s changes %d member(s) of BASE, want %d (known row %v)", c.ID, changed, n, known)
		}
	}
	if len(want) != len(f.Controls) {
		t.Errorf("the controls file has %d rows, the table here %d", len(f.Controls), len(want))
	}
}

// TestAssessKitSandboxFlagIsNotReadByTheRoute: the two E6 rows together are the
// live proof the old "sandbox off" control cannot give any more. With the flag
// false and nothing else wrong the launch is accepted as a sandboxed one (it
// reaches the tripwire), and with the flag false and a backend that is not
// grounded the sandbox rules answer (E9), exactly as they do for the flag
// true: the route never treats the body as an unsandboxed launch.
func TestAssessKitSandboxFlagIsNotReadByTheRoute(t *testing.T) {
	f := readKitControls(t)
	h := newRelaxHarness(t, "")
	plan := h.plan("")
	values := map[string]string{
		"project_root_hash": h.hash, "run_id": plan.RunID, "tool": "claude-code",
		"target": "http://localhost:3000/", "tripwire_digest": kitTripwire(plan.PromptSHA256),
	}
	answer := func(set map[string]any) (int, map[string]string) {
		c := kitControl{ID: "probe", Set: set}
		h.lm.lastFreshSpec = FreshLaunchSpec{}
		w := postAssess(t, h.s.handleSecurityAssessLaunch, "/api/security/assessments/launch", kitBody(t, f, c, values), true)
		var out map[string]string
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if h.lm.lastFreshSpec.Tool != "" {
			t.Fatalf("a control reached the launcher: %+v", h.lm.lastFreshSpec)
		}
		return w.Code, out
	}
	for _, tc := range []struct {
		name string
		set  map[string]any
	}{
		{"flag true with a backend that is not grounded", map[string]any{"sandbox": true, "backend": "oci-runc"}},
		{"flag false with a backend that is not grounded", map[string]any{"sandbox": false, "backend": "oci-runc"}},
		{"no flag with a backend that is not grounded", map[string]any{"backend": "oci-runc"}},
	} {
		code, out := answer(tc.set)
		if code != http.StatusConflict || out["rule"] != "E9" || out["code"] != secassess.CodeBackendNotGrounded {
			t.Errorf("%s: %d %v", tc.name, code, out)
		}
	}
	for _, tc := range []map[string]any{{"sandbox": false}, {"sandbox": true}, {}} {
		code, out := answer(tc)
		if code != http.StatusConflict || out["rule"] != "" || out["code"] != codePlanChanged {
			t.Errorf("%v: %d %v (the route must accept the body up to the tripwire)", tc, code, out)
		}
	}
}
