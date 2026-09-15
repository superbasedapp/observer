package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// TestHandleConfigSection_Guard pins the G1.1 guard section (security-
// routing usability arc). The hard invariants:
//
//  1. [guard.cloud] survives a PUT whose body zeroes or omits it —
//     network egress stays a hand-written config decision (D1), the
//     dashboard must never be able to flip it.
//  2. Rules.OrgBundle (org-client-owned) and Rules.CEL (v2 gate)
//     survive likewise.
//  3. Boundary lists: an empty list in the body preserves the prior
//     value (nil = engine defaults; explicit "none" is config-file
//     territory).
//  4. Closed enums (mode / egress_action / min_severity) are rejected
//     with 400 at the PUT, not at the next daemon start.
//  5. [guard.prompt] (§8.1, PHASE-3b-DASHBOARD) IS editable through
//     this section — a body that supplies a full Prompt object (as
//     the real frontend's draft always does, see sectionSpecs.ts's
//     "Guard.Prompt"/"Guard.Prompt.Detectors" groups) persists it.
func TestHandleConfigSection_Guard(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	seed := `[observer]
log_level = "info"

[guard]
enabled = true
mode = "observe"

[guard.rules]
org_bundle = "/custom/org-bundle.json"

[guard.boundary]
allow_paths = ["../sibling/**"]

[guard.cloud]
enabled = true
payload_max_bytes = 2048

[guard.cloud.llm_judge]
enabled = true
endpoint = "http://localhost:9999/v1/chat/completions"
`
	if err := os.WriteFile(cfgPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	// Body deliberately zeroes cloud + org_bundle + boundary (a real UI
	// draft never carries them — a hostile/buggy one might send zeros;
	// either way they must not land).
	body := `{"Enabled":true,"Mode":"enforce","Strict":false,"RetentionDays":180,` +
		`"Rules":{"Disable":["R-151"],"UserPolicy":"","ProjectPolicy":"","OrgBundle":"","CEL":false},` +
		`"Boundary":{"AllowPaths":[],"ProtectedBranches":[]},` +
		`"Taint":{"Enabled":true,"DecayTurns":12},` +
		`"Proxy":{"EgressScan":true,"EgressAction":"mask","EgressAllow":["TESTKEY-[0-9]+"],"ResponseScan":true,"InjectionHeuristics":true},` +
		`"MCP":{"Pinning":true,"PoisoningHeuristics":false},` +
		`"Budget":{"SessionUSD":5,"DailyUSD":40,"Hard":false},` +
		`"Alerts":{"Desktop":true,"MinSeverity":"warn"},` +
		`"Export":{"OTel":false},` +
		`"Dialects":{"Compile":true,"Targets":["claude-code"]},` +
		`"Cloud":{"Enabled":false,"PayloadMaxBytes":0},` +
		// Prompt (§8.1, PHASE-3b-DASHBOARD) is a real, editable section
		// now — the frontend's draft always sends the complete object
		// (see sectionSpecs.ts's "Guard.Prompt"/"Guard.Prompt.Detectors"
		// groups), never an omitted key on a real save.
		`"Prompt":{"Enabled":true,"Mode":"ask-once","HookLane":true,"ProxyLane":true,` +
		`"EnforceIndependent":true,"ReconsiderTTL":"30m","ReconsiderMinDelay":"3s","Allow":[],"SuppressInCode":true,` +
		`"MaxFindings":64,"Detectors":{"credit_card":"ask-once","iban":"ask-once",` +
		`"us_ssn":"ask-once","uk_nino":"ask-once","in_aadhaar":"ask-once","in_pan":"ask-once",` +
		`"email":"off","phone_e164":"off","phone_nanp":"off","github_pat":"block"}}}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/guard", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("PUT guard: %d body=%s", rr.Code, rr.Body.String())
	}
	var saved struct {
		RestartRequired bool `json:"restart_required"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&saved); err != nil {
		t.Fatal(err)
	}
	if !saved.RestartRequired {
		t.Errorf("guard saves must report restart_required=true (no hot-reload seam)")
	}

	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	g := reloaded.Guard

	// 1. Cloud survived the zeroing body.
	if !g.Cloud.Enabled || g.Cloud.PayloadMaxBytes != 2048 || !g.Cloud.LLMJudge.Enabled {
		t.Errorf("cloud opt-in must survive a guard section save: %+v", g.Cloud)
	}
	// 2. Org bundle path survived.
	if g.Rules.OrgBundle != "/custom/org-bundle.json" {
		t.Errorf("org_bundle must survive: %q", g.Rules.OrgBundle)
	}
	// 3. Boundary allowlist survived the empty-list body.
	if len(g.Boundary.AllowPaths) != 1 || g.Boundary.AllowPaths[0] != "../sibling/**" {
		t.Errorf("boundary allow_paths must survive an empty-list save: %+v", g.Boundary.AllowPaths)
	}
	// The knobs the section owns did land.
	if g.Mode != "enforce" || g.RetentionDays != 180 {
		t.Errorf("mode/retention not persisted: mode=%q retention=%d", g.Mode, g.RetentionDays)
	}
	if len(g.Rules.Disable) != 1 || g.Rules.Disable[0] != "R-151" {
		t.Errorf("rules.disable not persisted: %+v", g.Rules.Disable)
	}
	if g.Taint.DecayTurns != 12 {
		t.Errorf("taint.decay_turns not persisted: %d", g.Taint.DecayTurns)
	}
	if len(g.Proxy.EgressAllow) != 1 || g.Alerts.MinSeverity != "warn" {
		t.Errorf("proxy/alerts not persisted: %+v %q", g.Proxy.EgressAllow, g.Alerts.MinSeverity)
	}
	if g.Budget.SessionUSD != 5 || g.Budget.DailyUSD != 40 {
		t.Errorf("budget not persisted: %+v", g.Budget)
	}
	// 4. Prompt (§8.1, PHASE-3b-DASHBOARD) is a real editable section
	// now, not preserved-from-prior — the body's values land.
	if g.Prompt.Mode != "ask-once" || !g.Prompt.Enabled || !g.Prompt.HookLane ||
		!g.Prompt.ProxyLane || g.Prompt.ReconsiderTTL != "30m" || g.Prompt.ReconsiderMinDelay != "3s" || g.Prompt.MaxFindings != 64 {
		t.Errorf("guard.prompt not persisted: %+v", g.Prompt)
	}
	if g.Prompt.Detectors["github_pat"] != "block" || g.Prompt.Detectors["email"] != "off" {
		t.Errorf("guard.prompt.detectors not persisted: %+v", g.Prompt.Detectors)
	}

	// 4. Closed enums reject at the PUT.
	for _, bad := range []string{
		`{"Mode":"yolo","Proxy":{"EgressAction":"mask"},"Alerts":{"MinSeverity":"high"}}`,
		`{"Mode":"observe","Proxy":{"EgressAction":"shred"},"Alerts":{"MinSeverity":"high"}}`,
		`{"Mode":"observe","Proxy":{"EgressAction":"flag"},"Alerts":{"MinSeverity":"loud"}}`,
	} {
		rr = httptest.NewRecorder()
		server.Handler().ServeHTTP(rr,
			httptest.NewRequest(http.MethodPut, "/api/config/section/guard", strings.NewReader(bad)))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("invalid enum body must 400, got %d (%s)", rr.Code, bad)
		}
	}

	// editable_sections advertises guard.
	rr = httptest.NewRecorder()
	server.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/config", nil))
	var got struct {
		EditableSections []string `json:"editable_sections"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range got.EditableSections {
		if s == "guard" {
			found = true
		}
	}
	if !found {
		t.Errorf("editable_sections must advertise guard: %v", got.EditableSections)
	}
}

// TestHandleConfigSection_Guard_PromptFullObjectRoundTrips pins the
// PHASE-3b-DASHBOARD contract for [guard.prompt]: it is now a REAL
// editable section (sectionSpecs.ts's "Guard.Prompt"/
// "Guard.Prompt.Detectors" groups), not preserved-from-prior. Its
// draft is a full clone of the loaded config (StructuredConfigSection
// resolves the whole ["Guard"] subtree, not just the fields it
// renders), so a real save always echoes back the CURRENT Prompt
// object even when the operator only touched an unrelated field
// (retention_days here) — this test pins that echo round-trips
// unchanged, the same "send the whole subtree" contract every other
// guard-section field already relies on (Rules.Disable, Taint,
// Proxy, …). Superseded name: this used to be
// TestHandleConfigSection_Guard_PreservesPrompt, back when Phase 1
// shipped the schema with no dashboard form yet and the server had to
// defensively preserve Prompt server-side against a real frontend
// that never sent it at all. See
// TestHandleConfigSection_Guard_RejectsMissingPrompt for the new
// failure mode a genuinely Prompt-less body now hits.
func TestHandleConfigSection_Guard_PromptFullObjectRoundTrips(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	seed := `[guard]
enabled = true
mode = "observe"

[guard.prompt]
enabled = true
mode = "block"
hook_lane = true
proxy_lane = false
reconsider_ttl = "45m"
allow = ["TESTKEY-[0-9]+"]
suppress_in_code = false
max_findings = 32

[guard.prompt.detectors]
credit_card = "block"
email = "warn"
`
	if err := os.WriteFile(cfgPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	wantPrompt := loaded.Guard.Prompt
	if wantPrompt.Mode != "block" || wantPrompt.ReconsiderTTL != "45m" {
		t.Fatalf("seed did not take: %+v", wantPrompt)
	}

	// Body shaped like today's REAL frontend (post-PHASE-3b-DASHBOARD):
	// it edits an unrelated guard knob (retention_days) but its draft is
	// a full clone of the loaded config, so it echoes the CURRENT Prompt
	// object back unchanged — exactly what StructuredConfigSection sends
	// on every save, whether or not the operator touched anything under
	// the "Guard.Prompt" groups this turn.
	promptJSON, err := json.Marshal(wantPrompt)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"Enabled":true,"Mode":"enforce","Strict":false,"RetentionDays":200,` +
		`"Proxy":{"EgressAction":"mask"},` +
		`"Alerts":{"MinSeverity":"high"},` +
		`"Prompt":` + string(promptJSON) + `}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/guard", strings.NewReader(body)))
	if rr.Code != 200 {
		t.Fatalf("PUT guard: %d body=%s", rr.Code, rr.Body.String())
	}

	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := reloaded.Guard.Prompt
	if got.Mode != wantPrompt.Mode ||
		got.Enabled != wantPrompt.Enabled ||
		got.HookLane != wantPrompt.HookLane ||
		got.ProxyLane != wantPrompt.ProxyLane ||
		got.ReconsiderTTL != wantPrompt.ReconsiderTTL ||
		got.SuppressInCode != wantPrompt.SuppressInCode ||
		got.MaxFindings != wantPrompt.MaxFindings ||
		len(got.Allow) != len(wantPrompt.Allow) ||
		len(got.Detectors) != len(wantPrompt.Detectors) {
		t.Errorf("guard.prompt must survive an unrelated guard-section save:\n  got  %+v\n  want %+v", got, wantPrompt)
	}
	for id, mode := range wantPrompt.Detectors {
		if got.Detectors[id] != mode {
			t.Errorf("guard.prompt.detectors[%q] = %q, want %q", id, got.Detectors[id], mode)
		}
	}

	// The unrelated knob the section owns did land, confirming the save
	// actually took effect rather than failing silently.
	if reloaded.Guard.RetentionDays != 200 {
		t.Errorf("retention_days not persisted: %d", reloaded.Guard.RetentionDays)
	}
}

// TestHandleConfigSection_Guard_RejectsMissingPrompt pins the failure
// mode a genuinely Prompt-less body now hits (PHASE-3b-DASHBOARD):
// since [guard.prompt] is a real editable section, a body that omits
// the "Prompt" key entirely decodes it to its Go zero value
// (Mode:""), which fails the prompt.mode enum check at line ~825 —
// the PUT is REJECTED with 400 rather than silently wiping the
// configured section (the old preserve-on-omit behavior this
// supersedes). This is the correct fail-loud posture for a caller
// that isn't the real frontend (which always echoes the full object,
// see TestHandleConfigSection_Guard_PromptFullObjectRoundTrips) — a
// raw/scripted PUT missing Prompt gets a clear error instead of a
// silent data loss, and the on-disk config is untouched by the
// rejected write.
func TestHandleConfigSection_Guard_RejectsMissingPrompt(t *testing.T) {
	tdir := t.TempDir()
	cfgPath := filepath.Join(tdir, "config.toml")
	seed := `[guard]
enabled = true
mode = "observe"

[guard.prompt]
enabled = true
mode = "block"
hook_lane = true
proxy_lane = false
reconsider_ttl = "45m"
allow = ["TESTKEY-[0-9]+"]
suppress_in_code = false
max_findings = 32

[guard.prompt.detectors]
credit_card = "block"
email = "warn"
`
	if err := os.WriteFile(cfgPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	// Body with no "Prompt" key at all — a raw/scripted caller, not the
	// real frontend (which always echoes the full Prompt object).
	body := `{"Enabled":true,"Mode":"enforce","Strict":false,"RetentionDays":200,` +
		`"Proxy":{"EgressAction":"mask"},` +
		`"Alerts":{"MinSeverity":"high"}}`
	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodPut, "/api/config/section/guard", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("PUT guard with no Prompt key: got %d, want 400 body=%s", rr.Code, rr.Body.String())
	}

	// The rejected write must not have touched the on-disk config.
	reloaded, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Guard.Mode != "observe" || reloaded.Guard.Prompt.Mode != "block" {
		t.Errorf("a rejected PUT must not partially persist: guard.mode=%q guard.prompt.mode=%q",
			reloaded.Guard.Mode, reloaded.Guard.Prompt.Mode)
	}
}

// TestAPIGuardRulesEffective pins the G1.5 effective view: a custom
// user-layer rule resolves through /api/guard/rules?effective=1 with
// its source attributed, so the Security page's RuleCell can show its
// definition instead of degrading to a bare mono ID.
func TestAPIGuardRulesEffective(t *testing.T) {
	tdir := t.TempDir()
	policyPath := filepath.Join(tdir, "guard-policy.toml")
	userPolicy := `[[rule]]
id = "U-001"
category = "boundary"
severity = "high"
decision = "ask"
applies_to = ["shell_exec"]
match.command_base = "terraform"
match.arg_contains = "apply"
`
	if err := os.WriteFile(policyPath, []byte(userPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(tdir, "config.toml")
	seed := "[guard]\nenabled = true\nmode = \"observe\"\n\n[guard.rules]\nuser_policy = " +
		strconv.Quote(policyPath) + "\n"
	if err := os.WriteFile(cfgPath, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(tdir, "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	server, err := New(Options{DB: database, ConfigPath: cfgPath})
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	server.Handler().ServeHTTP(rr,
		httptest.NewRequest(http.MethodGet, "/api/guard/rules?effective=1", nil))
	if rr.Code != 200 {
		t.Fatalf("GET effective rules: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Rules []struct {
			ID     string `json:"id"`
			Doc    string `json:"doc"`
			Source string `json:"source"`
		} `json:"rules"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	var custom, builtins bool
	for _, r := range resp.Rules {
		if r.ID == "U-001" {
			custom = true
			if r.Source != "user" {
				t.Errorf("U-001 = %+v, want source=user", r)
			}
		}
		if r.ID == "R-101" {
			builtins = true
		}
	}
	if !custom {
		t.Errorf("effective view missing the user-layer rule U-001")
	}
	if !builtins {
		t.Errorf("effective view missing built-ins (R-101)")
	}
}
