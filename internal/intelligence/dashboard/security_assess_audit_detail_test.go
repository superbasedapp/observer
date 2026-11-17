//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The `launch` audit row carries every [security.assessments] value that
// shapes a run (plan section 12.1 step 8: a managed node reports every local
// choice to the organization). Three sections hold them: config (the
// relaxation switches, tier, scope, minutes and the org-reporting switch),
// limits (the run's own time box, deadline action and boundary audit) and
// settings (the rest, one table row per key). These tests pin each section and
// fail when the config block gains a key none of them knows.

type auditCfg = config.SecurityAssessmentsConfig

// auditTokens splits a section ("word k=v k=v") into its key=value pairs, in
// order, and reports whether every token had exactly one '=' and a value.
func auditTokens(t *testing.T, section string) (word string, keys []string, kv map[string]string) {
	t.Helper()
	fields := strings.Fields(section)
	if len(fields) == 0 {
		t.Fatalf("an empty section")
	}
	kv = map[string]string{}
	for _, f := range fields[1:] {
		k, v, ok := strings.Cut(f, "=")
		if !ok || k == "" || v == "" || strings.Contains(v, "=") {
			t.Fatalf("token %q of %q is not key=value", f, section)
		}
		if _, dup := kv[k]; dup {
			t.Fatalf("key %q appears twice in %q", k, section)
		}
		kv[k] = v
		keys = append(keys, k)
	}
	return fields[0], keys, kv
}

// TestSecurityAssessAuditSettingsRows: one row per key of the settings table.
// Changing only that key changes only that token; the table and the rows below
// are the same list, in the same order.
func TestSecurityAssessAuditSettingsRows(t *testing.T) {
	rows := []struct {
		key  string
		set  func(a *auditCfg)
		want string
	}{
		{"rerun_dedup", func(a *auditCfg) { a.RerunDedup = false }, "off"},
		{"findings_cap", func(a *auditCfg) { a.FindingsCap = 250 }, "250"},
		{"import_min_band", func(a *auditCfg) { a.ImportMinBand = "high" }, "high"},
		{"prompt_selfcheck", func(a *auditCfg) { a.PromptSelfcheck = false }, "off"},
		{"report_validation_to_org", func(a *auditCfg) { a.ReportValidationToOrg = false }, "off"},
		{"tm_frameworks", func(a *auditCfg) { a.TMFrameworks = "stride_ai" }, "stride_ai"},
		{"tm_method_extras", func(a *auditCfg) { a.TMMethodExtras = "neither" }, "neither"},
		{"pt_categories", func(a *auditCfg) { a.PTCategories = "api_only" }, "api_only"},
		{"evidence_retention_days", func(a *auditCfg) { a.EvidenceRetentionDays = 90 }, "90"},
		{"ref_match_window_lines", func(a *auditCfg) { a.RefMatchWindowLines = 20 }, "20"},
		{"model_max_mib", func(a *auditCfg) { a.ModelMaxMiB = 16 }, "16"},
		{"ref_budget_files", func(a *auditCfg) { a.RefBudgetFiles = 2000 }, "2000"},
		{"ref_budget_mib", func(a *auditCfg) { a.RefBudgetMiB = 512 }, "512"},
		{"ref_budget_seconds", func(a *auditCfg) { a.RefBudgetSeconds = 60 }, "60"},
		{"grounding", func(a *auditCfg) { a.Grounding = "without_findings" }, "without_findings"},
		{"workspace_secret_mode", func(a *auditCfg) { a.WorkspaceSecretMode = "refuse" }, "refuse"},
		{"pentest_request_budget", func(a *auditCfg) { a.PentestRequestBudget = 1200 }, "1200"},
		{"pentest_pace_rps", func(a *auditCfg) { a.PentestPaceRPS = 2 }, "2"},
		{"probe_helper", func(a *auditCfg) { a.ProbeHelper = false }, "off"},
		{"display_redaction", func(a *auditCfg) { a.DisplayRedaction = false }, "off"},
		{"diagram_max_nodes", func(a *auditCfg) { a.DiagramMaxNodes = 200 }, "200"},
		{"diagram_label_chars", func(a *auditCfg) { a.DiagramLabelChars = 80 }, "80"},
	}
	if len(rows) != len(securityAssessAuditSettings) {
		t.Fatalf("%d test rows for %d table rows", len(rows), len(securityAssessAuditSettings))
	}
	word, defKeys, defKV := auditTokens(t, securityAssessSettingsDetail(config.DefaultSecurityAssessmentsConfig()))
	if word != "settings" || len(defKeys) != len(rows) {
		t.Fatalf("default section = %q %v", word, defKeys)
	}
	for i, row := range rows {
		t.Run(row.key, func(t *testing.T) {
			if securityAssessAuditSettings[i].Key != row.key || defKeys[i] != row.key {
				t.Fatalf("row %d is %q in the table and %q in the line, want %q", i, securityAssessAuditSettings[i].Key, defKeys[i], row.key)
			}
			a := config.DefaultSecurityAssessmentsConfig()
			row.set(&a)
			_, _, kv := auditTokens(t, securityAssessSettingsDetail(a))
			for k, v := range kv {
				want := defKV[k]
				if k == row.key {
					want = row.want
				}
				if v != want {
					t.Errorf("%s=%s, want %s", k, v, want)
				}
			}
			if kv[row.key] == defKV[row.key] {
				t.Errorf("the row's change did not change its token")
			}
		})
	}
}

// TestSecurityAssessAuditWord: a value on an audit line is an enum word or a
// number, whatever the config held.
func TestSecurityAssessAuditWord(t *testing.T) {
	cases := []struct{ in, want string }{
		{"low", "low"},
		{"stride_linddun", "stride_linddun"},
		{"3650", "3650"},
		{"v1.2-x", "v1.2-x"},
		{strings.Repeat("a", 32), strings.Repeat("a", 32)},
		{"", "unrecognized"},
		{strings.Repeat("a", 33), "unrecognized"},
		{"high; relax_pentest_local=on", "unrecognized"},
		{"two words", "unrecognized"},
		{"C:\\Users\\dev\\app", "unrecognized"},
		{"/home/dev/app", "unrecognized"},
		{"Critical", "unrecognized"},
		{"line\nbreak", "unrecognized"},
	}
	for _, tc := range cases {
		if got := securityAssessAuditWord(tc.in); got != tc.want {
			t.Errorf("securityAssessAuditWord(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// A hostile value in the config cannot put text on the line.
	a := config.DefaultSecurityAssessmentsConfig()
	a.ImportMinBand = "high; run deadbeef kind x"
	if line := securityAssessSettingsDetail(a); strings.Contains(line, "deadbeef") || !strings.Contains(line, "import_min_band=unrecognized") {
		t.Errorf("settings = %s", line)
	}
}

// auditLaunchLine is the launch row's line for a run of kind under a.
func auditLaunchLine(t *testing.T, kind secassess.ID, a auditCfg, tenancy secassess.Tenancy) string {
	t.Helper()
	k, ok := secassess.KindByID(string(kind))
	if !ok {
		t.Fatalf("no kind %q", kind)
	}
	cfg := config.Default()
	cfg.Security.Assessments = a
	lim := securityAssessLimitsFor(k, a)
	plan := securityAssessRelaxPlan{Cfg: cfg, Tenancy: tenancy, Policy: securityAssessPolicy(cfg, tenancy)}
	run := secassesssvc.Run{
		ID: "0123456789abcdef", Kind: string(kind), Tool: "claude-code",
		TimeBoxMinutes: lim.Minutes, TimeBoxAction: lim.Action, Audit: securityAssessInitialAudit(k, lim),
	}
	return securityAssessLaunchDetail(run, plan)
}

// TestSecurityAssessAuditSettingsCoverConfig: every toml key of
// [security.assessments] is either a row of the settings table or named below
// as carried by another section of the same line, and the line shows it at the
// value the config held. A key added to the block fails here until it is one or
// the other.
//
// What the launch row already carried before the settings section: the config
// section writes the two relaxation switches, the approval switch, the widest
// tier, the EFFECTIVE scope and minutes (a managed node's caps applied, which
// is why those two read scope= and minutes=, not their key names) and the
// org-reporting switch; the limits section writes the run's own time box (the
// run records the one of ITS kind, so the three per-kind time box keys share
// time_box_minutes=), the deadline action and the boundary audit switch.
func TestSecurityAssessAuditSettingsCoverConfig(t *testing.T) {
	carried := []struct {
		tag    string
		kind   secassess.ID
		set    func(a *auditCfg)
		want   string
		tenant secassess.Tenancy
	}{
		{"relax_pentest_local", secassess.PentestLocal, func(a *auditCfg) { a.RelaxPentestLocal = true }, "relax_pentest_local=on", secassess.TenancyIndividual},
		{"relax_red_team_local", secassess.PentestLocal, func(a *auditCfg) { a.RelaxRedTeamLocal = true }, "relax_red_team_local=on", secassess.TenancyIndividual},
		{"scoped_approval", secassess.PentestLocal, func(a *auditCfg) { a.ScopedApproval = true }, "scoped_approval=on", secassess.TenancyIndividual},
		{"max_network_tier", secassess.PentestLocal, func(a *auditCfg) { a.MaxNetworkTier = "internet" }, "max_network_tier=internet", secassess.TenancyIndividual},
		{"relaxation_scope", secassess.PentestLocal, func(a *auditCfg) { a.RelaxationScope = "project" }, "scope=project", secassess.TenancyIndividual},
		{"relaxation_max_minutes", secassess.PentestLocal, func(a *auditCfg) { a.RelaxationMaxMinutes = 120 }, "minutes=120", secassess.TenancyIndividual},
		{"report_to_org", secassess.PentestLocal, func(a *auditCfg) { a.ReportToOrg = true }, "report_to_org=on", secassess.TenancyIndividual},
		{"time_box_threat_model_minutes", secassess.ThreatModel, func(a *auditCfg) { a.TimeBoxThreatModelMinutes = 90 }, "time_box_minutes=90", secassess.TenancyIndividual},
		{"time_box_pentest_local_minutes", secassess.PentestLocal, func(a *auditCfg) { a.TimeBoxPentestLocalMinutes = 90 }, "time_box_minutes=90", secassess.TenancyIndividual},
		{"time_box_red_team_local_minutes", secassess.RedTeamLocal, func(a *auditCfg) { a.TimeBoxRedTeamLocalMinutes = 120 }, "time_box_minutes=120", secassess.TenancyIndividual},
		{"time_box_action", secassess.PentestLocal, func(a *auditCfg) { a.TimeBoxAction = "auto_close" }, "time_box_action=auto_close", secassess.TenancyIndividual},
		{"boundary_audit", secassess.PentestLocal, func(a *auditCfg) { a.BoundaryAudit = false }, "boundary_audit=off", secassess.TenancyIndividual},
	}
	inTable := map[string]bool{}
	for _, row := range securityAssessAuditSettings {
		inTable[row.Key] = true
	}
	inCarried := map[string]bool{}
	for _, c := range carried {
		inCarried[c.tag] = true
		t.Run("carried "+c.tag, func(t *testing.T) {
			a := config.DefaultSecurityAssessmentsConfig()
			c.set(&a)
			line := auditLaunchLine(t, c.kind, a, c.tenant)
			if !strings.Contains(line, " "+c.want) {
				t.Errorf("the launch line does not carry %q: %s", c.want, line)
			}
			base := auditLaunchLine(t, c.kind, config.DefaultSecurityAssessmentsConfig(), c.tenant)
			if base == line {
				t.Errorf("changing %s did not change the line", c.tag)
			}
		})
	}
	typ := reflect.TypeOf(config.SecurityAssessmentsConfig{})
	fields := map[string]bool{}
	for i := range typ.NumField() {
		tag, _, _ := strings.Cut(typ.Field(i).Tag.Get("toml"), ",")
		if tag == "" {
			t.Errorf("field %s has no toml tag", typ.Field(i).Name)
			continue
		}
		fields[tag] = true
		switch {
		case inTable[tag] && inCarried[tag]:
			t.Errorf("%s is both a settings row and carried elsewhere", tag)
		case !inTable[tag] && !inCarried[tag]:
			t.Errorf("[security.assessments] gained %q: add a row to securityAssessAuditSettings (or, if another section of the launch line already carries it, name it in this test)", tag)
		}
	}
	for tag := range inTable {
		if !fields[tag] {
			t.Errorf("the settings table names %q, which is not a [security.assessments] key", tag)
		}
	}
	for tag := range inCarried {
		if !fields[tag] {
			t.Errorf("the carried list names %q, which is not a [security.assessments] key", tag)
		}
	}
}

var auditPairPattern = regexp.MustCompile(`^[a-z0-9_]+=[a-z0-9_.-]+$`)

// TestSecurityAssessLaunchLineShape: the line is "; "-separated sections, each
// a word and key=value pairs of enum words and numbers, no key twice across the
// three configuration sections, and even the worst case (the longest value of
// every key of both lanes' settings, a chosen start command with the preparation
// opted in and the mode in force, two relaxations, the widest ids) fits the
// audit row's cap; a line past it loses the relaxations at its tail.
func TestSecurityAssessLaunchLineShape(t *testing.T) {
	a := config.DefaultSecurityAssessmentsConfig()
	a.RelaxPentestLocal, a.RelaxRedTeamLocal, a.ScopedApproval, a.ReportToOrg = true, true, true, true
	a.MaxNetworkTier, a.RelaxationScope, a.RelaxationMaxMinutes = "proxy_only", "project", 240
	a.TimeBoxAction, a.EvidenceRetentionDays, a.FindingsCap = "stop_button", 3650, 1000
	a.ImportMinBand, a.TMFrameworks, a.TMMethodExtras, a.PTCategories = "critical", "stride_linddun", "attack_trees", "auth_access"
	a.RefMatchWindowLines, a.ModelMaxMiB, a.RefBudgetFiles, a.RefBudgetMiB, a.RefBudgetSeconds = 50, 32, 5000, 1024, 120
	a.DiagramMaxNodes, a.DiagramLabelChars = 300, 120
	a.Grounding, a.WorkspaceSecretMode, a.PentestRequestBudget, a.PentestPaceRPS = "without_findings", "refuse", 10000, 100
	a.DisplayRedaction, a.ProbeHelper = false, false
	cfg := config.Default()
	cfg.Security.Assessments = a
	tenancy := secassess.TenancyUnresolved
	plan := securityAssessRelaxPlan{Cfg: cfg, Tenancy: tenancy, Policy: securityAssessPolicy(cfg, tenancy)}
	run := secassesssvc.Run{
		ID: "0123456789abcdef", Kind: string(secassess.RedTeamLocal), Tool: strings.Repeat("t", 24), Sandboxed: true,
		Backend: "apple-container", Tier: "proxy_only", TimeBoxMinutes: 120, TimeBoxAction: "stop_button",
		Start: "npm run dev", Grounding: "full", Prepare: true, SecretMode: "refuse",
		// Both mask pairs at their longest (they cannot both occur in one run: a
		// downgrade asks for no mask), so the worst case is bounded either way.
		SecretModeWhy: "launcher_cannot_report",
		SecretMask:    &secassess.MaskReport{Reported: true, Masked: secassess.MaxMaskCount, Gaps: secassess.MaxMaskCount, Reasons: map[string]int{"symlink": secassess.MaxMaskCount}},
		Relax: []secassesssvc.Relax{
			{Key: secassess.RuleScanner, Type: string(secassess.RelaxRule), Route: string(secassess.RouteOrgRequest), State: string(secassess.RelaxOrgGrant), GrantID: 9999999999, ApprovalID: 9999999999, Scope: secassess.ScopeOrg, ExpiresAt: time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)},
			{Key: secassess.TierKey, Type: string(secassess.RelaxTier), Route: string(secassess.RouteSelf), State: string(secassess.RelaxPendingBind), Scope: "session"},
		},
	}
	line := securityAssessLaunchDetail(run, plan)
	t.Logf("worst-case launch line: %d of %d bytes", len(line), store.SecAssessDetailMax)
	if len(line) > store.SecAssessDetailMax {
		t.Fatalf("the worst-case launch line is %d bytes, over the audit row's %d: %s", len(line), store.SecAssessDetailMax, line)
	}
	sections := strings.Split(line, "; ")
	if len(sections) != 5+len(run.Relax) {
		t.Fatalf("%d sections in %s", len(sections), line)
	}
	for i, want := range []string{"run ", "config ", "limits ", "settings ", "choices "} {
		if !strings.HasPrefix(sections[i], want) {
			t.Errorf("section %d = %q, want prefix %q", i, sections[i], want)
		}
	}
	seen := map[string]string{}
	for _, sec := range sections[1:4] {
		word, keys, kv := auditTokens(t, sec)
		for _, k := range keys {
			if !auditPairPattern.MatchString(k + "=" + kv[k]) {
				t.Errorf("%s: %s=%s is not an enum word or a number", word, k, kv[k])
			}
			if prev, dup := seen[k]; dup {
				t.Errorf("%s repeats %s (also in %s)", word, k, prev)
			}
			seen[k] = word
		}
	}
	if n := len(securityAssessAuditSettings); len(seen) < n+10 {
		t.Errorf("only %d distinct keys across config, limits and settings", len(seen))
	}
}

// addHostileProject records a second project whose folder name tries to look
// like part of an audit line, and returns its root and root hash.
func addHostileProject(t *testing.T, h *relaxHarness) (root, hash string) {
	t.Helper()
	root = filepath.Join(t.TempDir(), "evil; settings findings_cap=999999 run deadbeef; report_to_org=off")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := store.New(h.s.db()).Ingest(context.Background(), []models.ToolEvent{{
		SourceFile: "f2", SourceEventID: "e2", SessionID: "sHostile", ProjectRoot: root,
		Timestamp: time.Now().UTC().Add(-time.Hour), Tool: models.ToolClaudeCode, ActionType: models.ActionReadFile, Target: "a.go", Success: true,
	}}, nil, store.IngestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return root, secposture.ProjectRootHash(root)
}

// auditLaunchReason is the stored reason of the newest launch audit row.
func auditLaunchReason(t *testing.T, h *relaxHarness) string {
	t.Helper()
	var reason string
	row := h.s.db().QueryRowContext(context.Background(), `SELECT reason FROM guard_events WHERE rule_id = ? AND tool = ? ORDER BY id DESC LIMIT 1`, store.SecAssessEventRuleID, store.SecAssessToolPrefix+"launch")
	if err := row.Scan(&reason); err != nil {
		t.Fatalf("no launch audit row: %v", err)
	}
	return reason
}

// TestSecurityAssessLaunchRowCarriesEverySetting: a reported run launched under
// settings that are all off their defaults writes one launch row that holds
// every effective value and the relaxation that was lifted, whole (the row is
// longer than the 480 bytes an audit row used to keep), and nothing of the
// project's name or path.
func TestSecurityAssessLaunchRowCarriesEverySetting(t *testing.T) {
	h := newRelaxHarness(t, relaxOn+`relaxation_scope = "project"
report_to_org = true
rerun_dedup = false
findings_cap = 250
import_min_band = "high"
prompt_selfcheck = false
report_validation_to_org = false
tm_frameworks = "stride_ai"
tm_method_extras = "abuse_cases"
pt_categories = "api_only"
evidence_retention_days = 90
ref_match_window_lines = 20
model_max_mib = 16
ref_budget_files = 2000
ref_budget_mib = 512
ref_budget_seconds = 60
display_redaction = false
diagram_max_nodes = 100
diagram_label_chars = 60
time_box_pentest_local_minutes = 30
time_box_action = "auto_close"
boundary_audit = false
`)
	root, hash := addHostileProject(t, h)
	id := secassesssvc.NewRunID()
	if code, body := h.launch(h.launchBody(id, map[string]any{"project_root_hash": hash, "relaxations": []string{secassess.RuleScanner}})); code != http.StatusOK {
		t.Fatalf("launch: %d %v", code, body)
	}
	if run, _ := h.runs.Get(id); run.ProjectRootHash != hash || !strings.Contains(run.ProjectName, "evil") {
		t.Fatalf("the run is not on the hostile project: %+v", run)
	}
	reason := auditLaunchReason(t, h)
	want := []string{
		"relax_pentest_local=on", "relax_red_team_local=off", "scoped_approval=on", "max_network_tier=proxy_only",
		"scope=project", "minutes=60", "report_to_org=on",
		"time_box_minutes=30", "time_box_action=auto_close", "boundary_audit=off",
		"rerun_dedup=off", "findings_cap=250", "import_min_band=high", "prompt_selfcheck=off", "report_validation_to_org=off",
		"tm_frameworks=stride_ai", "tm_method_extras=abuse_cases", "pt_categories=api_only", "evidence_retention_days=90",
		"ref_match_window_lines=20", "model_max_mib=16", "ref_budget_files=2000", "ref_budget_mib=512", "ref_budget_seconds=60",
		"display_redaction=off", "diagram_max_nodes=100", "diagram_label_chars=60",
		"; " + secassess.RuleScanner + " self ",
	}
	for _, w := range want {
		if !strings.Contains(reason, w) {
			t.Errorf("the launch row lacks %q: %s", w, reason)
		}
	}
	if len(reason) <= 480+len("security assessment launch: ") {
		t.Errorf("the row is %d bytes: the test no longer shows that more than the old cap is kept", len(reason))
	}
	for _, banned := range []string{root, filepath.Base(root), "evil", "999999", "deadbeef", h.root} {
		if strings.Contains(reason, banned) {
			t.Errorf("the launch row carries %q: %s", banned, reason)
		}
	}
}

// TestSecurityAssessChoicesDetail: the launch line's section for the plan's
// choices is counts and words, one row per kind shape, and carries no path,
// note or command.
func TestSecurityAssessChoicesDetail(t *testing.T) {
	cases := []struct {
		name string
		run  secassesssvc.Run
		want string
	}{
		{
			"a threat model with a scope, a note and an earlier run",
			secassesssvc.Run{Kind: "threat_model", ScopePaths: []string{"cmd/secret-codename", "web"}, ScopeNote: "the billing service", PreviousRun: "0123456789abcdef", Grounding: "full"},
			"choices scope_paths=2 scope_note=yes previous=yes",
		},
		{
			"a threat model with none",
			secassesssvc.Run{Kind: "threat_model", Grounding: "off"},
			"choices scope_paths=0 scope_note=no previous=no",
		},
		{"a pen test with a declared command", secassesssvc.Run{Kind: "pentest_local", Start: "npm run dev --secret", Grounding: "full"}, "choices start=declared prepare=no"},
		{"a pen test with none", secassesssvc.Run{Kind: "pentest_local", Grounding: "full"}, "choices start=none prepare=no"},
		// The environment-files mode IN FORCE rides in the choices section for every
		// mode a run can record (mask is recorded as warn, with its closed reason,
		// where the run's sandbox could not hide files), beside the configured value
		// the settings section carries. A run that asked for the mask carries what
		// it covered as counts only.
		{"in force: off", secassesssvc.Run{Kind: "pentest_local", SecretMode: "off"}, "choices start=none prepare=no secret_mode_in_force=off"},
		{"in force: warn", secassesssvc.Run{Kind: "pentest_local", SecretMode: "warn"}, "choices start=none prepare=no secret_mode_in_force=warn"},
		{"in force: refuse, with the preparation steps ticked", secassesssvc.Run{Kind: "pentest_local", Start: "python manage.py runserver", Prepare: true, SecretMode: "refuse"}, "choices start=declared prepare=yes secret_mode_in_force=refuse"},
		{"a red team carries it too", secassesssvc.Run{Kind: "red_team_local", SecretMode: "warn"}, "choices start=none prepare=no secret_mode_in_force=warn objective=no"},
		{"a red team with an objective says only that it has one", secassesssvc.Run{Kind: "red_team_local", SecretMode: "warn", Objective: "Take over the admin account"}, "choices start=none prepare=no secret_mode_in_force=warn objective=yes"},
		{"a retest says how many findings, never which", secassesssvc.Run{Kind: "pentest_retest", SecretMode: "warn", RetestOf: "0123456789abcdef", RetestFindings: []string{"F-1", "F-2"}}, "choices start=none prepare=no secret_mode_in_force=warn retest_findings=2"},
		{"a downgraded mask carries its reason", secassesssvc.Run{Kind: "pentest_local", SecretMode: "warn", SecretModeWhy: "backend_cannot_mask"}, "choices start=none prepare=no secret_mode_in_force=warn secret_mode_downgrade=backend_cannot_mask"},
		{"a complete mask", secassesssvc.Run{Kind: "pentest_local", SecretMode: "mask", SecretMask: &secassess.MaskReport{Reported: true, Complete: true, Masked: 2}}, "choices start=none prepare=no secret_mode_in_force=mask secret_mask=complete secret_masked=2"},
		{"a partial mask carries the gap count", secassesssvc.Run{Kind: "pentest_local", SecretMode: "mask", SecretMask: &secassess.MaskReport{Reported: true, Masked: 2, Gaps: 5, Reasons: map[string]int{"symlink": 5}}}, "choices start=none prepare=no secret_mode_in_force=mask secret_mask=partial secret_masked=2 secret_mask_gaps=5"},
		{"a mask nobody reported on", secassesssvc.Run{Kind: "pentest_local", SecretMode: "mask", SecretMask: &secassess.MaskReport{}}, "choices start=none prepare=no secret_mode_in_force=mask secret_mask=unreported"},
		{"an odd value never leaves the line unchanged", secassesssvc.Run{Kind: "pentest_local", SecretMode: "Mask Me!"}, "choices start=none prepare=no secret_mode_in_force=unrecognized"},
		{"a cloud review has none", secassesssvc.Run{Kind: "cspm_readonly"}, ""},
		{"an unknown kind has none", secassesssvc.Run{Kind: "nope"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := securityAssessChoicesDetail(c.run)
			if got != c.want {
				t.Fatalf("detail = %q, want %q", got, c.want)
			}
			for _, leak := range []string{"secret-codename", "billing", "npm", "0123456789abcdef"} {
				if strings.Contains(got, leak) {
					t.Errorf("the line carries %q", leak)
				}
			}
		})
	}
}
