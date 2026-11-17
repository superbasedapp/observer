package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestSecurityAssessmentsDefaults: with nothing configured nothing is lifted,
// and a file that sets one key keeps the others' safe defaults (plan 13.3).
func TestSecurityAssessmentsDefaults(t *testing.T) {
	t.Parallel()
	d := DefaultSecurityConfig().Assessments
	if d.RelaxPentestLocal || d.RelaxRedTeamLocal || d.ScopedApproval || d.ReportToOrg {
		t.Fatalf("a default relaxes something: %+v", d)
	}
	if d.MaxNetworkTier != "proxy_only" || d.RelaxationScope != "session" || d.RelaxationMaxMinutes != 60 {
		t.Fatalf("defaults %+v", d)
	}
	if d.TimeBoxThreatModelMinutes != 60 || d.TimeBoxPentestLocalMinutes != 45 || d.TimeBoxRedTeamLocalMinutes != 60 ||
		d.TimeBoxAction != "stop_button" || !d.BoundaryAudit || d.EvidenceRetentionDays != 0 {
		t.Fatalf("depth defaults %+v", d)
	}
	if !d.RerunDedup || d.FindingsCap != 0 || d.ImportMinBand != "low" || !d.PromptSelfcheck || !d.ReportValidationToOrg ||
		d.TMFrameworks != "all" || d.TMMethodExtras != "both" || d.PTCategories != "all" {
		t.Fatalf("model contract defaults %+v", d)
	}
	if d.RefMatchWindowLines != 5 || d.ModelMaxMiB != 4 || d.RefBudgetFiles != 500 || d.RefBudgetMiB != 128 || d.RefBudgetSeconds != 10 {
		t.Fatalf("check-bound defaults %+v", d)
	}
	if d.Grounding != "full" || d.WorkspaceSecretMode != "mask" || d.PentestRequestBudget != 600 || d.PentestPaceRPS != 5 {
		t.Fatalf("depth W3/W4 defaults %+v", d)
	}
	if !d.DisplayRedaction || d.DiagramMaxNodes != 60 || d.DiagramLabelChars != 40 {
		t.Fatalf("model view defaults %+v", d)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("[security.assessments]\nrelax_pentest_local = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Security.Assessments
	if !a.RelaxPentestLocal || a.RelaxRedTeamLocal || a.MaxNetworkTier != "proxy_only" || a.RelaxationScope != "session" || a.RelaxationMaxMinutes != 60 {
		t.Fatalf("partial merge: %+v", a)
	}
	if a.TimeBoxPentestLocalMinutes != 45 || a.TimeBoxAction != "stop_button" || !a.BoundaryAudit {
		t.Fatalf("partial merge dropped a depth default: %+v", a)
	}
	if !a.RerunDedup || a.FindingsCap != 0 || a.ImportMinBand != "low" || !a.PromptSelfcheck || !a.ReportValidationToOrg || a.TMFrameworks != "all" || a.PTCategories != "all" {
		t.Fatalf("partial merge dropped a model contract default: %+v", a)
	}
	if a.RefMatchWindowLines != 5 || a.ModelMaxMiB != 4 || a.RefBudgetFiles != 500 || a.RefBudgetMiB != 128 || a.RefBudgetSeconds != 10 {
		t.Fatalf("partial merge dropped a check-bound default: %+v", a)
	}
	if a.Grounding != "full" || a.WorkspaceSecretMode != "mask" || a.PentestRequestBudget != 600 || a.PentestPaceRPS != 5 {
		t.Fatalf("partial merge dropped a W3/W4 default: %+v", a)
	}
	if !a.DisplayRedaction || a.DiagramMaxNodes != 60 || a.DiagramLabelChars != 40 {
		t.Fatalf("partial merge dropped a model view default: %+v", a)
	}
}

// TestValidateSecurityAssessments: a tier, scope or window outside the closed
// sets does not validate; the window accepts any whole number from 5 to 240
// so a lowering pin never fails validation.
func TestValidateSecurityAssessments(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(c *SecurityAssessmentsConfig)
		bad    string
	}{
		{"defaults", func(*SecurityAssessmentsConfig) {}, ""},
		{"internet tier", func(c *SecurityAssessmentsConfig) { c.MaxNetworkTier = "internet" }, ""},
		{"host tier is never an option", func(c *SecurityAssessmentsConfig) { c.MaxNetworkTier = "host" }, "max_network_tier"},
		{"a made-up tier", func(c *SecurityAssessmentsConfig) { c.MaxNetworkTier = "" }, "max_network_tier"},
		{"project scope", func(c *SecurityAssessmentsConfig) { c.RelaxationScope = "project" }, ""},
		{"global scope is never an option", func(c *SecurityAssessmentsConfig) { c.RelaxationScope = "global" }, "relaxation_scope"},
		{"a pinned 45 minute ceiling", func(c *SecurityAssessmentsConfig) { c.RelaxationMaxMinutes = 45 }, ""},
		{"4 minutes", func(c *SecurityAssessmentsConfig) { c.RelaxationMaxMinutes = 4 }, "relaxation_max_minutes"},
		{"241 minutes", func(c *SecurityAssessmentsConfig) { c.RelaxationMaxMinutes = 241 }, "relaxation_max_minutes"},
		{"zero minutes", func(c *SecurityAssessmentsConfig) { c.RelaxationMaxMinutes = 0 }, "relaxation_max_minutes"},
		{"a 90 minute pen test box", func(c *SecurityAssessmentsConfig) { c.TimeBoxPentestLocalMinutes = 90 }, ""},
		{"a 4 minute threat model box", func(c *SecurityAssessmentsConfig) { c.TimeBoxThreatModelMinutes = 4 }, "time_box_threat_model_minutes"},
		{"a 241 minute red team box", func(c *SecurityAssessmentsConfig) { c.TimeBoxRedTeamLocalMinutes = 241 }, "time_box_red_team_local_minutes"},
		{"a zero pen test box", func(c *SecurityAssessmentsConfig) { c.TimeBoxPentestLocalMinutes = 0 }, "time_box_pentest_local_minutes"},
		{"auto close", func(c *SecurityAssessmentsConfig) { c.TimeBoxAction = "auto_close" }, ""},
		{"a made-up box action", func(c *SecurityAssessmentsConfig) { c.TimeBoxAction = "kill" }, "time_box_action"},
		{"the audit off", func(c *SecurityAssessmentsConfig) { c.BoundaryAudit = false }, ""},
		{"retention in days", func(c *SecurityAssessmentsConfig) { c.EvidenceRetentionDays = 90 }, ""},
		{"a negative retention", func(c *SecurityAssessmentsConfig) { c.EvidenceRetentionDays = -1 }, "evidence_retention_days"},
		{"a retention beyond ten years", func(c *SecurityAssessmentsConfig) { c.EvidenceRetentionDays = 3651 }, "evidence_retention_days"},
		{"dedup off", func(c *SecurityAssessmentsConfig) { c.RerunDedup = false }, ""},
		{"a cap of 100", func(c *SecurityAssessmentsConfig) { c.FindingsCap = 100 }, ""},
		{"a cap at the import ceiling", func(c *SecurityAssessmentsConfig) { c.FindingsCap = 1000 }, ""},
		{"a cap past the import ceiling", func(c *SecurityAssessmentsConfig) { c.FindingsCap = 1001 }, "findings_cap"},
		{"a negative cap", func(c *SecurityAssessmentsConfig) { c.FindingsCap = -1 }, "findings_cap"},
		{"a high minimum band", func(c *SecurityAssessmentsConfig) { c.ImportMinBand = "high" }, ""},
		{"a made-up band", func(c *SecurityAssessmentsConfig) { c.ImportMinBand = "severe" }, "import_min_band"},
		{"the self-check off", func(c *SecurityAssessmentsConfig) { c.PromptSelfcheck = false }, ""},
		{"org reporting of the check off", func(c *SecurityAssessmentsConfig) { c.ReportValidationToOrg = false }, ""},
		{"stride and the AI frameworks", func(c *SecurityAssessmentsConfig) { c.TMFrameworks = "stride_ai" }, ""},
		{"a made-up framework preset", func(c *SecurityAssessmentsConfig) { c.TMFrameworks = "pasta" }, "tm_frameworks"},
		{"abuse cases only", func(c *SecurityAssessmentsConfig) { c.TMMethodExtras = "abuse_cases" }, ""},
		{"an empty method preset", func(c *SecurityAssessmentsConfig) { c.TMMethodExtras = "" }, "tm_method_extras"},
		{"api only categories", func(c *SecurityAssessmentsConfig) { c.PTCategories = "api_only" }, ""},
		{"a made-up category preset", func(c *SecurityAssessmentsConfig) { c.PTCategories = "mobile" }, "pt_categories"},
		{"a one line match window", func(c *SecurityAssessmentsConfig) { c.RefMatchWindowLines = 1 }, ""},
		{"a 50 line match window", func(c *SecurityAssessmentsConfig) { c.RefMatchWindowLines = 50 }, ""},
		{"a zero match window", func(c *SecurityAssessmentsConfig) { c.RefMatchWindowLines = 0 }, "ref_match_window_lines"},
		{"a 51 line match window", func(c *SecurityAssessmentsConfig) { c.RefMatchWindowLines = 51 }, "ref_match_window_lines"},
		{"a 32 MiB model", func(c *SecurityAssessmentsConfig) { c.ModelMaxMiB = 32 }, ""},
		{"a zero MiB model", func(c *SecurityAssessmentsConfig) { c.ModelMaxMiB = 0 }, "model_max_mib"},
		{"a 33 MiB model", func(c *SecurityAssessmentsConfig) { c.ModelMaxMiB = 33 }, "model_max_mib"},
		{"a 5000 file ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetFiles = 5000 }, ""},
		{"a 49 file ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetFiles = 49 }, "ref_budget_files"},
		{"a 5001 file ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetFiles = 5001 }, "ref_budget_files"},
		{"a 1024 MiB ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetMiB = 1024 }, ""},
		{"a 15 MiB ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetMiB = 15 }, "ref_budget_mib"},
		{"a 1025 MiB ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetMiB = 1025 }, "ref_budget_mib"},
		{"a 120 second ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetSeconds = 120 }, ""},
		{"a zero second ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetSeconds = 0 }, "ref_budget_seconds"},
		{"a 121 second ref budget", func(c *SecurityAssessmentsConfig) { c.RefBudgetSeconds = 121 }, "ref_budget_seconds"},
		{"the digest without findings", func(c *SecurityAssessmentsConfig) { c.Grounding = "without_findings" }, ""},
		{"the digest off", func(c *SecurityAssessmentsConfig) { c.Grounding = "off" }, ""},
		{"a made-up grounding mode", func(c *SecurityAssessmentsConfig) { c.Grounding = "deep" }, "grounding"},
		{"an empty grounding mode", func(c *SecurityAssessmentsConfig) { c.Grounding = "" }, "grounding"},
		{"secret files warn", func(c *SecurityAssessmentsConfig) { c.WorkspaceSecretMode = "warn" }, ""},
		{"secret files refuse", func(c *SecurityAssessmentsConfig) { c.WorkspaceSecretMode = "refuse" }, ""},
		{"secret files off", func(c *SecurityAssessmentsConfig) { c.WorkspaceSecretMode = "off" }, ""},
		{"a made-up secret mode", func(c *SecurityAssessmentsConfig) { c.WorkspaceSecretMode = "hide" }, "workspace_secret_mode"},
		{"a 10 request budget", func(c *SecurityAssessmentsConfig) { c.PentestRequestBudget = 10 }, ""},
		{"a 10000 request budget", func(c *SecurityAssessmentsConfig) { c.PentestRequestBudget = 10000 }, ""},
		{"a 9 request budget", func(c *SecurityAssessmentsConfig) { c.PentestRequestBudget = 9 }, "pentest_request_budget"},
		{"a 10001 request budget", func(c *SecurityAssessmentsConfig) { c.PentestRequestBudget = 10001 }, "pentest_request_budget"},
		{"a pace of 1", func(c *SecurityAssessmentsConfig) { c.PentestPaceRPS = 1 }, ""},
		{"a pace of 100", func(c *SecurityAssessmentsConfig) { c.PentestPaceRPS = 100 }, ""},
		{"a pace of 0", func(c *SecurityAssessmentsConfig) { c.PentestPaceRPS = 0 }, "pentest_pace_rps"},
		{"a pace of 101", func(c *SecurityAssessmentsConfig) { c.PentestPaceRPS = 101 }, "pentest_pace_rps"},
		{"a 10 node diagram", func(c *SecurityAssessmentsConfig) { c.DiagramMaxNodes = 10 }, ""},
		{"a 300 node diagram", func(c *SecurityAssessmentsConfig) { c.DiagramMaxNodes = 300 }, ""},
		{"a 9 node diagram", func(c *SecurityAssessmentsConfig) { c.DiagramMaxNodes = 9 }, "diagram_max_nodes"},
		{"a 301 node diagram", func(c *SecurityAssessmentsConfig) { c.DiagramMaxNodes = 301 }, "diagram_max_nodes"},
		{"a zero node diagram", func(c *SecurityAssessmentsConfig) { c.DiagramMaxNodes = 0 }, "diagram_max_nodes"},
		{"a 10 character diagram label", func(c *SecurityAssessmentsConfig) { c.DiagramLabelChars = 10 }, ""},
		{"a 120 character diagram label", func(c *SecurityAssessmentsConfig) { c.DiagramLabelChars = 120 }, ""},
		{"a 9 character diagram label", func(c *SecurityAssessmentsConfig) { c.DiagramLabelChars = 9 }, "diagram_label_chars"},
		{"a 121 character diagram label", func(c *SecurityAssessmentsConfig) { c.DiagramLabelChars = 121 }, "diagram_label_chars"},
		{"a zero character diagram label", func(c *SecurityAssessmentsConfig) { c.DiagramLabelChars = 0 }, "diagram_label_chars"},
		{"display redaction off", func(c *SecurityAssessmentsConfig) { c.DisplayRedaction = false }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultSecurityAssessmentsConfig()
			tc.mutate(&c)
			err := validateSecurityAssessments(c)
			switch {
			case tc.bad == "" && err != nil:
				t.Fatalf("unexpected: %v", err)
			case tc.bad != "" && (err == nil || !strings.Contains(err.Error(), tc.bad)):
				t.Fatalf("err = %v, want one naming %s", err, tc.bad)
			}
		})
	}
}

// TestSecurityAssessmentsKeysMatchTheRelaxationTable (plan 13.3): every kind
// with rows in the module's relaxation table has exactly one relax_<kind> key,
// and every relax_ key names a kind with rows.
func TestSecurityAssessmentsKeysMatchTheRelaxationTable(t *testing.T) {
	t.Parallel()
	var keys []string
	for _, r := range SecuritySettings() {
		if k, ok := strings.CutPrefix(r.Key, "security.assessments.relax_"); ok {
			keys = append(keys, "relax_"+k)
		}
	}
	var want []string
	for _, k := range secassess.RelaxKinds() {
		want = append(want, secassess.RelaxConfigKey(k))
	}
	slices.Sort(keys)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Fatalf("relax keys in the contract %v, kinds with rows %v", keys, want)
	}
}

// TestSecurityAssessmentsClasses: the five capability keys are class P (the
// organization may pin them) and have a governance pin row that can only
// narrow; the scope and the reporting switch are local settings.
func TestSecurityAssessmentsClasses(t *testing.T) {
	t.Parallel()
	classes := map[string]SettingClass{}
	for _, r := range SecuritySettings() {
		if strings.HasPrefix(r.Key, "security.assessments.") {
			classes[r.Key] = r.Class
		}
	}
	wantP := []string{"relax_pentest_local", "relax_red_team_local", "scoped_approval", "max_network_tier", "relaxation_max_minutes"}
	for _, k := range wantP {
		key := "security.assessments." + k
		if classes[key] != SettingPolicy {
			t.Errorf("%s is class %q, want P", key, classes[key])
		}
		if _, ok := governancePinnableByKey[key]; !ok {
			t.Errorf("%s has no governance pin row", key)
		}
	}
	// The W3/W4 keys: grounding is local; the secret handling and the two
	// request limits are policy keys with a pin row.
	for _, k := range []string{"workspace_secret_mode", "pentest_request_budget", "pentest_pace_rps", "probe_helper"} {
		key := "security.assessments." + k
		if classes[key] != SettingPolicy {
			t.Errorf("%s is class %q, want P", key, classes[key])
		}
		if _, ok := governancePinnableByKey[key]; !ok {
			t.Errorf("%s has no governance pin row", key)
		}
	}
	if k := "security.assessments.grounding"; classes[k] != SettingLocal {
		t.Errorf("%s is class %q, want U", k, classes[k])
	} else if _, ok := governancePinnableByKey[k]; ok {
		t.Errorf("%s must not be pinnable", k)
	}
	for _, k := range []string{"relaxation_scope", "report_to_org"} {
		key := "security.assessments." + k
		if classes[key] != SettingLocal {
			t.Errorf("%s is class %q, want U", key, classes[key])
		}
		if _, ok := governancePinnableByKey[key]; ok {
			t.Errorf("%s must not be pinnable", key)
		}
	}
}

// TestSecurityAssessmentsPinsOnlyNarrow: through the governance overlay a pin
// turns a capability off and holds the tier, a pin that would switch it on is
// skipped, and the minutes pin is a ceiling.
func TestSecurityAssessmentsPinsOnlyNarrow(t *testing.T) {
	t.Parallel()
	local := Default()
	local.Security.Assessments = SecurityAssessmentsConfig{
		RelaxPentestLocal: true, RelaxRedTeamLocal: true, ScopedApproval: true,
		MaxNetworkTier: "internet", RelaxationScope: "session", RelaxationMaxMinutes: 240,
	}
	got, out := ApplyGovernancePinsTo(local, map[string]any{
		"security.assessments.relax_pentest_local":    false,
		"security.assessments.max_network_tier":       "proxy_only",
		"security.assessments.relaxation_max_minutes": int64(30),
	})
	a := got.Security.Assessments
	if a.RelaxPentestLocal || a.MaxNetworkTier != "proxy_only" || a.RelaxationMaxMinutes != 30 {
		t.Fatalf("pins did not narrow: %+v (outcome %+v)", a, out)
	}
	if !a.RelaxRedTeamLocal || !a.ScopedApproval {
		t.Fatalf("an unpinned key changed: %+v", a)
	}
	// A pin that would switch a capability ON is not applied.
	off := Default()
	got, _ = ApplyGovernancePinsTo(off, map[string]any{
		"security.assessments.relax_red_team_local": true,
		"security.assessments.max_network_tier":     "internet",
	})
	if a := got.Security.Assessments; a.RelaxRedTeamLocal || a.MaxNetworkTier != "proxy_only" {
		t.Fatalf("an org pin switched a capability on: %+v", a)
	}
	// The pen test limits: the budget and pace pins are ceilings, the .env
	// handling only tightens to refusing the launch.
	lim := Default()
	lim.Security.Assessments.PentestRequestBudget = 2400
	lim.Security.Assessments.PentestPaceRPS = 10
	lim.Security.Assessments.WorkspaceSecretMode = "warn"
	got, _ = ApplyGovernancePinsTo(lim, map[string]any{
		"security.assessments.pentest_request_budget": int64(600),
		"security.assessments.pentest_pace_rps":       int64(2),
		"security.assessments.workspace_secret_mode":  "refuse",
	})
	if a := got.Security.Assessments; a.PentestRequestBudget != 600 || a.PentestPaceRPS != 2 || a.WorkspaceSecretMode != "refuse" {
		t.Fatalf("the W4 pins did not narrow: %+v", a)
	}
	loose := Default()
	loose.Security.Assessments.WorkspaceSecretMode = "refuse"
	loose.Security.Assessments.PentestRequestBudget = 200
	got, _ = ApplyGovernancePinsTo(loose, map[string]any{
		"security.assessments.workspace_secret_mode":  "off",
		"security.assessments.pentest_request_budget": int64(2400),
	})
	if a := got.Security.Assessments; a.WorkspaceSecretMode != "refuse" || a.PentestRequestBudget != 200 {
		t.Fatalf("an org pin loosened a W4 key: %+v", a)
	}
	// A local value below the org's ceiling keeps it.
	low := Default()
	low.Security.Assessments.RelaxationMaxMinutes = 15
	got, _ = ApplyGovernancePinsTo(low, map[string]any{"security.assessments.relaxation_max_minutes": int64(120)})
	if m := got.Security.Assessments.RelaxationMaxMinutes; m != 15 {
		t.Fatalf("a ceiling raised a lower local value to %d", m)
	}
}

// TestSecurityAssessmentsPresetsMatchTheTables: a preset the settings offer is
// a preset the module's tables define, in the same order, so a picker can never
// name one the prompt and the validator do not know.
func TestSecurityAssessmentsPresetsMatchTheTables(t *testing.T) {
	t.Parallel()
	ids := func(ps []secassess.Preset) []string {
		out := make([]string, len(ps))
		for i, p := range ps {
			out[i] = p.ID
		}
		return out
	}
	for _, tc := range []struct {
		name string
		got  []string
		want []string
	}{
		{"frameworks", SecurityAssessmentsFrameworkPresets, ids(secassess.FrameworkPresets)},
		{"method extras", SecurityAssessmentsExtraPresets, ids(secassess.MethodExtraPresets)},
		{"categories", SecurityAssessmentsCategoryPresets, ids(secassess.CategoryPresets)},
	} {
		if !slices.Equal(tc.got, tc.want) {
			t.Errorf("%s: settings offer %v, the tables define %v", tc.name, tc.got, tc.want)
		}
	}
	var bands []string
	for _, b := range secassess.Bands {
		bands = append(bands, string(b))
	}
	if !slices.Equal(SecurityAssessmentsBands, bands) {
		t.Errorf("bands: settings offer %v, the table defines %v", SecurityAssessmentsBands, bands)
	}
	grounding := []string{string(secassess.GroundingFull), string(secassess.GroundingNoFindings), string(secassess.GroundingOff)}
	if !slices.Equal(SecurityAssessmentsGroundingModes, grounding) {
		t.Errorf("grounding: settings offer %v, the table defines %v", SecurityAssessmentsGroundingModes, grounding)
	}
	// Every default is the first (widest) preset of its list, and resolves.
	d := DefaultSecurityAssessmentsConfig()
	for _, tc := range []struct {
		list []secassess.Preset
		id   string
	}{
		{secassess.FrameworkPresets, d.TMFrameworks},
		{secassess.MethodExtraPresets, d.TMMethodExtras},
		{secassess.CategoryPresets, d.PTCategories},
	} {
		if _, ok := secassess.ResolvePreset(tc.list, tc.id); !ok || tc.list[0].ID != tc.id {
			t.Errorf("default %q is not the first preset %q", tc.id, tc.list[0].ID)
		}
	}
}

// TestSecurityAssessmentsDiagramBoundsMatchTheRenderer: the diagram size the
// settings accept and offer is the renderer's own range (this package imports
// neither side of it, so a test ties them), the default is the renderer's
// default, and every picker value validates.
func TestSecurityAssessmentsDiagramBoundsMatchTheRenderer(t *testing.T) {
	t.Parallel()
	if securityAssessmentsMaxDiagramNodes != secassess.MaxMermaidNodes {
		t.Errorf("the settings accept up to %d nodes, the renderer draws at most %d", securityAssessmentsMaxDiagramNodes, secassess.MaxMermaidNodes)
	}
	if d := DefaultSecurityAssessmentsConfig(); d.DiagramMaxNodes != secassess.DefaultMermaidNodes {
		t.Errorf("default %d, the renderer's default is %d", d.DiagramMaxNodes, secassess.DefaultMermaidNodes)
	}
	for _, n := range SecurityAssessmentsDiagramNodes {
		c := DefaultSecurityAssessmentsConfig()
		c.DiagramMaxNodes = n
		if err := validateSecurityAssessments(c); err != nil {
			t.Errorf("the picker offers %d, which does not validate: %v", n, err)
		}
	}
}

// TestSecurityAssessmentsDiagramLabelBoundsMatchTheRenderer: the label length
// the settings accept and offer is the renderer's own range, the default is the
// renderer's default, and every picker value validates.
func TestSecurityAssessmentsDiagramLabelBoundsMatchTheRenderer(t *testing.T) {
	t.Parallel()
	if securityAssessmentsMaxDiagramLabelChars != secassess.MaxMermaidLabelChars {
		t.Errorf("the settings accept up to %d characters, the renderer keeps at most %d", securityAssessmentsMaxDiagramLabelChars, secassess.MaxMermaidLabelChars)
	}
	if d := DefaultSecurityAssessmentsConfig(); d.DiagramLabelChars != secassess.DefaultMermaidLabelChars {
		t.Errorf("default %d, the renderer's default is %d", d.DiagramLabelChars, secassess.DefaultMermaidLabelChars)
	}
	for _, n := range SecurityAssessmentsDiagramLabelChars {
		c := DefaultSecurityAssessmentsConfig()
		c.DiagramLabelChars = n
		if err := validateSecurityAssessments(c); err != nil {
			t.Errorf("the picker offers %d, which does not validate: %v", n, err)
		}
	}
}

// TestSecurityAssessmentsProbeHelperPin: the request helper is a policy switch
// an organization may pin off and never on (depth plan W5b), on by default.
func TestSecurityAssessmentsProbeHelperPin(t *testing.T) {
	t.Parallel()
	const key = "security.assessments.probe_helper"
	if !Default().Security.Assessments.ProbeHelper {
		t.Fatal("the request helper is not on by default")
	}
	got, _ := ApplyGovernancePinsTo(Default(), map[string]any{key: false})
	if got.Security.Assessments.ProbeHelper {
		t.Error("an org pin could not switch the helper off")
	}
	off := Default()
	off.Security.Assessments.ProbeHelper = false
	got, _ = ApplyGovernancePinsTo(off, map[string]any{key: true})
	if got.Security.Assessments.ProbeHelper {
		t.Error("an org pin switched the helper on")
	}
}
