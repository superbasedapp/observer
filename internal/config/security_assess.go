package config

import (
	"fmt"
	"slices"
)

// security_assess.go is [security.assessments]: what the agent-run security
// assessments module may ask the developer (or, on a managed node, the
// organization) to lift for one run (docs/plans/security-assessments-module-
// plan-2026-11-13.md section 13.3). Every key defaults to the safest value, so
// a config that names nothing offers no relaxation. The five capability keys
// are class P: the organization may pin them to their safe value (the minutes
// as a ceiling) through node governance (nodegov.PinnableKeys). The scope and
// the org-reporting switch are local experience settings. An agent can never
// change one: R-165 refuses any [security] change.

// SecurityAssessmentsConfig is [security.assessments].
type SecurityAssessmentsConfig struct {
	// RelaxPentestLocal lets the penetration test ask for its relaxation rows
	// (guard rule R-179, the wider sandbox network). Default false.
	RelaxPentestLocal bool `toml:"relax_pentest_local"`
	// RelaxRedTeamLocal is the same for the red team exercise. Default false.
	RelaxRedTeamLocal bool `toml:"relax_red_team_local"`
	// ScopedApproval lets the guard-rule rows be asked for at launch (a local
	// approval on an individual node, an org request on a managed one). With
	// it off only the tier row is offered. Default false.
	ScopedApproval bool `toml:"scoped_approval"`
	// MaxNetworkTier is the widest live sandbox network tier the tier row
	// accepts: one of SecurityAssessmentsTiers. The host tier is never an
	// option. Default "proxy_only", which offers no tier relaxation.
	MaxNetworkTier string `toml:"max_network_tier"`
	// RelaxationScope is what a LOCAL approval covers: "session" (the run's
	// terminal session) or "project" (every session in the project, sandboxed
	// or not; an individual node only, a managed node is always session).
	RelaxationScope string `toml:"relaxation_scope"`
	// RelaxationMaxMinutes is the hard cap of a local approval's life and the
	// window an org request asks for. The picker offers
	// SecurityAssessmentsMinutes; validation accepts any whole number from 5
	// to 240 so a lowering pin from the organization never fails validation.
	// A managed node caps it at 60.
	RelaxationMaxMinutes int `toml:"relaxation_max_minutes"`
	// ReportToOrg writes the run's audit rows on an individual node, which
	// then ship with the guard events when the node is enrolled and pushing.
	// A managed node always writes them. Default false.
	ReportToOrg bool `toml:"report_to_org"`
	// TimeBoxThreatModelMinutes, TimeBoxPentestLocalMinutes and
	// TimeBoxRedTeamLocalMinutes are the time boxes the prompt states and the run
	// row shows, per kind. The pickers offer SecurityAssessmentsThreatModelBoxes
	// and SecurityAssessmentsPentestBoxes; validation accepts any whole number
	// from 5 to 240 so a lowering pin from the organization never fails
	// validation. Defaults 60, 45 and 60.
	TimeBoxThreatModelMinutes  int `toml:"time_box_threat_model_minutes"`
	TimeBoxPentestLocalMinutes int `toml:"time_box_pentest_local_minutes"`
	TimeBoxRedTeamLocalMinutes int `toml:"time_box_red_team_local_minutes"`
	// TimeBoxAction is what happens at the deadline: "stop_button" (the run row
	// offers Stop; nothing is closed for the developer) or "auto_close" (Observer
	// closes the terminal). Default "stop_button".
	TimeBoxAction string `toml:"time_box_action"`
	// BoundaryAudit takes the git-state snapshots before and after a run. With
	// it off the run row says the check was not made. Default true.
	BoundaryAudit bool `toml:"boundary_audit"`
	// EvidenceRetentionDays is how long a run's stored model and snapshots are
	// kept: 0 keeps them as long as the run is in the run record (the newest
	// 100), otherwise a number of days. A local setting: an organization has no
	// direction to pin, because "keep longest" is the widest value. Default 0.
	EvidenceRetentionDays int `toml:"evidence_retention_days"`

	// The keys below belong to the model contract (depth plan W1c). All are
	// local experience settings: none is a capability an organization would
	// pin, and each is the widest or the recommended value by default.

	// RerunDedup gives an imported finding a rule id and fingerprint that carry
	// no run id, so a re-run of the same assessment updates the findings it
	// already imported instead of adding a second copy. Off keeps the run id in
	// the rule id, so each run stands alone. Default true.
	RerunDedup bool `toml:"rerun_dedup"`
	// FindingsCap is the most findings one run imports, highest risk first: 0
	// is no cap of this key's own. Whatever is left out is counted on the run
	// row. The importer keeps at most 1000 results per run whatever this is
	// (an operator-accepted bound, ruled 2026-11-14); a run past it is counted
	// and shown as over the ceiling. Default 0.
	FindingsCap int `toml:"findings_cap"`
	// ImportMinBand is the lowest risk band a derived finding is imported at:
	// one of SecurityAssessmentsBands. Default "low" (every finding that has a
	// location in the code).
	ImportMinBand string `toml:"import_min_band"`
	// PromptSelfcheck names the self-check command in the task, so the agent
	// checks its own assessment.json before it finishes. Default true.
	PromptSelfcheck bool `toml:"prompt_selfcheck"`
	// ReportValidationToOrg writes a content-free "validated" audit row when a
	// run is checked, for a run that is reported to the organization. Default
	// true.
	ReportValidationToOrg bool `toml:"report_validation_to_org"`
	// TMFrameworks is which frameworks the threat model asks for and holds the
	// model to: one of SecurityAssessmentsFrameworkPresets. STRIDE is in every
	// one. Default "all".
	TMFrameworks string `toml:"tm_frameworks"`
	// TMMethodExtras is whether the threat model is asked for abuse cases and an
	// attack tree: one of SecurityAssessmentsExtraPresets. Default "both".
	TMMethodExtras string `toml:"tm_method_extras"`
	// PTCategories is which test categories a penetration test covers and the
	// check counts: one of SecurityAssessmentsCategoryPresets. Default "all".
	PTCategories string `toml:"pt_categories"`

	// The keys below are the check's own bounds (depth plan, review fix). They
	// are local settings: a larger value is the wider one, and each default is
	// the recommended answer.

	// RefMatchWindowLines is how close to a cited line the cited text has to be
	// for a reference to read "found": the text must sit on a code line within
	// this many lines counted from the first cited line (1 is the cited line
	// itself). A reference whose text is further away in the range is "exists",
	// never credited as found. The picker offers SecurityAssessmentsRefWindows;
	// validation accepts 1 to 50. Default 5.
	RefMatchWindowLines int `toml:"ref_match_window_lines"`
	// ModelMaxMiB is the size cap of the assessment.json the agent writes, in
	// MiB. A file over it is refused with the reason "too_large" and the cap is
	// named. The picker offers SecurityAssessmentsModelMaxMiB; validation
	// accepts 1 to 32. Default 4.
	ModelMaxMiB int `toml:"model_max_mib"`
	// RefBudgetFiles, RefBudgetMiB and RefBudgetSeconds are the budget of the
	// reference check: how many distinct project files it opens, how much it
	// reads in all and how long it looks. Past a limit the remaining references
	// read "unchecked" (never "found"), the validation is "partial" and the
	// card says how many were not checked. Pickers: SecurityAssessmentsRefFiles,
	// SecurityAssessmentsRefMiB, SecurityAssessmentsRefSeconds; validation
	// accepts 50 to 5000 files, 16 to 1024 MiB and 1 to 120 seconds. Defaults
	// 500, 128 and 10.
	RefBudgetFiles   int `toml:"ref_budget_files"`
	RefBudgetMiB     int `toml:"ref_budget_mib"`
	RefBudgetSeconds int `toml:"ref_budget_seconds"`

	// The keys below belong to threat-model and penetration-test depth (depth
	// plan W3 and W4).

	// Grounding is what the grounding digest carries: "full" (languages,
	// dependencies by role, infrastructure files, a spec, start hints and the
	// project's open findings), "without_findings" (the same without the
	// open-findings list) or "off" (no digest). A local setting. Default "full".
	Grounding string `toml:"grounding"`
	// WorkspaceSecretMode is what happens to the .env files in the live
	// workspace of a penetration test box, which the box can read: "off" (say
	// nothing), "warn" (the plan says how many there are and the task tells the
	// agent not to open them), "mask" (hide them inside the box by file name,
	// as a snapshot taken when it starts, which only a sandbox that can do it
	// does; for any other the effective mode is "warn", and the plan says why) or
	// "refuse" (the launch is refused while the findings store holds an open
	// secret finding in one). An organization may pin "refuse". Default "mask".
	WorkspaceSecretMode string `toml:"workspace_secret_mode"`
	// PentestRequestBudget is the most requests a penetration test or red team
	// run is asked to send in all; the picker offers
	// SecurityAssessmentsRequestBudgets, validation accepts 10 to 10000 so a
	// lowering pin never fails validation. A policy ceiling. Default 600.
	PentestRequestBudget int `toml:"pentest_request_budget"`
	// PentestPaceRPS is the most requests per second the run is asked to send;
	// the picker offers SecurityAssessmentsPaces, validation accepts 1 to 100.
	// A policy ceiling. Default 5.
	PentestPaceRPS int `toml:"pentest_pace_rps"`
	// ProbeHelper writes the request helper (probe.py and its settings file
	// probe.json) into the run folder of a penetration test or red team run
	// before the agent starts. The agent sends its requests to the target
	// through it, and the helper logs each one, which is what lets a finding
	// read "Helper log matches". Off writes nothing and every finding's
	// evidence reads "No log". A policy switch: an organization may pin off,
	// never on. Default true.
	ProbeHelper bool `toml:"probe_helper"`

	// The keys below belong to the model view (depth plan W5a and W6a). Both
	// are local experience settings and each default is the recommended value.

	// DisplayRedaction hides the secrets Observer recognises when the agent's
	// report and the checked model are shown on the dashboard. It changes what
	// is displayed only: the files in the project are as the agent wrote them,
	// and the free text of the stored copy of a checked model was redacted when it
	// was written whatever this key says (ids, references and paths are keys and
	// are shown and stored as written). Off shows the stored text as it is. Default true.
	DisplayRedaction bool `toml:"display_redaction"`
	// DiagramMaxNodes is the most nodes the data-flow diagram source of a
	// threat model draws; the model has no such limit, the diagram does, so a
	// large model still reads. Nodes past it are counted, never silent. The
	// picker offers SecurityAssessmentsDiagramNodes; validation accepts 10 to
	// 300. Default 60.
	DiagramMaxNodes int `toml:"diagram_max_nodes"`
	// DiagramLabelChars is the most characters of the agent's own text a label
	// of the data-flow diagram source keeps (a component, actor, zone or flow
	// label is cut to it, and the view says how many labels were cut). The
	// picker offers SecurityAssessmentsDiagramLabelChars; validation accepts 10
	// to 120. Default 40.
	DiagramLabelChars int `toml:"diagram_label_chars"`
}

// The [security.assessments] pickers.
var (
	SecurityAssessmentsTiers   = []string{"proxy_only", "internet"}
	SecurityAssessmentsScopes  = []string{"session", "project"}
	SecurityAssessmentsMinutes = []int{15, 30, 60, 120, 240}
	// The time box pickers. A managed node's lowering pin may name any whole
	// number from 5 to 240.
	SecurityAssessmentsThreatModelBoxes = []int{30, 45, 60, 90, 120}
	SecurityAssessmentsPentestBoxes     = []int{15, 30, 45, 60, 90, 120}
	SecurityAssessmentsBoxActions       = []string{"stop_button", "auto_close"}
	SecurityAssessmentsRetentionDays    = []int{0, 30, 90, 180}
	// The model-contract pickers. The preset ids are pinned to the secassess
	// tables by a test in the dashboard package (this package imports neither).
	SecurityAssessmentsBands            = []string{"low", "medium", "high", "critical"}
	SecurityAssessmentsFindingsCaps     = []int{0, 25, 50, 100, 250, 500}
	SecurityAssessmentsFrameworkPresets = []string{"all", "stride", "stride_linddun", "stride_ai"}
	SecurityAssessmentsExtraPresets     = []string{"both", "abuse_cases", "attack_trees", "neither"}
	SecurityAssessmentsCategoryPresets  = []string{"all", "web_no_api", "api_only", "auth_access"}
	// The check-bound pickers (validation accepts the whole range in the
	// constants below, so a value written by hand never fails for not being on
	// a picker).
	SecurityAssessmentsRefWindows  = []int{1, 3, 5, 10, 20, 50}
	SecurityAssessmentsModelMaxMiB = []int{1, 2, 4, 8, 16, 32}
	SecurityAssessmentsRefFiles    = []int{100, 250, 500, 1000, 2000, 5000}
	SecurityAssessmentsRefMiB      = []int{32, 64, 128, 256, 512, 1024}
	SecurityAssessmentsRefSeconds  = []int{5, 10, 20, 30, 60, 120}
	// The depth pickers (W3, W4): the grounding digest, what a pen test box
	// does about .env files, and the request limits.
	SecurityAssessmentsGroundingModes = []string{"full", "without_findings", "off"}
	SecurityAssessmentsSecretModes    = []string{"off", "warn", "mask", "refuse"}
	SecurityAssessmentsRequestBudgets = []int{200, 600, 1200, 2400}
	SecurityAssessmentsPaces          = []int{1, 2, 5, 10}
	// The model view pickers (W5a, W6a): the diagram's node cap and label length.
	SecurityAssessmentsDiagramNodes      = []int{20, 40, 60, 100, 150, 200}
	SecurityAssessmentsDiagramLabelChars = []int{20, 40, 60, 80, 120}
)

// Bounds of relaxation_max_minutes at validation.
const (
	securityAssessmentsMinMinutes = 5
	securityAssessmentsMaxMinutes = 240

	// securityAssessmentsMaxRetention bounds evidence_retention_days at
	// validation (ten years).
	securityAssessmentsMaxRetention = 3650

	// securityAssessmentsMaxFindingsCap bounds findings_cap at validation: the
	// import's own ceiling (secscan's sarif-import MaxResults).
	securityAssessmentsMaxFindingsCap = 1000

	// The check bounds' ranges (see SecurityAssessmentsConfig).
	securityAssessmentsMinRefWindow  = 1
	securityAssessmentsMaxRefWindow  = 50
	securityAssessmentsMinModelMiB   = 1
	securityAssessmentsMaxModelMiB   = 32
	securityAssessmentsMinRefFiles   = 50
	securityAssessmentsMaxRefFiles   = 5000
	securityAssessmentsMinRefMiB     = 16
	securityAssessmentsMaxRefMiB     = 1024
	securityAssessmentsMinRefSeconds = 1
	securityAssessmentsMaxRefSeconds = 120

	// The request limits' ranges (a lowering pin may name any whole number in
	// them).
	securityAssessmentsMinRequestBudget = 10
	securityAssessmentsMaxRequestBudget = 10000
	securityAssessmentsMinPace          = 1
	securityAssessmentsMaxPace          = 100

	// The diagram node cap's range. The upper bound is secassess.MaxMermaidNodes
	// (a test in the dashboard package pins the two together; this package
	// imports neither).
	securityAssessmentsMinDiagramNodes = 10
	securityAssessmentsMaxDiagramNodes = 300

	// The diagram label length's range; the upper bound is
	// secassess.MaxMermaidLabelChars (pinned by a test, like the node cap).
	securityAssessmentsMinDiagramLabelChars = 10
	securityAssessmentsMaxDiagramLabelChars = 120
)

// DefaultSecurityAssessmentsConfig is the safe default: nothing relaxed.
func DefaultSecurityAssessmentsConfig() SecurityAssessmentsConfig {
	return SecurityAssessmentsConfig{
		MaxNetworkTier: "proxy_only", RelaxationScope: "session", RelaxationMaxMinutes: 60,
		TimeBoxThreatModelMinutes: 60, TimeBoxPentestLocalMinutes: 45, TimeBoxRedTeamLocalMinutes: 60,
		TimeBoxAction: "stop_button", BoundaryAudit: true,
		RerunDedup: true, ImportMinBand: "low", PromptSelfcheck: true, ReportValidationToOrg: true,
		TMFrameworks: "all", TMMethodExtras: "both", PTCategories: "all",
		RefMatchWindowLines: 5, ModelMaxMiB: 4, RefBudgetFiles: 500, RefBudgetMiB: 128, RefBudgetSeconds: 10,
		Grounding: "full", WorkspaceSecretMode: "mask", PentestRequestBudget: 600, PentestPaceRPS: 5, ProbeHelper: true,
		DisplayRedaction: true, DiagramMaxNodes: 60, DiagramLabelChars: 40,
	}
}

// validateSecurityAssessments checks [security.assessments].
func validateSecurityAssessments(c SecurityAssessmentsConfig) error {
	if !slices.Contains(SecurityAssessmentsTiers, c.MaxNetworkTier) {
		return fmt.Errorf("config: security.assessments.max_network_tier %q not in %v", c.MaxNetworkTier, SecurityAssessmentsTiers)
	}
	if !slices.Contains(SecurityAssessmentsScopes, c.RelaxationScope) {
		return fmt.Errorf("config: security.assessments.relaxation_scope %q not in %v", c.RelaxationScope, SecurityAssessmentsScopes)
	}
	if c.RelaxationMaxMinutes < securityAssessmentsMinMinutes || c.RelaxationMaxMinutes > securityAssessmentsMaxMinutes {
		return fmt.Errorf("config: security.assessments.relaxation_max_minutes %d not %d to %d", c.RelaxationMaxMinutes, securityAssessmentsMinMinutes, securityAssessmentsMaxMinutes)
	}
	for _, b := range []struct {
		key string
		min int
	}{
		{"time_box_threat_model_minutes", c.TimeBoxThreatModelMinutes},
		{"time_box_pentest_local_minutes", c.TimeBoxPentestLocalMinutes},
		{"time_box_red_team_local_minutes", c.TimeBoxRedTeamLocalMinutes},
	} {
		if b.min < securityAssessmentsMinMinutes || b.min > securityAssessmentsMaxMinutes {
			return fmt.Errorf("config: security.assessments.%s %d not %d to %d", b.key, b.min, securityAssessmentsMinMinutes, securityAssessmentsMaxMinutes)
		}
	}
	if !slices.Contains(SecurityAssessmentsBoxActions, c.TimeBoxAction) {
		return fmt.Errorf("config: security.assessments.time_box_action %q not in %v", c.TimeBoxAction, SecurityAssessmentsBoxActions)
	}
	if c.EvidenceRetentionDays < 0 || c.EvidenceRetentionDays > securityAssessmentsMaxRetention {
		return fmt.Errorf("config: security.assessments.evidence_retention_days %d not 0 to %d", c.EvidenceRetentionDays, securityAssessmentsMaxRetention)
	}
	if c.FindingsCap < 0 || c.FindingsCap > securityAssessmentsMaxFindingsCap {
		return fmt.Errorf("config: security.assessments.findings_cap %d not 0 to %d", c.FindingsCap, securityAssessmentsMaxFindingsCap)
	}
	for _, b := range []struct {
		key           string
		val, min, max int
	}{
		{"ref_match_window_lines", c.RefMatchWindowLines, securityAssessmentsMinRefWindow, securityAssessmentsMaxRefWindow},
		{"model_max_mib", c.ModelMaxMiB, securityAssessmentsMinModelMiB, securityAssessmentsMaxModelMiB},
		{"ref_budget_files", c.RefBudgetFiles, securityAssessmentsMinRefFiles, securityAssessmentsMaxRefFiles},
		{"ref_budget_mib", c.RefBudgetMiB, securityAssessmentsMinRefMiB, securityAssessmentsMaxRefMiB},
		{"ref_budget_seconds", c.RefBudgetSeconds, securityAssessmentsMinRefSeconds, securityAssessmentsMaxRefSeconds},
		{"pentest_request_budget", c.PentestRequestBudget, securityAssessmentsMinRequestBudget, securityAssessmentsMaxRequestBudget},
		{"pentest_pace_rps", c.PentestPaceRPS, securityAssessmentsMinPace, securityAssessmentsMaxPace},
		{"diagram_max_nodes", c.DiagramMaxNodes, securityAssessmentsMinDiagramNodes, securityAssessmentsMaxDiagramNodes},
		{"diagram_label_chars", c.DiagramLabelChars, securityAssessmentsMinDiagramLabelChars, securityAssessmentsMaxDiagramLabelChars},
	} {
		if b.val < b.min || b.val > b.max {
			return fmt.Errorf("config: security.assessments.%s %d not %d to %d", b.key, b.val, b.min, b.max)
		}
	}
	for _, e := range []struct {
		key, val string
		in       []string
	}{
		{"import_min_band", c.ImportMinBand, SecurityAssessmentsBands},
		{"tm_frameworks", c.TMFrameworks, SecurityAssessmentsFrameworkPresets},
		{"tm_method_extras", c.TMMethodExtras, SecurityAssessmentsExtraPresets},
		{"pt_categories", c.PTCategories, SecurityAssessmentsCategoryPresets},
		{"grounding", c.Grounding, SecurityAssessmentsGroundingModes},
		{"workspace_secret_mode", c.WorkspaceSecretMode, SecurityAssessmentsSecretModes},
	} {
		if !slices.Contains(e.in, e.val) {
			return fmt.Errorf("config: security.assessments.%s %q not in %v", e.key, e.val, e.in)
		}
	}
	return nil
}

// assessmentsSecuritySettings are the settings-contract rows of the section
// (their home is the Code security Settings card).
func assessmentsSecuritySettings() []SecuritySetting {
	const home = "Code security"
	return []SecuritySetting{
		{Key: "security.assessments.relax_pentest_local", Class: SettingPolicy, Values: "Off / On", Default: "Off (the penetration test offers no relaxation)", NodeHome: home},
		{Key: "security.assessments.relax_red_team_local", Class: SettingPolicy, Values: "Off / On", Default: "Off (the red team exercise offers no relaxation)", NodeHome: home},
		{Key: "security.assessments.scoped_approval", Class: SettingPolicy, Values: "Off / On", Default: "Off (guard rules are never lifted for a run)", NodeHome: home},
		{Key: "security.assessments.max_network_tier", Class: SettingPolicy, Values: "proxy_only / internet", Default: "proxy_only (no tier relaxation)", NodeHome: home},
		{Key: "security.assessments.relaxation_scope", Class: SettingLocal, Values: "session / project (project is an individual node only)", Default: "session", NodeHome: home},
		{Key: "security.assessments.relaxation_max_minutes", Class: SettingPolicy, Values: "15 / 30 / 60 / 120 / 240 (a managed node caps it at 60)", Default: "60", NodeHome: home},
		{Key: "security.assessments.report_to_org", Class: SettingLocal, Values: "Off / On (an individual node; a managed node always reports)", Default: "Off", NodeHome: home},
		{Key: "security.assessments.time_box_threat_model_minutes", Class: SettingPolicy, Values: "30 / 45 / 60 / 90 / 120 minutes (a lowering pin is a ceiling)", Default: "60", NodeHome: home},
		{Key: "security.assessments.time_box_pentest_local_minutes", Class: SettingPolicy, Values: "15 / 30 / 45 / 60 / 90 / 120 minutes (a lowering pin is a ceiling)", Default: "45", NodeHome: home},
		{Key: "security.assessments.time_box_red_team_local_minutes", Class: SettingPolicy, Values: "15 / 30 / 45 / 60 / 90 / 120 minutes (a lowering pin is a ceiling)", Default: "60", NodeHome: home},
		{Key: "security.assessments.time_box_action", Class: SettingPolicy, Values: "stop_button / auto_close (an organization may pin auto_close)", Default: "stop_button (the run row offers Stop; nothing is closed for you)", NodeHome: home},
		{Key: "security.assessments.boundary_audit", Class: SettingLocal, Values: "Off / On", Default: "On (git state is snapshotted before and after a run)", NodeHome: home},
		{Key: "security.assessments.evidence_retention_days", Class: SettingLocal, Values: "Run record window / 30 / 90 / 180 days (local: keeping longest is the widest value, so an organization has no direction to pin)", Default: "Run record window (the newest 100 runs)", NodeHome: home},
		{Key: "security.assessments.rerun_dedup", Class: SettingLocal, Values: "Off / On", Default: "On (a re-run updates the findings it already imported)", NodeHome: home},
		{Key: "security.assessments.findings_cap", Class: SettingLocal, Values: "No cap / 25 / 50 / 100 / 250 / 500 findings per run (No cap still means the importer keeps at most 1,000 results per run; local: no cap is the widest value, so an organization has no direction to pin)", Default: "No cap (every finding with a location is imported; the importer keeps at most 1,000 results per run)", NodeHome: home},
		{Key: "security.assessments.import_min_band", Class: SettingLocal, Values: "low / medium / high / critical (local: low is the widest value)", Default: "low (every finding with a location)", NodeHome: home},
		{Key: "security.assessments.prompt_selfcheck", Class: SettingLocal, Values: "Off / On", Default: "On (the task names the self-check command)", NodeHome: home},
		{Key: "security.assessments.report_validation_to_org", Class: SettingLocal, Values: "Off / On (a run that is reported to the organization)", Default: "On (a content-free row that the model was checked)", NodeHome: home},
		{Key: "security.assessments.tm_frameworks", Class: SettingLocal, Values: "all / stride / stride_linddun / stride_ai (local: all is the widest value)", Default: "all (STRIDE, LINDDUN and the AI frameworks, each where it applies)", NodeHome: home},
		{Key: "security.assessments.tm_method_extras", Class: SettingLocal, Values: "both / abuse_cases / attack_trees / neither (local: both is the widest value)", Default: "both (abuse cases and an attack tree)", NodeHome: home},
		{Key: "security.assessments.pt_categories", Class: SettingLocal, Values: "all / web_no_api / api_only / auth_access (local: all is the widest value)", Default: "all (the twelve test categories)", NodeHome: home},
		{Key: "security.assessments.ref_match_window_lines", Class: SettingLocal, Values: "1 / 3 / 5 / 10 / 20 / 50 lines (local: a larger window credits a reference whose text is further from the cited line)", Default: "5 (the cited text must be within 5 lines of the first cited line to read found)", NodeHome: home},
		{Key: "security.assessments.model_max_mib", Class: SettingLocal, Values: "1 / 2 / 4 / 8 / 16 / 32 MiB (local: larger is the wider value)", Default: "4 (an assessment.json over 4 MiB is refused with its cap named)", NodeHome: home},
		{Key: "security.assessments.ref_budget_files", Class: SettingLocal, Values: "100 / 250 / 500 / 1000 / 2000 / 5000 files (local: larger is the wider value)", Default: "500 (the reference check opens at most 500 distinct files; the rest read unchecked)", NodeHome: home},
		{Key: "security.assessments.ref_budget_mib", Class: SettingLocal, Values: "32 / 64 / 128 / 256 / 512 / 1024 MiB (local: larger is the wider value)", Default: "128 (the reference check reads at most 128 MiB in all)", NodeHome: home},
		{Key: "security.assessments.ref_budget_seconds", Class: SettingLocal, Values: "5 / 10 / 20 / 30 / 60 / 120 seconds (local: larger is the wider value)", Default: "10 (the reference check looks for at most 10 seconds)", NodeHome: home},
		{Key: "security.assessments.grounding", Class: SettingLocal, Values: "full / without_findings / off (local: full is the widest value)", Default: "full (the task carries a digest of facts about the project, including its open findings)", NodeHome: home},
		{Key: "security.assessments.workspace_secret_mode", Class: SettingPolicy, Values: "off / warn / mask / refuse (an organization may pin refuse)", Default: "mask (where the sandbox can hide .env files; otherwise warn)", NodeHome: home},
		{Key: "security.assessments.pentest_request_budget", Class: SettingPolicy, Values: "200 / 600 / 1200 / 2400 requests (a lowering pin is a ceiling)", Default: "600", NodeHome: home},
		{Key: "security.assessments.pentest_pace_rps", Class: SettingPolicy, Values: "1 / 2 / 5 / 10 requests per second (a lowering pin is a ceiling)", Default: "5", NodeHome: home},
		{Key: "security.assessments.probe_helper", Class: SettingPolicy, Values: "Off / On (an organization may pin Off, never On)", Default: "On (a request helper and its settings file are written into the run folder; the agent's requests go through it and are logged)", NodeHome: home},
		{Key: "security.assessments.display_redaction", Class: SettingLocal, Values: "Off / On (local: it changes only what this dashboard shows)", Default: "On (secrets Observer recognises are hidden in the report and the model as shown; the files in the project are as the agent wrote them)", NodeHome: home},
		{Key: "security.assessments.diagram_max_nodes", Class: SettingLocal, Values: "20 / 40 / 60 / 100 / 150 / 200 nodes (local: larger is the wider value)", Default: "60 (the data-flow diagram source draws at most 60 nodes; the rest are counted)", NodeHome: home},
		{Key: "security.assessments.diagram_label_chars", Class: SettingLocal, Values: "20 / 40 / 60 / 80 / 120 characters (local: larger is the wider value)", Default: "40 (a label in the data-flow diagram source keeps at most 40 characters of the agent's text; the view counts the labels it cut)", NodeHome: home},
	}
}
