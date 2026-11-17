package secassess

// words.go holds the places and switches the user-facing sentences of this
// package name, in the words the screens use (polish round, UX-8). A sentence a
// person reads names the screen and the label of the switch they can see, never
// a config key, a TOML section, an enum value, a guard rule id or a flag: those
// stay in the structured fields beside the sentence (Relaxation.Key,
// Consent.Code, Consent.Row) for the callers and the tests that need them.
//
// The labels are the Settings rows' own. The web table
// (web/src/lib/codeSecuritySettings.ts) owns them; TestSettingLabelsMatchTheWeb
// pins this copy to it, so a renamed row fails here and not on a user's screen.
// Nothing here is read by a prompt builder: the prompt keeps its own words.

// The screens a sentence sends the reader to.
const (
	// WhereSettings is the Settings page that holds the assessment switches.
	WhereSettings = "Settings > Guard > Code security"
	// WhereSandbox is the page that holds the sandbox network setting and its
	// host list.
	WhereSandbox = "Terminals > Settings > Sandbox isolation"
)

// The labels of the Settings rows a sentence names.
const (
	// LabelRelaxPentest is the switch that lets a penetration test offer
	// relaxations.
	LabelRelaxPentest = "Penetration test may ask for relaxations"
	// LabelRelaxRedTeam is the same switch for the red team exercise.
	LabelRelaxRedTeam = "Red team exercise may ask for relaxations"
	// LabelScopedApproval is the switch that lets an assessment offer to lift
	// the scanner guard rule.
	LabelScopedApproval = "Assessments may ask to lift a guard rule"
	// LabelMaxNetwork is the widest sandbox network an assessment may run under.
	LabelMaxNetwork = "Widest sandbox network an assessment may run under"
	// LabelMaxNetworkProxyOnly is that setting's value that allows no wider
	// network.
	LabelMaxNetworkProxyOnly = "Model proxy only"
	// LabelEnvFiles is the environment-files setting of a penetration test.
	LabelEnvFiles = "Environment files in a penetration test"
	// LabelModelMaxMiB is the size cap of the file an agent writes.
	LabelModelMaxMiB = "Largest assessment.json that is read"
	// LabelProbeHelper is the request helper switch.
	LabelProbeHelper = "Request helper for penetration tests"
	// LabelHostList is the sandbox card's list of hosts a sandboxed agent may
	// reach.
	LabelHostList = "Hosts a sandboxed agent may reach (internet mode)"
	// LabelSandboxNetwork is the sandbox card's network field.
	LabelSandboxNetwork = "Network"
)

// RelaxSettingLabel is the label of the Settings switch that lets a kind offer
// relaxations, "" for a kind with none (the words of the setting
// RelaxConfigKey names).
func RelaxSettingLabel(kind ID) string {
	switch kind {
	case PentestLocal:
		return LabelRelaxPentest
	case RedTeamLocal:
		return LabelRelaxRedTeam
	}
	return ""
}

// TierName is a sandbox network tier as the sandbox card shows it: the model
// proxy alone is "proxy only", and the others are their own words. An unknown
// or empty tier reads as the card's default, internet.
func TierName(tier string) string {
	switch tier {
	case "proxy_only":
		return "proxy only"
	case "none", "host", "internet":
		return tier
	}
	return "internet"
}
