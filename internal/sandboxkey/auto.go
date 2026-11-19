package sandboxkey

// auto.go resolves the custody a hosted launch runs with (decision SBXD-1,
// docs/decisions/sandbox-terminal-decisions-2026-11.md). The configuration
// value "auto" (the default for a node that never set key_custody) keeps
// the key on this machine whenever this machine can add it for the tool
// (the org AI Gateway route, or credential injection with a stored key of a
// provider the tool's route carries) and otherwise puts the key in the box,
// so a fresh node meets no setup step. A per-tool value
// ([terminal.sandbox.hosted.key_custody_by_tool]) wins over the node value.
//
// It is THE one owner of that resolution: HomeKey walks it first for a
// tool's launch, so the hosted probe, the setup step, the dialog's key line
// and the launch all read the same answer.

// custodyAuto is the configuration spelling (sandboxvocab.CustodyAuto).
const custodyAuto = "auto"

// The CustodyResolution.Rule names, one per row of custodyRules.
const (
	CustodyRuleToolSetting = "tool_setting"
	CustodyRuleNodeSetting = "node_setting"
	CustodyRuleRowKeepsKey = "row_keeps_key_home"
	CustodyRuleNodeWide    = "auto_node_wide"
	CustodyRuleHomeServes  = "auto_home_serves"
	CustodyRuleNothingHome = "auto_nothing_at_home"
)

// CustodyResolution is the custody a launch runs with and why: the plain
// sentence a person reads (no config key, no enum value) and the technical
// detail.
type CustodyResolution struct {
	// Custody is the resolved custody (a run's, never "auto"), except on the
	// node-wide question under auto, where it stays "auto".
	Custody   string
	Rule      string
	Why       string
	Technical string
}

// Auto reports whether the custody the launch was configured with is
// auto, so the resolution was this machine's choice, not a setting.
func (r CustodyResolution) Auto() bool {
	return r.Rule != CustodyRuleToolSetting && r.Rule != CustodyRuleNodeSetting
}

// custodyRule is one row: when match holds, the row decides.
type custodyRow struct {
	rule    string
	match   func(HomeKeyFacts, string) bool
	custody func(HomeKeyFacts, string) string
	why     string
	tech    func(HomeKeyFacts, string) string
}

// effectiveSetting is the setting that applies: the tool's own value on a
// tool's launch, else the node's ("" reads as home_relay, the value every
// node had before auto existed).
func effectiveSetting(f HomeKeyFacts) string {
	if f.ForTool && f.ToolCustody != "" {
		return f.ToolCustody
	}
	if f.Custody == "" {
		return custodyHomeRelay
	}
	return f.Custody
}

// homeServesTool reports whether this machine adds the key for the tool:
// the home_relay rows of the HomeKey table serve it.
func homeServesTool(f HomeKeyFacts) bool {
	f.Custody, f.ToolCustody = custodyHomeRelay, ""
	return homeKeyWalk(f).OK
}

// custodyRules are walked top-down (CLAUDE.md rule 5); the last row always
// matches.
var custodyRules = []custodyRow{
	{
		rule:    CustodyRuleToolSetting,
		match:   func(f HomeKeyFacts, s string) bool { return f.ForTool && f.ToolCustody != "" && s != custodyAuto },
		custody: func(_ HomeKeyFacts, s string) string { return s },
		why:     "This agent's model key setting is chosen for it in your settings.",
		tech: func(_ HomeKeyFacts, s string) string {
			return "[terminal.sandbox.hosted.key_custody_by_tool] sets " + s + " for this tool"
		},
	},
	{
		rule:    CustodyRuleNodeSetting,
		match:   func(_ HomeKeyFacts, s string) bool { return s != custodyAuto },
		custody: func(_ HomeKeyFacts, s string) string { return s },
		why:     "The model key setting for hosted sandboxes is chosen in your settings.",
		tech:    func(_ HomeKeyFacts, s string) string { return "[terminal.sandbox.hosted].key_custody = " + s },
	},
	{
		rule:    CustodyRuleRowKeepsKey,
		match:   func(f HomeKeyFacts, _ string) bool { return f.InBoxRefused },
		custody: func(HomeKeyFacts, string) string { return custodyHomeRelay },
		why:     "This sandbox keeps every model key on this machine.",
		tech: func(HomeKeyFacts, string) string {
			return "key custody auto resolves to home_relay: the row offers no in-box custody (its capability row's Net.KeyCustody)"
		},
	},
	{
		rule:    CustodyRuleNodeWide,
		match:   func(f HomeKeyFacts, _ string) bool { return !f.ForTool },
		custody: func(HomeKeyFacts, string) string { return custodyAuto },
		why:     "Each agent's key stays on this machine when Observer can add it here, otherwise it is put in the box.",
		tech: func(HomeKeyFacts, string) string {
			return "key custody auto: resolved per launch and per tool (home_relay when this machine adds the key, else in_box_api_key)"
		},
	},
	{
		rule:    CustodyRuleHomeServes,
		match:   func(f HomeKeyFacts, _ string) bool { return homeServesTool(f) },
		custody: func(HomeKeyFacts, string) string { return custodyHomeRelay },
		why:     "Observer can add this agent's key from this machine, so the key stays here.",
		tech: func(HomeKeyFacts, string) string {
			return "key custody auto resolves to home_relay: the org AI Gateway route, or credential injection with a stored key of a provider the tool's route carries, serves the tool"
		},
	},
	{
		rule:    CustodyRuleNothingHome,
		match:   func(HomeKeyFacts, string) bool { return true },
		custody: func(HomeKeyFacts, string) string { return custodyInBoxAPIKey },
		why:     "Nothing on this machine can add this agent's key, so the key is put in the box.",
		tech: func(HomeKeyFacts, string) string {
			return "key custody auto resolves to in_box_api_key: neither the org AI Gateway route nor credential injection serves the tool (store a key of a provider its route carries with `observer sandbox credentials add <provider>` to keep it home)"
		},
	},
}

// ResolveCustody walks the table for f.
func ResolveCustody(f HomeKeyFacts) CustodyResolution {
	s := effectiveSetting(f)
	for _, r := range custodyRules {
		if r.match(f, s) {
			return CustodyResolution{Custody: r.custody(f, s), Rule: r.rule, Why: r.why, Technical: r.tech(f, s)}
		}
	}
	return CustodyResolution{Custody: s, Rule: CustodyRuleNodeSetting}
}

// ResolvedFacts are f with its custody replaced by the resolved one and the
// per-tool value consumed, so the HomeKey rows read one custody.
func ResolvedFacts(f HomeKeyFacts) (HomeKeyFacts, CustodyResolution) {
	r := ResolveCustody(f)
	f.Custody, f.ToolCustody = r.Custody, ""
	return f, r
}

// MayPutKeyInBox reports whether a launch under the node's custody settings
// can resolve to a key in the box for some tool (the consent binds the
// stored keys that would then enter it, decision SBXD-3): an in-box value,
// or auto, at the node or for any tool. Under home_relay everywhere it is
// false, so a home_relay node's consent never reopens for a stored key.
func MayPutKeyInBox(node string, byTool map[string]string, inBoxRefused bool) bool {
	if inBoxRefused {
		return false
	}
	in := func(c string) bool { return c == custodyAuto || c == custodyInBoxAPIKey }
	if in(node) {
		return true
	}
	for _, c := range byTool {
		if in(c) {
			return true
		}
	}
	return false
}

// KeepHomeOffers are the providers whose key, once stored on this machine,
// would keep this tool's key here where it is not kept here now (the
// dialog's paste field, decision SBXD-1: "Keep it on this machine"). Only
// while credential injection is selected and built (a stored key is then
// read), only for a tool's launch, and never under an explicit in-box
// setting (storing a key there would put it in the box). Walked through
// HomeKey itself, so the offer and the launch never disagree.
func KeepHomeOffers(f HomeKeyFacts) []string {
	if !f.ForTool || !f.InjectionSelected || !f.InjectionBuilt {
		return nil
	}
	keptHome := func(v HomeKeyVerdict) bool { return v.OK && v.Resolution.Custody == custodyHomeRelay }
	now := HomeKey(f)
	if keptHome(now) || (now.Resolution.Custody != custodyHomeRelay && now.Resolution.Rule != CustodyRuleNothingHome) {
		return nil
	}
	var out []string
	for _, id := range Known(f.ToolProviders) {
		if containsString(f.StoredProviders, id) {
			continue
		}
		g := f
		g.StoredProviders = append(append([]string(nil), f.StoredProviders...), id)
		if keptHome(HomeKey(g)) {
			out = append(out, id)
		}
	}
	return out
}

// CustodySetting is the configured custody that applies to f's launch: the
// tool's own value, else the node's ("" reads as home_relay). A run's plan
// records it beside the resolved custody.
func CustodySetting(f HomeKeyFacts) string { return effectiveSetting(f) }
