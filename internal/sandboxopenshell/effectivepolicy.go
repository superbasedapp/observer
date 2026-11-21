package sandboxopenshell

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// effectivepolicy.go is the read-back of what a gateway will actually
// enforce for a box (lane FU8, ledger OSH-40, sweep E1). Observer compiles
// the box's rules, but OpenShell lets three gateway-side settings widen
// them: a gateway-global policy REPLACES every sandbox's policy,
// gateway-scope proposal_approval_mode = auto approves new hosts without a
// person, and agent_policy_proposals_enabled lets the agent propose them
// (doc 01 sections 6.4 and 6.7). Either would make the gateway a second
// egress owner (rule W4). This file is pure: it renders the CLI reads and
// classifies their answers; the driver runs them.
//
// Two reads, two places:
//
//   - the gateway (probe row PS): `openshell settings get --global` and
//     `openshell policy get --global --full -o json`. In external mode a
//     gateway whose settings allow automatic approval or proposals, or
//     that holds a global policy, is refused, and so is one whose answers
//     cannot be read. In managed mode the same facts are Observer's private gateway's
//     database settings: a positive deviation refuses (and is drift), an
//     unreadable answer only reads as unknown drift, never as clean.
//   - each box (the host helper, after create and on its own tick):
//     `openshell policy get <box> --full -o json`, compared with the rules
//     Observer compiled. Any rule, endpoint, port, address range, program
//     or enforcement the compiled rules do not hold is a widening and the
//     box is stopped with a closed reason.
//
// The answer shapes of these three commands at v0.1.6 are grounded by the
// first run of live check FU8-L1 (2026-11-03, fresh Ubuntu 24.04, lane FU9;
// the answers are fixtures under testdata/openshell-0.1.6): `settings get
// --global` prints "key = <unset>" lines (its --json form an object of
// strings), every unset value as the marker "<unset>"; `policy get --global
// -o json` answers a revision's metadata only (no document), and with
// --full the metadata and the revision's "policy", whose "status" says
// whether it is in force ("loaded") or not ("superseded"), or exits 1 with
// "no global policy revision found" when none was ever set; `policy get
// <box> --full -o json` answers one merged "policy" document beside the
// revision metadata. The parsers accept a closed set of shapes: for the
// settings, snake_case and camelCase setting names (one setting, so two
// spellings must agree), scalar values or value objects with members
// value, scope and source, list entries, and plain "key<sep>value" lines;
// for policies, snake_case and camelCase section names, with every policy
// document at every depth read; for the global read, the revision answer's
// closed members and statuses. Every other shape reads as unreadable,
// which never passes.

// The probe verdicts of row PS.
const (
	// VerdictGatewayAutoApproval: the gateway approves policy proposals
	// without a person (proposal_approval_mode = auto at gateway scope).
	VerdictGatewayAutoApproval = "gateway_auto_approval"
	// VerdictGatewayPolicyProposals: the gateway lets agents propose
	// policy changes (agent_policy_proposals_enabled = true).
	VerdictGatewayPolicyProposals = "gateway_policy_proposals"
	// VerdictGatewayGlobalPolicy: the gateway holds a gateway-global
	// policy, which replaces the box's compiled policy.
	VerdictGatewayGlobalPolicy = "gateway_global_policy"
	// VerdictGatewaySettingsUnknown: the gateway's settings or its global
	// policy could not be read (external mode only: a gateway Observer
	// cannot read is never taken as one that widens nothing).
	VerdictGatewaySettingsUnknown = "gateway_settings_unknown"
)

// The two gateway settings the read checks (doc 01 section 6.7, upstream
// crates/openshell-core/src/settings.rs).
const (
	SettingApprovalMode = "proposal_approval_mode"
	SettingProposals    = "agent_policy_proposals_enabled"
)

// GatewaySettings are the two settings as the gateway reports them at
// gateway scope. A value is lower case with quotes trimmed; "" means the
// setting has no value at gateway scope (the marker "<unset>" or null), so
// the read finds nothing at that scope that widens a box; the upstream
// defaults are manual approval and proposals off (doc 01 section 6.7,
// upstream crates/openshell-core/src/settings.rs; live check FU8-L1 read
// both unset on an untouched v0.1.6 gateway). It does NOT mean every box
// runs with the defaults: a sandbox-scope value (proposal_approval_mode =
// auto, or agent_policy_proposals_enabled = true, set on one box) is not
// part of this `--global` read, so row PS cannot see it on an external
// gateway. That is a recorded residual (audit FU9-A1): on an external box
// only the box watch (the `--full` effective policy read on the helper's
// tick) catches the widening such a setting lets through, after the fact.
type GatewaySettings struct {
	ApprovalMode string
	Proposals    string
}

// AutoApproval reports whether the gateway approves proposals without a
// person. Only "auto" does: upstream fails an unknown persisted value
// closed to manual.
func (s GatewaySettings) AutoApproval() bool { return s.ApprovalMode == "auto" }

// ProposalsOn reports whether agents may propose policy changes.
func (s GatewaySettings) ProposalsOn() bool {
	switch s.Proposals {
	case "true", "1", "yes", "on", "enabled":
		return true
	}
	return false
}

// GlobalPolicy is what the global policy read found.
type GlobalPolicy int

// The closed GlobalPolicy vocabulary.
const (
	// GlobalPolicyUnknown: not read, or the answer was not understood
	// (the zero value: never read as absent).
	GlobalPolicyUnknown GlobalPolicy = iota
	// GlobalPolicyAbsent: the gateway holds no global policy.
	GlobalPolicyAbsent
	// GlobalPolicyPresent: the gateway holds one.
	GlobalPolicyPresent
)

// GatewayPolicyFacts are row PS's facts.
type GatewayPolicyFacts struct {
	// SettingsRead: the settings answer was read and both settings were in
	// it.
	SettingsRead bool
	// Settings are the settings read (valid when SettingsRead).
	Settings GatewaySettings
	// Global is the global policy read.
	Global GlobalPolicy
}

// gatewayPolicyRow is one row of the PS table.
type gatewayPolicyRow struct {
	rule string
	// managed: the row also refuses in managed mode (a positive
	// deviation); false rows refuse in external mode only.
	managed bool
	holds   func(f GatewayPolicyFacts) bool
	verdict string
	reason  string
}

// gatewayPolicyRows is the PS table, walked top-down (CLAUDE.md rule 5).
var gatewayPolicyRows = []gatewayPolicyRow{
	{
		"PS1", true, func(f GatewayPolicyFacts) bool { return f.Global == GlobalPolicyPresent }, VerdictGatewayGlobalPolicy,
		"the OpenShell gateway holds a gateway-global policy, which replaces the box's compiled policy (its network rules, filesystem view and process settings); remove it (`openshell policy delete --global`) on a gateway Observer uses",
	},
	{
		"PS2", true, func(f GatewayPolicyFacts) bool { return f.SettingsRead && f.Settings.AutoApproval() }, VerdictGatewayAutoApproval,
		"the OpenShell gateway approves policy proposals automatically (proposal_approval_mode = auto at gateway scope), so a box could gain hosts its tier does not allow; set it to manual (`openshell settings set --global --key proposal_approval_mode --value manual`)",
	},
	{
		"PS3", true, func(f GatewayPolicyFacts) bool { return f.SettingsRead && f.Settings.ProposalsOn() }, VerdictGatewayPolicyProposals,
		"the OpenShell gateway lets agents propose policy changes (agent_policy_proposals_enabled = true at gateway scope); turn it off (`openshell settings set --global --key agent_policy_proposals_enabled --value false`)",
	},
	{
		"PS4", false, func(f GatewayPolicyFacts) bool { return !f.SettingsRead }, VerdictGatewaySettingsUnknown,
		"Observer could not read the OpenShell gateway's settings (`openshell settings get --global`), so it cannot tell whether the gateway approves policy proposals automatically",
	},
	{
		"PS5", false, func(f GatewayPolicyFacts) bool { return f.Global == GlobalPolicyUnknown }, VerdictGatewaySettingsUnknown,
		"Observer could not tell whether the OpenShell gateway holds a gateway-global policy (`openshell policy get --global`), which would replace the box's compiled policy",
	},
}

// GatewayPolicyVerdict walks the PS table for the gateway mode and returns
// the verdict and reason ("" and "" when the row passes) and the deciding
// rule.
func GatewayPolicyVerdict(mode string, f GatewayPolicyFacts) (verdict, reason, rule string) {
	for _, r := range gatewayPolicyRows {
		if mode == GatewayManaged && !r.managed {
			continue
		}
		if r.holds(f) {
			return r.verdict, r.reason, r.rule
		}
	}
	return "", "", ""
}

// GatewayDBDrift is the managed gateway's database settings as a drift
// value: the settings the gateway keeps in its own database, beside the
// gateway.toml drift.go reads (OSH-40, managed half).
type GatewayDBDrift int

// The closed GatewayDBDrift vocabulary.
const (
	// GatewayDBNotRead: no managed probe has read them (nothing to add).
	GatewayDBNotRead GatewayDBDrift = iota
	// GatewayDBClean: OpenShell's defaults (manual approval, proposals off,
	// no global policy).
	GatewayDBClean
	// GatewayDBChanged: a setting or a global policy Observer never set.
	GatewayDBChanged
	// GatewayDBUnknown: the read did not say.
	GatewayDBUnknown
)

// ClassifyGatewayDB turns a managed gateway's PS facts into a drift value.
func ClassifyGatewayDB(f GatewayPolicyFacts) GatewayDBDrift {
	if v, _, _ := GatewayPolicyVerdict(GatewayManaged, f); v != "" {
		return GatewayDBChanged
	}
	if v, _, _ := GatewayPolicyVerdict(GatewayExternal, f); v != "" {
		return GatewayDBUnknown
	}
	return GatewayDBClean
}

// gatewayDriftFoldRows folds the database value into the config value,
// walked top-down: a change anywhere is a change, an unknown is never
// clean.
var gatewayDriftFoldRows = []struct {
	holds func(cfg GatewayDrift, db GatewayDBDrift) bool
	out   func(cfg GatewayDrift) GatewayDrift
}{
	// F0: no managed gateway was ever started here: the database half
	// does not apply (a stale reading from another mode never shows).
	{
		func(cfg GatewayDrift, _ GatewayDBDrift) bool { return cfg == GatewayDriftNone },
		func(GatewayDrift) GatewayDrift { return GatewayDriftNone },
	},
	// F1: a change on either side is a change.
	{
		func(cfg GatewayDrift, db GatewayDBDrift) bool {
			return cfg == GatewayDriftChanged || db == GatewayDBChanged
		},
		func(GatewayDrift) GatewayDrift { return GatewayDriftChanged },
	},
	// F2: an unknown on either side, or database settings not read yet by
	// this process (fix round 1, FU8-A7), is unknown, never clean.
	{
		func(cfg GatewayDrift, db GatewayDBDrift) bool {
			return cfg == GatewayDriftUnknown || db == GatewayDBUnknown || db == GatewayDBNotRead
		},
		func(GatewayDrift) GatewayDrift { return GatewayDriftUnknown },
	},
	// F3: both sides clean.
	{func(GatewayDrift, GatewayDBDrift) bool { return true }, func(cfg GatewayDrift) GatewayDrift { return cfg }},
}

// FoldGatewayDrift combines the gateway.toml drift with the database
// settings drift.
func FoldGatewayDrift(cfg GatewayDrift, db GatewayDBDrift) GatewayDrift {
	for _, r := range gatewayDriftFoldRows {
		if r.holds(cfg, db) {
			return r.out(cfg)
		}
	}
	return GatewayDriftUnknown
}

// SettingsArgv returns `openshell settings get --global` on the pinned
// gateway.
func SettingsArgv(t Target) ([]string, error) {
	g, err := t.pinnedGlobals()
	if err != nil {
		return nil, err
	}
	argv := append([]string{Program}, g...)
	return append(argv, "settings", "get", "--global"), nil
}

// GlobalPolicyArgv returns `openshell policy get --global --full -o json`
// on the pinned gateway. Without --full v0.1.6 answers a set global
// policy's revision metadata alone (live check FU8-L1); with it the answer
// holds the revision's policy as well, and its status says whether that
// policy is in force.
func GlobalPolicyArgv(t Target) ([]string, error) {
	g, err := t.pinnedGlobals()
	if err != nil {
		return nil, err
	}
	argv := append([]string{Program}, g...)
	return append(argv, "policy", "get", "--global", "--full", "-o", "json"), nil
}

// EffectivePolicyArgv returns `openshell policy get <box> --full -o json`
// on the pinned gateway: the box's effective policy.
func EffectivePolicyArgv(t Target, name string) ([]string, error) {
	g, err := t.pinnedGlobals()
	if err != nil {
		return nil, err
	}
	if !nameRE.MatchString(name) {
		return nil, fmt.Errorf("sandboxopenshell.EffectivePolicyArgv: sandbox name %q is not a name", name)
	}
	argv := append([]string{Program}, g...)
	return append(argv, "policy", "get", name, "--full", "-o", "json"), nil
}

// maxReadBack bounds an answer the parsers read.
const maxReadBack = 1 << 20

// unsetMarker is how OpenShell v0.1.6 prints a setting with no value at a
// scope, in the text and the JSON answer alike (live check FU8-L1). At
// --global it says only that the gateway scope holds no value, not that no
// box has one (see GatewaySettings, audit FU9-A1).
const unsetMarker = "<unset>"

// normValue lower-cases a setting value and trims quotes and space; the
// unset marker becomes "" (lane FU9).
func normValue(s string) string {
	v := strings.ToLower(strings.Trim(strings.TrimSpace(s), "\"'`"))
	if v == unsetMarker {
		return ""
	}
	return v
}

// settingValues are the closed value sets per setting (fix round 1,
// FU8-A3): anything else is unreadable, never a default. "" is the
// explicit unset value (null, or the marker "<unset>"): the setting's
// default.
var settingValues = map[string][]string{
	SettingApprovalMode: {"", "manual", "auto"},
	SettingProposals:    {"", "true", "false", "1", "0"},
}

// errSettingValue is a found setting whose value is not in its closed set.
var errSettingValue = fmt.Errorf("sandboxopenshell.ParseGatewaySettings: a setting value outside its closed set")

// settingsSeen collects the two settings; a second sighting with another
// value is a conflict (a multi-scope answer it cannot order).
type settingsSeen struct {
	vals  map[string]string
	found map[string]bool
	err   error
}

// put records one sighting of setting k with value v (already normalized).
func (ss *settingsSeen) put(k, v string, ok bool) {
	if ss.err != nil {
		return
	}
	if !ok || !slices.Contains(settingValues[k], v) {
		ss.err = errSettingValue
		return
	}
	if ss.found[k] && ss.vals[k] != v {
		ss.err = fmt.Errorf("sandboxopenshell.ParseGatewaySettings: %s answered twice with different values", k)
		return
	}
	ss.found[k], ss.vals[k] = true, v
}

// settingNames maps each accepted spelling of a setting to its name: the
// snake_case name and its camelCase twin are the same setting, so a
// disagreement between them is caught (fix round 2, FU8-R2).
var settingNames = map[string]string{
	SettingApprovalMode:           SettingApprovalMode,
	"proposalApprovalMode":        SettingApprovalMode,
	SettingProposals:              SettingProposals,
	"agentPolicyProposalsEnabled": SettingProposals,
}

// settingSpellings are settingNames' keys in a fixed order.
var settingSpellings = []string{SettingApprovalMode, "proposalApprovalMode", SettingProposals, "agentPolicyProposalsEnabled"}

// settingObjectMembers are the members a setting's value object may carry
// ({"value": ..., "scope": ..., "source": ...}); any other member makes it
// unreadable (fix round 2, FU8-R2: an "effective" beside a null "value"
// must not read as the default).
var settingObjectMembers = []string{"value", "scope", "source"}

// settingEntryMembers are the members a {key|name, value} list entry may
// carry.
var settingEntryMembers = []string{"key", "name", "value", "scope", "source"}

// ParseGatewaySettings reads the answer of `openshell settings get
// --global`. JSON: an object keyed by setting (either spelling) whose value
// is a scalar or a value object with members from settingObjectMembers, or
// a list of {key|name, value} entries; map keys are walked in sorted
// order, and a duplicate key in one object is unreadable. Text: every line
// that names a setting must be exactly "key<sep>value" (sep: space, ':' or
// '='). Each value must be in the setting's closed set or an explicit
// null, both settings must be present, and two sightings of one setting
// must agree. Anything else errs (unreadable).
func ParseGatewaySettings(b []byte) (GatewaySettings, error) {
	if len(b) > maxReadBack {
		return GatewaySettings{}, fmt.Errorf("sandboxopenshell.ParseGatewaySettings: answer too large")
	}
	ss := &settingsSeen{vals: map[string]string{}, found: map[string]bool{}}
	if json.Valid(b) {
		doc, err := decodeStrictAll(b)
		if err != nil {
			return GatewaySettings{}, fmt.Errorf("sandboxopenshell.ParseGatewaySettings: %w", err)
		}
		walkSettings(doc, ss)
	} else {
		for _, line := range strings.Split(string(b), "\n") {
			parseSettingLine(strings.TrimSpace(line), ss)
		}
	}
	if ss.err != nil {
		return GatewaySettings{}, ss.err
	}
	if !ss.found[SettingApprovalMode] || !ss.found[SettingProposals] {
		return GatewaySettings{}, fmt.Errorf("sandboxopenshell.ParseGatewaySettings: the answer does not name %s and %s", SettingApprovalMode, SettingProposals)
	}
	return GatewaySettings{ApprovalMode: ss.vals[SettingApprovalMode], Proposals: ss.vals[SettingProposals]}, nil
}

// decodeStrictAll decodes a whole answer through decodeStrict (fix round
// 3, FU8-R5: a duplicate key is unreadable everywhere, not only in the
// settings) and refuses trailing data, as json.Unmarshal does.
func decodeStrictAll(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	v, err := decodeStrict(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}

// nearName folds a name for the near-match rule: lower case, with every
// rune that is not a letter or a digit removed (lane FU9, FU8-R11), so
// "Proposal_Approval_Mode", " network_policies", "NetworkPolicies" and
// "proposal.approval.mode" all fold to their known name's fold.
func nearName(s string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, s)
}

// nearMiss reports whether s folds to one of names without being exactly
// one of them (fix round 3, FU8-R6: a variant spelling of a known name is
// unreadable, never ignored).
func nearMiss(s string, names []string) bool {
	f := nearName(s)
	near := false
	for _, n := range names {
		if s == n {
			return false
		}
		near = near || f == nearName(n)
	}
	return near
}

// maxStrictDepth bounds decodeStrict's nesting.
const maxStrictDepth = 32

// decodeStrict decodes one JSON value like encoding/json into any, but errs
// on a duplicate key in one object (encoding/json keeps the last one).
func decodeStrict(dec *json.Decoder, depth int) (any, error) {
	if depth > maxStrictDepth {
		return nil, fmt.Errorf("nested too deep")
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := tok.(json.Delim)
	if !isDelim {
		return tok, nil
	}
	switch d {
	case '{':
		m := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, _ := kt.(string)
			if _, dup := m[k]; dup {
				return nil, fmt.Errorf("duplicate key %q", k)
			}
			v, err := decodeStrict(dec, depth+1)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		_, err := dec.Token()
		return m, err
	case '[':
		var l []any
		for dec.More() {
			v, err := decodeStrict(dec, depth+1)
			if err != nil {
				return nil, err
			}
			l = append(l, v)
		}
		_, err := dec.Token()
		return l, err
	}
	return nil, fmt.Errorf("unexpected %v", d)
}

// parseSettingLine reads one text line: a line that names a setting
// anywhere must be exactly "key<sep>value" with one value token, or the
// answer is unreadable (a bullet, a help line, a usage line or a wider
// table never reads as a value or a default).
func parseSettingLine(line string, ss *settingsSeen) {
	folded := nearName(line)
	exact := false
	for _, spelling := range settingSpellings {
		exact = exact || strings.Contains(line, spelling)
	}
	if !exact {
		for _, spelling := range settingSpellings {
			if strings.Contains(folded, nearName(spelling)) {
				// A setting named in another case or spelling (FU8-R6).
				ss.put(settingNames[spelling], "", false)
				return
			}
		}
	}
	for _, spelling := range settingSpellings {
		name := settingNames[spelling]
		if !strings.Contains(line, spelling) {
			continue
		}
		rest, ok := strings.CutPrefix(line, spelling)
		if !ok || (rest != "" && !strings.ContainsAny(rest[:1], " \t:=")) {
			ss.put(name, "", false)
			return
		}
		rest = strings.TrimSpace(rest)
		if r, cut := strings.CutPrefix(rest, ":"); cut {
			rest = strings.TrimSpace(r)
		} else if r, cut := strings.CutPrefix(rest, "="); cut {
			rest = strings.TrimSpace(r)
		}
		if rest == "" || strings.ContainsAny(rest, " \t") {
			ss.put(name, "", false)
			return
		}
		v := normValue(rest)
		if v == "null" {
			v = ""
		}
		ss.put(name, v, true)
		return
	}
}

// onlyMembers reports whether every member of m is in allowed.
func onlyMembers(m map[string]any, allowed []string) bool {
	for k := range m {
		if !slices.Contains(allowed, k) {
			return false
		}
	}
	return true
}

// mentionsSetting reports whether s, folded (nearName), contains a
// setting name's fold: the text path's rule, applied to JSON keys and
// string values too (fix round 4, FU8-R8), so a dotted key
// ("gateway.proposal_approval_mode"), a suffixed key
// ("proposal_approval_mode_override") or a value naming a setting
// ("proposal_approval_mode=auto") is never walked past.
func mentionsSetting(s string) bool {
	f := nearName(s)
	for _, spelling := range settingSpellings {
		if strings.Contains(f, nearName(spelling)) {
			return true
		}
	}
	return false
}

// metaScalar reports whether a value object's or entry's scope or source
// member is a plain scalar that names no setting (fix round 4, FU8-R10:
// a nested object there would hide a setting from the walk).
func metaScalar(v any) bool {
	switch t := v.(type) {
	case nil, bool, float64:
		return true
	case string:
		return !mentionsSetting(t)
	}
	return false
}

// metaMembersScalar reports whether m's scope and source members, when
// present, are metaScalar.
func metaMembersScalar(m map[string]any) bool {
	for _, k := range []string{"scope", "source"} {
		if x, has := m[k]; has && !metaScalar(x) {
			return false
		}
	}
	return true
}

// walkSettings collects the two settings from a decoded JSON document, map
// keys in sorted order, to decodeStrict's depth (fix round 3, FU8-R4: no
// shallower bound). Two closed shapes consume a setting: a member whose
// key is exactly a setting's name (a scalar, or a value object with a
// scalar value and scalar scope and source), and an entry {key|name,
// value} with exactly one of key and name naming the setting. Any other
// key or string value whose fold contains a setting name's fold (an entry
// with both key and name, other member names, a dotted or suffixed key, a
// value naming a setting, a variant spelling) is unreadable, never
// skipped (fix round 4, FU8-R8).
func walkSettings(v any, ss *settingsSeen) {
	if ss.err != nil {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		consumed := walkSettingEntry(t, ss)
		for _, k := range sortedKeys(t) {
			if (k == "key" || k == "name") && consumed {
				continue
			}
			name, isSetting := settingNames[k]
			if !isSetting {
				if mentionsSetting(k) {
					ss.put(settingNames[settingSpellings[0]], "", false)
					return
				}
				walkSettings(t[k], ss)
				continue
			}
			x := t[k]
			if m, isMap := x.(map[string]any); isMap {
				var hasValue bool
				x, hasValue = m["value"]
				if !hasValue || !onlyMembers(m, settingObjectMembers) || !metaMembersScalar(m) {
					ss.put(name, "", false)
					continue
				}
			}
			val, ok := scalarValue(x)
			ss.put(name, val, ok)
		}
	case []any:
		for _, x := range t {
			walkSettings(x, ss)
		}
	case string:
		// A setting's name in a value no closed shape consumed.
		if mentionsSetting(t) {
			ss.put(settingNames[settingSpellings[0]], "", false)
		}
	}
}

// walkSettingEntry consumes a {key|name, value} entry naming a setting and
// reports whether it did. An entry naming a setting in any other shape
// sets the error.
func walkSettingEntry(t map[string]any, ss *settingsSeen) bool {
	key, keyIsString := t["key"].(string)
	nm, nameIsString := t["name"].(string)
	keyName, keySetting := settingNames[key]
	nmName, nmSetting := settingNames[nm]
	if !(keyIsString && keySetting) && !(nameIsString && nmSetting) {
		return false
	}
	_, hasKey := t["key"]
	_, hasName := t["name"]
	if hasKey && hasName {
		ss.put(settingNames[settingSpellings[0]], "", false)
		return true
	}
	name := keyName
	if !keySetting {
		name = nmName
	}
	x, has := t["value"]
	val, ok := scalarValue(x)
	ss.put(name, val, has && ok && onlyMembers(t, settingEntryMembers) && metaMembersScalar(t))
	return true
}

// scalarValue renders a JSON value as a normalized setting value: a
// string, a bool, 0 or 1, null (""), or a one-member typed value
// ({"string_value": "auto"}, {"bool_value": true}). ok is false for any
// other shape.
func scalarValue(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", true
	case string:
		return normValue(t), true
	case bool:
		return strconv.FormatBool(t), true
	case float64:
		if t == 0 || t == 1 {
			return strconv.FormatFloat(t, 'f', -1, 64), true
		}
	case map[string]any:
		if len(t) != 1 {
			return "", false
		}
		for _, k := range []string{"string_value", "stringValue", "bool_value", "boolValue"} {
			if x, ok := t[k]; ok {
				switch x.(type) {
				case string, bool:
					return scalarValue(x)
				}
			}
		}
	}
	return "", false
}

// globalAbsentPhrases are the answers of a failed `policy get --global`
// that mean "no global policy" (lower case). Anything else a failed read
// prints is unknown, never absent.
var globalAbsentPhrases = []string{"no global policy", "global policy not found", "global policy is not set", "no policy is set"}

// globalAbsentKeys are the members an exit-0 JSON answer may carry, each
// null, and still read as "no global policy" (fix round 1, FU8-A2). Any
// other JSON without a policy marker is unknown.
var globalAbsentKeys = []string{"policy", "global_policy", "globalPolicy"}

// globalRevisionMembers are the members of v0.1.6's global policy revision
// answer (`policy get --global [--full] -o json`, live check FU8-L1): the
// revision metadata, and with --full its "policy". Any other member makes
// the answer unknown.
var globalRevisionMembers = []string{"created_at_ms", "hash", "loaded_at_ms", "policy", "scope", "status", "version"}

// globalRevisionScope is the revision answer's scope for the global read.
const globalRevisionScope = "global"

// globalStatusRows is the revision status table, walked top-down (CLAUDE.md
// rule 5): a loaded revision is the global policy in force (row PS1 then
// applies), a superseded one was deleted (`policy delete --global`) and
// replaces nothing. Any other status is unknown, which never reads as
// absent.
var globalStatusRows = []struct {
	status string
	out    GlobalPolicy
}{
	{"loaded", GlobalPolicyPresent},
	{"superseded", GlobalPolicyAbsent},
}

// classifyGlobalRevision reads a revision answer (an object with a
// "status" member): every member in globalRevisionMembers, the scope (when
// present) "global", the policy (when present) an object or null, and the
// status a row of globalStatusRows; anything else is unknown.
func classifyGlobalRevision(m map[string]any) GlobalPolicy {
	if !onlyMembers(m, globalRevisionMembers) {
		return GlobalPolicyUnknown
	}
	if sc, has := m["scope"]; has && sc != globalRevisionScope {
		return GlobalPolicyUnknown
	}
	switch m["policy"].(type) {
	case nil, map[string]any:
	default:
		return GlobalPolicyUnknown
	}
	st, _ := m["status"].(string)
	for _, r := range globalStatusRows {
		if st == r.status {
			return r.out
		}
	}
	return GlobalPolicyUnknown
}

// ClassifyGlobalPolicy reads the answer of `openshell policy get --global
// --full -o json`. ok is whether the command exited 0; out is its stdout
// and stderr. A revision answer (an object with a "status" member, the
// v0.1.6 shape) is classified by classifyGlobalRevision. Otherwise Absent
// only for an empty answer, null, {}, an object whose members are all null
// and among globalAbsentKeys, or a failed read naming none (v0.1.6: "no
// global policy revision found"); Present for any answer holding a policy
// document (even one with empty sections); Unknown for everything else.
func ClassifyGlobalPolicy(ok bool, out []byte) GlobalPolicy {
	if len(out) > maxReadBack {
		return GlobalPolicyUnknown
	}
	if !ok {
		low := strings.ToLower(string(out))
		for _, p := range globalAbsentPhrases {
			if strings.Contains(low, p) {
				return GlobalPolicyAbsent
			}
		}
		return GlobalPolicyUnknown
	}
	trim := bytes.TrimSpace(out)
	if len(trim) == 0 || string(trim) == "null" || string(trim) == "{}" {
		return GlobalPolicyAbsent
	}
	doc, err := decodeStrictAll(trim)
	if err != nil {
		return GlobalPolicyUnknown
	}
	if m, isMap := doc.(map[string]any); isMap {
		if _, revision := m["status"]; revision {
			return classifyGlobalRevision(m)
		}
	}
	pols, err := findPolicies(doc)
	if err != nil {
		return GlobalPolicyUnknown
	}
	if len(pols) > 0 {
		return GlobalPolicyPresent
	}
	if m, isMap := doc.(map[string]any); isMap && len(m) > 0 {
		for k, v := range m {
			if v != nil || !slices.Contains(globalAbsentKeys, k) {
				return GlobalPolicyUnknown
			}
		}
		return GlobalPolicyAbsent
	}
	return GlobalPolicyUnknown
}

// policyMarkers are the keys that make a JSON object a policy document
// (snake_case as the YAML spells them, camelCase as protobuf JSON does).
var policyMarkers = []string{"network_policies", "networkPolicies", "filesystem_policy", "filesystemPolicy", "landlock"}

// isPolicy reports whether an object carries a policy marker with a
// non-null value.
func isPolicy(t map[string]any) bool {
	for _, k := range policyMarkers {
		if m, ok := t[k]; ok && m != nil {
			return true
		}
	}
	return false
}

// maxPolicyDepth bounds findPolicies' walk.
const maxPolicyDepth = 8

// errPolicyTooDeep is an answer with JSON nested past maxPolicyDepth: a
// document there could not be read, so the answer is unreadable.
var errPolicyTooDeep = fmt.Errorf("sandboxopenshell: the answer nests deeper than %d levels", maxPolicyDepth)

// findPolicies returns every policy-document object anywhere in the answer
// (fix round 2, FU8-R1): breadth first, map keys in sorted order, and it
// also descends into a found document's other members (a merged policy
// beside or above its layers, a filesystem-only document above another
// holding the network rules). The sections themselves (policyMarkers) are
// not searched for further documents. JSON nested past maxPolicyDepth
// errs.
func findPolicies(v any) ([]map[string]any, error) {
	var found []map[string]any
	level := []any{v}
	for d := 0; len(level) > 0; d++ {
		if d > maxPolicyDepth {
			return nil, errPolicyTooDeep
		}
		var next []any
		for _, x := range level {
			switch t := x.(type) {
			case map[string]any:
				for k := range t {
					if nearMiss(k, policyMarkers) {
						return nil, fmt.Errorf("sandboxopenshell: %q is a variant spelling of a policy section", k)
					}
				}
				policy := isPolicy(t)
				if policy {
					found = append(found, t)
				}
				for _, k := range sortedKeys(t) {
					if policy && slices.Contains(policyMarkers, k) {
						continue
					}
					next = append(next, t[k])
				}
			case []any:
				next = append(next, t...)
			}
		}
		level = next
	}
	return found, nil
}

// sortedKeys returns m's keys in order (a deterministic walk).
func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// EffectiveRule is one network rule as the gateway reports it.
type EffectiveRule struct {
	Key       string
	Endpoints []EffectiveEndpoint
	Binaries  []string
}

// EffectiveEndpoint is one endpoint as the gateway reports it.
type EffectiveEndpoint struct {
	Host        string
	Ports       []int
	Enforcement string
	// AllowedIPs are the address ranges; nil when the answer lists none
	// (no restriction: wider than any compiled list).
	AllowedIPs []string
}

// ParseEffectivePolicy reads the answer of `openshell policy get <box>
// --full -o json` and returns its network rules (none for a policy with no
// network_policies). It errs when the answer is not a policy document it
// recognizes.
func ParseEffectivePolicy(b []byte) ([]EffectiveRule, error) {
	if len(b) > maxReadBack {
		return nil, fmt.Errorf("sandboxopenshell.ParseEffectivePolicy: answer too large")
	}
	doc, err := decodeStrictAll(b)
	if err != nil {
		return nil, fmt.Errorf("sandboxopenshell.ParseEffectivePolicy: %w", err)
	}
	pols, err := findPolicies(doc)
	if err != nil {
		return nil, err
	}
	if len(pols) == 0 {
		return nil, fmt.Errorf("sandboxopenshell.ParseEffectivePolicy: the answer holds no policy document")
	}
	// Every document's rules are unioned, so every layer is compared, at
	// whatever depth it sits (FU8-A4, FU8-R1).
	var out []EffectiveRule
	for _, pol := range pols {
		rules, err := parseNetworkPolicies(pol)
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

// parseNetworkPolicies reads one policy document's network rules.
func parseNetworkPolicies(pol map[string]any) ([]EffectiveRule, error) {
	// Both spellings are read and unioned (FU8-R1): a document carrying
	// network_policies and networkPolicies has both compared.
	var out []EffectiveRule
	for _, k := range []string{"network_policies", "networkPolicies"} {
		rules, err := parseNetworkSection(pol[k])
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

// parseNetworkSection reads one network_policies map (nil: none).
func parseNetworkSection(raw any) ([]EffectiveRule, error) {
	if raw == nil {
		return nil, nil
	}
	rules, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("sandboxopenshell.ParseEffectivePolicy: network_policies is not a map")
	}
	var out []EffectiveRule
	for _, key := range sortedKeys(rules) {
		r, ok := rules[key].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("sandboxopenshell.ParseEffectivePolicy: rule %q is not an object", key)
		}
		er := EffectiveRule{Key: key}
		eps, _ := r["endpoints"].([]any)
		for _, x := range eps {
			e, ok := x.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("sandboxopenshell.ParseEffectivePolicy: an endpoint of %q is not an object", key)
			}
			ee, err := parseEndpoint(e)
			if err != nil {
				return nil, fmt.Errorf("sandboxopenshell.ParseEffectivePolicy: rule %q: %w", key, err)
			}
			er.Endpoints = append(er.Endpoints, ee)
		}
		bins, _ := r["binaries"].([]any)
		for _, x := range bins {
			switch b := x.(type) {
			case string:
				er.Binaries = append(er.Binaries, b)
			case map[string]any:
				p, _ := b["path"].(string)
				er.Binaries = append(er.Binaries, p)
			}
		}
		out = append(out, er)
	}
	return out, nil
}

// parseEndpoint reads one endpoint object.
func parseEndpoint(e map[string]any) (EffectiveEndpoint, error) {
	var out EffectiveEndpoint
	out.Host, _ = e["host"].(string)
	out.Enforcement, _ = e["enforcement"].(string)
	addPort := func(x any) error {
		switch p := x.(type) {
		case float64:
			out.Ports = append(out.Ports, int(p))
		case string:
			n, err := strconv.Atoi(p)
			if err != nil {
				return fmt.Errorf("port %q", p)
			}
			out.Ports = append(out.Ports, n)
		case nil:
		default:
			return fmt.Errorf("a port is not a number")
		}
		return nil
	}
	if ps, ok := e["ports"].([]any); ok {
		for _, p := range ps {
			if err := addPort(p); err != nil {
				return out, err
			}
		}
	}
	// A protobuf answer renders an unset single port as 0 beside the
	// ports list (FU8-A8): ignored then; alone it is every port.
	if p, isNum := e["port"].(float64); !isNum || p != 0 || len(out.Ports) == 0 {
		if err := addPort(e["port"]); err != nil {
			return out, err
		}
	}
	ips, ok := e["allowed_ips"].([]any)
	if !ok {
		ips, _ = e["allowedIps"].([]any)
	}
	for _, x := range ips {
		s, _ := x.(string)
		out.AllowedIPs = append(out.AllowedIPs, s)
	}
	return out, nil
}

// EffectiveVerdict is the per-box comparison's outcome.
type EffectiveVerdict string

// The closed EffectiveVerdict vocabulary (each widening names its row).
const (
	// EffectiveMatch: the gateway enforces nothing the compiled rules do
	// not hold (it may enforce less).
	EffectiveMatch EffectiveVerdict = "match"
	// EffectiveExtraRule: a rule key the compiled policy does not have
	// (a provider layer, an approved proposal, a global policy).
	EffectiveExtraRule EffectiveVerdict = "effective_policy_extra_rule"
	// EffectiveExtraProgram: a rule names a program the compiled rule does
	// not.
	EffectiveExtraProgram EffectiveVerdict = "effective_policy_extra_program"
	// EffectiveExtraHost: an endpoint host the compiled rule does not have.
	EffectiveExtraHost EffectiveVerdict = "effective_policy_extra_host"
	// EffectiveExtraPort: a port the compiled endpoint does not allow.
	EffectiveExtraPort EffectiveVerdict = "effective_policy_extra_port"
	// EffectiveExtraAddresses: an address range the compiled endpoint does
	// not allow (or no range at all where one was compiled).
	EffectiveExtraAddresses EffectiveVerdict = "effective_policy_extra_addresses"
	// EffectiveNotEnforced: an endpoint that only audits (OpenShell's
	// default) where the compiled one enforces.
	EffectiveNotEnforced EffectiveVerdict = "effective_policy_not_enforced"
	// EffectiveUnreadable: the effective policy could not be read.
	EffectiveUnreadable EffectiveVerdict = "effective_policy_unreadable"
)

// effectiveCheck is one row of the comparison table: it returns a detail
// when the effective endpoint or rule is wider than the compiled one.
type effectiveCheck struct {
	verdict EffectiveVerdict
	rule    func(got EffectiveRule, want NetRule) string
	ep      func(got EffectiveEndpoint, want NetEndpoint) string
}

// effectiveChecks is the comparison table, walked top-down per rule and
// per endpoint (the first widening wins).
var effectiveChecks = []effectiveCheck{
	{verdict: EffectiveExtraProgram, rule: func(got EffectiveRule, want NetRule) string {
		for _, b := range got.Binaries {
			if !slices.Contains(want.Binaries, b) {
				return b
			}
		}
		return ""
	}},
	{verdict: EffectiveExtraPort, ep: func(got EffectiveEndpoint, want NetEndpoint) string {
		for _, p := range got.Ports {
			if !slices.Contains(want.Ports, p) {
				return got.Host + " port " + strconv.Itoa(p)
			}
		}
		if len(got.Ports) == 0 {
			return got.Host + " (no port: every port)"
		}
		return ""
	}},
	{verdict: EffectiveExtraAddresses, ep: func(got EffectiveEndpoint, want NetEndpoint) string {
		if len(want.AllowedIPs) == 0 {
			return ""
		}
		if len(got.AllowedIPs) == 0 {
			return got.Host + " (no address range: every address)"
		}
		for _, s := range got.AllowedIPs {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				if a, aerr := netip.ParseAddr(s); aerr == nil {
					p = netip.PrefixFrom(a, a.BitLen())
				} else {
					return got.Host + " range " + strconv.Quote(s)
				}
			}
			if !prefixCovered(p.Masked(), want.AllowedIPs, 0) {
				return got.Host + " range " + p.String()
			}
		}
		return ""
	}},
	{verdict: EffectiveNotEnforced, ep: func(got EffectiveEndpoint, _ NetEndpoint) string {
		if !enforced(got.Enforcement) {
			return got.Host + " enforcement " + quoteOr(got.Enforcement, "(default: audit)")
		}
		return ""
	}},
}

// enforcementPrefixes are the enum prefixes a protobuf or serde answer may
// put before the value (lower case, longest first).
var enforcementPrefixes = []string{"enforcement_mode_", "enforcement_"}

// enforced reports whether an endpoint's enforcement is exactly "enforce"
// once lower-cased and stripped of one known enum prefix (fix round 1,
// FU8-A1): "audit", "not_enforced", "unenforced", "ENFORCEMENT_AUDIT",
// an empty value (OpenShell's default is audit) or any other spelling is
// not enforced.
func enforced(v string) bool {
	v = strings.ToLower(strings.TrimSpace(v))
	for _, p := range enforcementPrefixes {
		if r, ok := strings.CutPrefix(v, p); ok {
			v = r
			break
		}
	}
	return v == netEnforcement
}

// maxCoverDepth bounds prefixCovered's splitting (an IPv6 /0 down to /128).
const maxCoverDepth = 128

// prefixCovered reports whether every address of p lies in the union of
// want (FU8-A8: a gateway that coalesces 0.0.0.0/1 and 128.0.0.0/1 into
// 0.0.0.0/0 is not wider). p is split in halves only while a want prefix
// lies strictly inside it, so the walk is bounded by the want prefixes.
func prefixCovered(p netip.Prefix, want []netip.Prefix, depth int) bool {
	inside := false
	for _, w := range want {
		if w.Addr().Is4() != p.Addr().Is4() {
			continue
		}
		if w.Bits() <= p.Bits() && w.Contains(p.Addr()) {
			return true
		}
		if w.Bits() > p.Bits() && p.Contains(w.Addr()) {
			inside = true
		}
	}
	if !inside || depth >= maxCoverDepth || p.Bits() >= p.Addr().BitLen() {
		return false
	}
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	hi := netip.PrefixFrom(halfAddr(p), p.Bits()+1)
	return prefixCovered(lo, want, depth+1) && prefixCovered(hi, want, depth+1)
}

// halfAddr is the first address of p's upper half.
func halfAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	bit := p.Bits()
	b[bit/8] |= 0x80 >> (bit % 8)
	a, _ := netip.AddrFromSlice(b)
	return a
}

// CompareEffective compares the gateway's effective network rules with the
// compiled ones and returns the first widening and its detail
// (EffectiveMatch and "" when there is none). The comparison is one way:
// a rule or endpoint the gateway lacks is narrower, never a refusal here.
// Only network rules are compared: the baseline paths v0.1.6 adds to every
// box's filesystem view (read-only /var/log and /dev/urandom, live check
// FU8-L1) are not egress, and a single port the gateway reports as "port"
// rather than "ports" is the same port.
func CompareEffective(compiled []NetRule, effective []EffectiveRule) (EffectiveVerdict, string) {
	for _, got := range effective {
		i := slices.IndexFunc(compiled, func(r NetRule) bool { return r.Key == got.Key })
		if i < 0 {
			return EffectiveExtraRule, got.Key
		}
		want := compiled[i]
		for _, c := range effectiveChecks {
			if c.rule != nil {
				if d := c.rule(got, want); d != "" {
					return c.verdict, got.Key + ": " + d
				}
			}
		}
		for _, ep := range got.Endpoints {
			j := slices.IndexFunc(want.Endpoints, func(e NetEndpoint) bool { return strings.EqualFold(e.Host, ep.Host) })
			if j < 0 {
				return EffectiveExtraHost, got.Key + ": " + ep.Host
			}
			for _, c := range effectiveChecks {
				if c.ep != nil {
					if d := c.ep(ep, want.Endpoints[j]); d != "" {
						return c.verdict, got.Key + ": " + d
					}
				}
			}
		}
	}
	return EffectiveMatch, ""
}

// EffectiveVerdictOf reads a `policy get --full` answer and compares it:
// an unreadable answer is EffectiveUnreadable, never a match.
func EffectiveVerdictOf(compiled []NetRule, answer []byte) (EffectiveVerdict, string) {
	eff, err := ParseEffectivePolicy(answer)
	if err != nil {
		return EffectiveUnreadable, err.Error()
	}
	return CompareEffective(compiled, eff)
}
