package sandboxopenshell

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// TestParseGatewaySettings: the accepted answer shapes, one case each, and
// the answers that do not name both settings.
func TestParseGatewaySettings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      string
		want    GatewaySettings
		wantErr bool
	}{
		{"json object", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false}`, GatewaySettings{"manual", "false"}, false},
		{"json settings member with value objects", `{"settings":{"proposal_approval_mode":{"value":"auto","scope":"gateway"},"agent_policy_proposals_enabled":{"value":true}}}`, GatewaySettings{"auto", "true"}, false},
		{"json list", `[{"key":"ocsf_json_enabled","value":true},{"key":"proposal_approval_mode","value":"AUTO"},{"name":"agent_policy_proposals_enabled","value":{"bool_value":false}}]`, GatewaySettings{"auto", "false"}, false},
		{"json numbers 0 and 1", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":1}`, GatewaySettings{"manual", "1"}, false},
		{"json explicit nulls", `{"proposal_approval_mode":null,"agent_policy_proposals_enabled":null}`, GatewaySettings{"", ""}, false},
		{"text key value", "proposal_approval_mode = \"auto\"\nagent_policy_proposals_enabled: true\n", GatewaySettings{"auto", "true"}, false},
		{"text space separated", "ocsf_json_enabled true\nproposal_approval_mode manual\nagent_policy_proposals_enabled false\n", GatewaySettings{"manual", "false"}, false},
		{"text null", "proposal_approval_mode: null\nagent_policy_proposals_enabled=0\n", GatewaySettings{"", "0"}, false},
		// Fix round 1 (FU8-A3): every shape the audit named is unreadable.
		{"value under another member name", `{"proposal_approval_mode":{"effective":"auto"},"agent_policy_proposals_enabled":false}`, GatewaySettings{}, true},
		{"entry with current_value", `[{"key":"proposal_approval_mode","current_value":"auto"},{"key":"agent_policy_proposals_enabled","value":false}]`, GatewaySettings{}, true},
		{"value outside the closed set", `{"proposal_approval_mode":"automatic","agent_policy_proposals_enabled":false}`, GatewaySettings{}, true},
		{"bool value outside the closed set", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":"enabled"}`, GatewaySettings{}, true},
		{"number outside the closed set", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":2}`, GatewaySettings{}, true},
		{"two scopes disagreeing", `{"gateway":{"proposal_approval_mode":"auto","agent_policy_proposals_enabled":false},"sandbox":{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false}}`, GatewaySettings{}, true},
		{"text table KEY SCOPE VALUE", "KEY                             SCOPE    VALUE\nproposal_approval_mode          gateway  auto\nagent_policy_proposals_enabled  default  false\n", GatewaySettings{}, true},
		{"text table KEY VALUE SCOPE", "proposal_approval_mode          manual  gateway\nagent_policy_proposals_enabled  false   default\n", GatewaySettings{}, true},
		{"usage line naming both keys", "usage: openshell settings set --key proposal_approval_mode|agent_policy_proposals_enabled --value <v>\n", GatewaySettings{}, true},
		{"help text", "proposal_approval_mode: how proposals are approved (manual or auto)\nagent_policy_proposals_enabled: whether agents may propose\n", GatewaySettings{}, true},
		{"key with no value", "proposal_approval_mode\nagent_policy_proposals_enabled\n", GatewaySettings{}, true},
		// Lane FU9: v0.1.6 prints an unset value as "<unset>" (live check
		// FU8-L1, Docker and rootless Podman alike); it is the default, in
		// both forms.
		{"unset marker", "proposal_approval_mode <unset>\nagent_policy_proposals_enabled false\n", GatewaySettings{"", "false"}, false},
		{"unset marker, json", `{"proposal_approval_mode":"<unset>","agent_policy_proposals_enabled":{"value":"<unset>","scope":"global"}}`, GatewaySettings{"", ""}, false},
		{"unset marker in a typed value", `[{"key":"proposal_approval_mode","value":{"string_value":"<UNSET>"}},{"key":"agent_policy_proposals_enabled","value":"<unset>"}]`, GatewaySettings{"", ""}, false},
		{"a marker with a space", "proposal_approval_mode <not set>\nagent_policy_proposals_enabled false\n", GatewaySettings{}, true},
		{"another marker", "proposal_approval_mode <default>\nagent_policy_proposals_enabled false\n", GatewaySettings{}, true},
		// Fix round 2 (FU8-R2), one row per shape.
		{"value object with scope and source", `{"proposal_approval_mode":{"value":"manual","scope":"global","source":"default"},"agent_policy_proposals_enabled":{"value":false}}`, GatewaySettings{"manual", "false"}, false},
		{"value object with a sibling effective", `{"proposal_approval_mode":{"value":null,"effective":"auto"},"agent_policy_proposals_enabled":false}`, GatewaySettings{}, true},
		{"list entry with a sibling effective", `[{"key":"proposal_approval_mode","value":null,"effective":"auto"},{"key":"agent_policy_proposals_enabled","value":false}]`, GatewaySettings{}, true},
		{"camelCase alone", `{"proposalApprovalMode":"auto","agentPolicyProposalsEnabled":false}`, GatewaySettings{"auto", "false"}, false},
		{"camelCase disagreeing with snake_case defaults", `{"defaults":{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false},"global":{"proposalApprovalMode":"auto"}}`, GatewaySettings{}, true},
		{"camelCase list entry", `[{"key":"proposalApprovalMode","value":"manual"},{"name":"agentPolicyProposalsEnabled","value":0}]`, GatewaySettings{"manual", "0"}, false},
		{"duplicate key in one object", `{"proposal_approval_mode":"auto","proposal_approval_mode":"manual","agent_policy_proposals_enabled":false}`, GatewaySettings{}, true},
		{"duplicate nested key", `{"settings":{"agent_policy_proposals_enabled":true,"agent_policy_proposals_enabled":false},"proposal_approval_mode":"manual"}`, GatewaySettings{}, true},
		{"text bullet", "- proposal_approval_mode: auto\nagent_policy_proposals_enabled false\n", GatewaySettings{}, true},
		{"text key mid-line", "sandbox x: proposal_approval_mode auto\nproposal_approval_mode manual\nagent_policy_proposals_enabled false\n", GatewaySettings{}, true},
		{"text camelCase line", "proposalApprovalMode: manual\nagentPolicyProposalsEnabled: false\n", GatewaySettings{"manual", "false"}, false},
		{"text two spellings disagreeing", "proposal_approval_mode manual\nproposalApprovalMode auto\nagent_policy_proposals_enabled false\n", GatewaySettings{}, true},
		// Fix round 3 (FU8-R4, FU8-R6), one row per shape.
		{"(i) a setting past the old depth bound", `{"defaults":{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false},"data":{"scopes":[{"name":"gateway","settings":[{"key":"proposal_approval_mode","value":"auto"}]}]}}`, GatewaySettings{}, true},
		{"(ii) entry with key and name", `{"defaults":{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false},"scopes":[{"key":"gateway","name":"proposal_approval_mode","value":"auto"}]}`, GatewaySettings{}, true},
		{"(iii) entry with other member names", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"overrides":[{"setting":"proposal_approval_mode","val":"auto"}]}`, GatewaySettings{}, true},
		{"setting name as a value elsewhere", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"changed":["proposal_approval_mode"]}`, GatewaySettings{}, true},
		{"key in another case", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"global":{"Proposal_Approval_Mode":"auto"}}`, GatewaySettings{}, true},
		{"key with surrounding space", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false," proposal_approval_mode":"auto"}`, GatewaySettings{}, true},
		{"text line in upper case", "proposal_approval_mode manual\nagent_policy_proposals_enabled false\nPROPOSAL_APPROVAL_MODE auto\n", GatewaySettings{}, true},
		// Fix round 4 (FU8-R8, FU8-R10), one row per shape.
		{"dotted key", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"overrides":{"gateway.proposal_approval_mode":"auto"}}`, GatewaySettings{}, true},
		{"suffixed key", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"proposal_approval_mode_override":"auto"}`, GatewaySettings{}, true},
		{"string value containing a setting name", `{"proposal_approval_mode":"manual","agent_policy_proposals_enabled":false,"applied":["proposal_approval_mode=auto"]}`, GatewaySettings{}, true},
		{"value object with a nested source", `{"proposal_approval_mode":{"value":"manual","source":{"proposal_approval_mode":"auto"}},"agent_policy_proposals_enabled":false}`, GatewaySettings{}, true},
		{"value object with an object scope", `{"proposal_approval_mode":{"value":"manual","scope":{"name":"gateway"}},"agent_policy_proposals_enabled":false}`, GatewaySettings{}, true},
		{"list entry with a nested source", `[{"key":"proposal_approval_mode","value":"manual","source":{"agent_policy_proposals_enabled":true}},{"key":"agent_policy_proposals_enabled","value":false}]`, GatewaySettings{}, true},
		{"value object with scalar scope and source", `{"proposal_approval_mode":{"value":"manual","scope":"gateway","source":"database"},"agent_policy_proposals_enabled":false}`, GatewaySettings{"manual", "false"}, false},
		// The fail-closed false positive FU8-L1 measures: a display name or
		// description that mentions a setting makes the answer unreadable.
		{"display name naming the setting", `[{"key":"proposal_approval_mode","value":"manual","label":"Proposal approval mode"},{"key":"agent_policy_proposals_enabled","value":false}]`, GatewaySettings{}, true},
		{"one missing", `{"proposal_approval_mode":"manual"}`, GatewaySettings{}, true},
		{"empty", "", GatewaySettings{}, true},
		{"unrelated", "error: unknown command settings", GatewaySettings{}, true},
	}
	for _, c := range cases {
		got, err := ParseGatewaySettings([]byte(c.in))
		if (err != nil) != c.wantErr || got != c.want {
			t.Errorf("%s: got %+v, %v; want %+v, err %v", c.name, got, err, c.want, c.wantErr)
		}
	}
	if (GatewaySettings{ApprovalMode: "bogus"}).AutoApproval() {
		t.Error("an unknown approval mode fails closed to manual upstream; it is not auto")
	}
}

// TestClassifyGlobalPolicy: one case per row of the classification.
func TestClassifyGlobalPolicy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		ok   bool
		in   string
		want GlobalPolicy
	}{
		{"empty answer", true, "", GlobalPolicyAbsent},
		{"null", true, "null", GlobalPolicyAbsent},
		{"empty object", true, "{}", GlobalPolicyAbsent},
		{"null policy member", true, `{"policy":null}`, GlobalPolicyAbsent},
		{"null global_policy member", true, `{"global_policy":null,"policy":null}`, GlobalPolicyAbsent},
		{"a policy", true, `{"policy":{"version":1,"network_policies":{"x":{"endpoints":[]}}}}`, GlobalPolicyPresent},
		{"a filesystem-only policy", true, `{"version":1,"filesystem_policy":{"read_only":["/"]}}`, GlobalPolicyPresent},
		// The managed brick risk (audit, decisions): an empty-sectioned
		// policy reads Present. FU8-L1's shape_global_none grounds what a
		// gateway with no global policy really answers.
		{"empty-sectioned policy", true, `{"policy":{"network_policies":{}}}`, GlobalPolicyPresent},
		// Fix round 1 (FU8-A2): JSON without a marker is unknown.
		{"policy as yaml text", true, `{"policy_yaml":"version: 1\nnetwork_policies: {}\n"}`, GlobalPolicyUnknown},
		{"global object with a revision", true, `{"global":{"revision":4,"status":"loaded"}}`, GlobalPolicyUnknown},
		{"error object", true, `{"error":"permission denied"}`, GlobalPolicyUnknown},
		{"policy member not null", true, `{"policy":"set"}`, GlobalPolicyUnknown},
		{"null beside another member", true, `{"policy":null,"revision":3}`, GlobalPolicyUnknown},
		{"a list", true, `[]`, GlobalPolicyUnknown},
		{"a string", true, `"none"`, GlobalPolicyUnknown},
		{"not json", true, "version: 1\nnetwork_policies: {}\n", GlobalPolicyUnknown},
		// Fix round 3 (FU8-R5, FU8-R6).
		{"duplicate policy key, the last null", true, `{"policy":{"network_policies":{"r":{}}},"policy":null}`, GlobalPolicyUnknown},
		{"variant section spelling", true, `{"policy":{"NetworkPolicies":{"r":{}}}}`, GlobalPolicyUnknown},
		{"trailing data", true, `{} {"policy":{"network_policies":{}}}`, GlobalPolicyUnknown},
		{"failed: none set", false, "Error: no global policy is configured", GlobalPolicyAbsent},
		{"failed: not found", false, "error: global policy not found", GlobalPolicyAbsent},
		{"failed: other", false, "error: connection refused", GlobalPolicyUnknown},
	}
	for _, c := range cases {
		if got := ClassifyGlobalPolicy(c.ok, []byte(c.in)); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

// TestGatewayDBAndFold: the managed database value and the fold table, one
// case per row.
func TestGatewayDBAndFold(t *testing.T) {
	t.Parallel()
	clean := GatewayPolicyFacts{SettingsRead: true, Settings: GatewaySettings{"manual", "false"}, Global: GlobalPolicyAbsent}
	if got := ClassifyGatewayDB(clean); got != GatewayDBClean {
		t.Fatalf("clean: %d", got)
	}
	auto := clean
	auto.Settings.ApprovalMode = "auto"
	if got := ClassifyGatewayDB(auto); got != GatewayDBChanged {
		t.Fatalf("auto: %d", got)
	}
	if got := ClassifyGatewayDB(GatewayPolicyFacts{}); got != GatewayDBUnknown {
		t.Fatalf("unread: %d", got)
	}
	cases := []struct {
		cfg  GatewayDrift
		db   GatewayDBDrift
		want GatewayDrift
	}{
		{GatewayDriftNone, GatewayDBNotRead, GatewayDriftNone},       // F0
		{GatewayDriftNone, GatewayDBChanged, GatewayDriftNone},       // F0: a stale reading never shows
		{GatewayDriftMatch, GatewayDBChanged, GatewayDriftChanged},   // F1
		{GatewayDriftChanged, GatewayDBClean, GatewayDriftChanged},   // F1
		{GatewayDriftChanged, GatewayDBNotRead, GatewayDriftChanged}, // F1
		{GatewayDriftMatch, GatewayDBUnknown, GatewayDriftUnknown},   // F2
		{GatewayDriftUnknown, GatewayDBClean, GatewayDriftUnknown},   // F2
		{GatewayDriftMatch, GatewayDBNotRead, GatewayDriftUnknown},   // F2 (FU8-A7)
		{GatewayDriftMatch, GatewayDBClean, GatewayDriftMatch},       // F3
	}
	for _, c := range cases {
		if got := FoldGatewayDrift(c.cfg, c.db); got != c.want {
			t.Errorf("fold(%s, %d) = %s, want %s", c.cfg, c.db, got, c.want)
		}
	}
}

// compiledRule is a compiled internet-tier rule over two hosts.
func compiledRule() []NetRule {
	allowed := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/2")}
	return []NetRule{{
		Key: NetRuleKey, Name: NetRuleKey,
		Endpoints: []NetEndpoint{
			{Host: "github.com", Entry: "github.com", Ports: NetPorts, AllowedIPs: allowed},
			{Host: "**.npmjs.org", Entry: "*.npmjs.org", Ports: NetPorts, AllowedIPs: allowed},
		},
		Binaries: []string{"/usr/local/bin/observer"},
	}}
}

// compiledHalves is a rule whose range is 0.0.0.0/1 plus 128.0.0.0/1.
func compiledHalves() []NetRule {
	r := compiledRule()
	r[0].Endpoints[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	return r
}

// effectiveJSON renders an effective answer around one network section.
func effectiveJSON(network string) string {
	return `{"sandbox":"sbo-x","revision":3,"policy":{"version":1,"filesystem_policy":{"read_only":["/usr"]},"network_policies":` + network + `}}`
}

// TestCompareEffective: one case per row of the comparison table, plus the
// narrower and matching answers.
func TestCompareEffective(t *testing.T) {
	t.Parallel()
	same := `{"observer_egress_allow_hosts":{"name":"observer_egress_allow_hosts","endpoints":[` +
		`{"host":"github.com","ports":[80,443],"enforcement":"enforce","allowed_ips":["0.0.0.0/1","128.0.0.0/2"]},` +
		`{"host":"**.npmjs.org","ports":[443],"enforcement":"enforce","allowed_ips":["1.2.3.0/24"]}],` +
		`"binaries":[{"path":"/usr/local/bin/observer"}]}}`
	cases := []struct {
		name    string
		answer  string
		rules   []NetRule
		verdict EffectiveVerdict
		detail  string
	}{
		{"same rules", effectiveJSON(same), compiledRule(), EffectiveMatch, ""},
		{"narrower (one host gone)", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"enforce","allowed_ips":["8.8.8.8"]}],"binaries":["/usr/local/bin/observer"]}}`), compiledRule(), EffectiveMatch, ""},
		{"camelCase answer", `{"policy":{"networkPolicies":{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","ports":["443"],"enforcement":"ENFORCE","allowedIps":["0.0.0.0/2"]}],"binaries":[]}}}}`, compiledRule(), EffectiveMatch, ""},
		{"no network on proxy_only", effectiveJSON(`null`), nil, EffectiveMatch, ""},
		{"empty network on proxy_only", effectiveJSON(`{}`), nil, EffectiveMatch, ""},
		{"a rule on proxy_only (approved proposal)", effectiveJSON(`{"approved_1":{"endpoints":[{"host":"evil.example","port":443,"enforcement":"enforce"}],"binaries":[]}}`), nil, EffectiveExtraRule, "approved_1"},
		{"a provider layer", effectiveJSON(`{"_provider_anthropic":{"endpoints":[{"host":"api.anthropic.com","port":443}]}}`), compiledRule(), EffectiveExtraRule, "_provider_anthropic"},
		{"extra program", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[],"binaries":[{"path":"/usr/bin/curl"}]}}`), compiledRule(), EffectiveExtraProgram, "/usr/bin/curl"},
		{"extra host", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"api.openai.com","port":443,"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveExtraHost, "api.openai.com"},
		{"extra port", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","ports":[22],"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveExtraPort, "port 22"},
		{"no port", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveExtraPort, "every port"},
		{"wider range", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"enforce","allowed_ips":["0.0.0.0/0"]}],"binaries":[]}}`), compiledRule(), EffectiveExtraAddresses, "0.0.0.0/0"},
		{"no range", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"enforce"}],"binaries":[]}}`), compiledRule(), EffectiveExtraAddresses, "every address"},
		{"enum enforce", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"ENFORCEMENT_ENFORCE","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveMatch, ""},
		{"enum audit", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"ENFORCEMENT_AUDIT","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveNotEnforced, "ENFORCEMENT_AUDIT"},
		{"enum mode audit", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"enforcement_mode_audit","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveNotEnforced, "enforcement_mode_audit"},
		{"not_enforced", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"not_enforced","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveNotEnforced, "not_enforced"},
		{"unenforced", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"unenforced","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveNotEnforced, "unenforced"},
		{"host in another case", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"GitHub.com","port":443,"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveMatch, ""},
		{"port 0 beside ports", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":0,"ports":[443],"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveMatch, ""},
		{"port 0 alone", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":0,"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveExtraPort, "port 0"},
		{"coalesced ranges", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"enforce","allowed_ips":["0.0.0.0/0"]}],"binaries":[]}}`), compiledHalves(), EffectiveMatch, ""},
		{"range past the union", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"enforce","allowed_ips":["::/0"]}],"binaries":[]}}`), compiledHalves(), EffectiveExtraAddresses, "::/0"},
		{"audit only", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"audit","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveNotEnforced, "audit"},
		{"enforcement left out", effectiveJSON(`{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}`), compiledRule(), EffectiveNotEnforced, "default: audit"},
		{"not json", "version: 1", compiledRule(), EffectiveUnreadable, ""},
		{"no policy document", `{"error":"not found"}`, compiledRule(), EffectiveUnreadable, "no policy document"},
		{"network not a map", effectiveJSON(`[]`), compiledRule(), EffectiveUnreadable, "not a map"},
	}
	for _, c := range cases {
		v, d := EffectiveVerdictOf(c.rules, []byte(c.answer))
		if v != c.verdict || !strings.Contains(d, c.detail) {
			t.Errorf("%s: got %s %q, want %s containing %q", c.name, v, d, c.verdict, c.detail)
		}
	}
}

// TestEffectiveReadArgv pins the three reads' argv on a pinned gateway and
// their refusals.
func TestEffectiveReadArgv(t *testing.T) {
	t.Parallel()
	tg := Target{Gateway: "openshell"}
	s, err := SettingsArgv(tg)
	if err != nil || !slices.Equal(s[len(s)-3:], []string{"settings", "get", "--global"}) {
		t.Fatalf("settings argv %v %v", s, err)
	}
	g, err := GlobalPolicyArgv(tg)
	if err != nil || !slices.Equal(g[len(g)-6:], []string{"policy", "get", "--global", "--full", "-o", "json"}) {
		t.Fatalf("global argv %v %v", g, err)
	}
	e, err := EffectivePolicyArgv(tg, "sbo-abc")
	if err != nil || !slices.Equal(e[len(e)-6:], []string{"policy", "get", "sbo-abc", "--full", "-o", "json"}) {
		t.Fatalf("effective argv %v %v", e, err)
	}
	if _, err := EffectivePolicyArgv(tg, "--all"); err == nil {
		t.Fatal("a flag is not a box name")
	}
	if _, err := SettingsArgv(Target{}); err == nil {
		t.Fatal("an unpinned target is refused")
	}
}

// TestEffectiveLayersUnioned (fix round 1, FU8-A4): an answer with several
// policy documents at one depth compares every layer, not the first.
func TestEffectiveLayersUnioned(t *testing.T) {
	t.Parallel()
	narrow := `{"version":1,"network_policies":{"observer_egress_allow_hosts":{"endpoints":[{"host":"github.com","port":443,"enforcement":"enforce","allowed_ips":["0.0.0.0/1"]}],"binaries":[]}}}`
	wide := `{"version":1,"network_policies":{"zz_layer":{"endpoints":[{"host":"pastebin.com","port":443,"enforcement":"enforce"}]}}}`
	for _, c := range []struct {
		name, answer string
		want         EffectiveVerdict
	}{
		{"wide layer sorts last", `{"layers":{"a_base":` + narrow + `,"b_global":` + wide + `}}`, EffectiveExtraRule},
		{"wide layer sorts first", `{"layers":{"a_global":` + wide + `,"b_base":` + narrow + `}}`, EffectiveExtraRule},
		{"layers in a list", `{"layers":[` + narrow + `,` + wide + `]}`, EffectiveExtraRule},
		{"one layer", `{"layers":{"a_base":` + narrow + `}}`, EffectiveMatch},
		// Fix round 2 (FU8-R1): documents at every depth.
		{"(a) merged policy beside its layers", `{"policy":` + narrow + `,"layers":{"global":` + wide + `}}`, EffectiveExtraRule},
		{"(b) filesystem-only document above the network rules", `{"spec":{"filesystem_policy":{"read_only":["/usr"]}},"status":{"effective":` + wide + `}}`, EffectiveExtraRule},
		{"(c) layers inside the found document", `{"policy":{"network_policies":` + netOf(narrow) + `,"layers":[` + wide + `]}}`, EffectiveExtraRule},
		{"both spellings in one document", `{"policy":{"network_policies":` + netOf(narrow) + `,"networkPolicies":` + netOf(wide) + `}}`, EffectiveExtraRule},
		{"both spellings, both narrow", `{"policy":{"network_policies":` + netOf(narrow) + `,"networkPolicies":` + netOf(narrow) + `}}`, EffectiveMatch},
		// Fix round 3 (FU8-R5, FU8-R6).
		{"duplicate network_policies, the last empty", `{"policy":{"version":1,"network_policies":` + netOf(wide) + `,"network_policies":{}}}`, EffectiveUnreadable},
		{"duplicate rule key", `{"policy":{"version":1,"network_policies":{"observer_egress_allow_hosts":{"endpoints":[{"host":"pastebin.com","port":443,"enforcement":"enforce"}]},"observer_egress_allow_hosts":{"endpoints":[]}}}}`, EffectiveUnreadable},
		{"variant section beside a narrow one", `{"policy":{"network_policies":` + netOf(narrow) + `,"NetworkPolicies":` + netOf(wide) + `}}`, EffectiveUnreadable},
		{"section key with a space", `{"policy":{"network_policies":` + netOf(narrow) + `," network_policies":` + netOf(wide) + `}}`, EffectiveUnreadable},
		{"nested past the bound", `{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":` + wide + `}}}}}}}}}`, EffectiveUnreadable},
	} {
		got, d := EffectiveVerdictOf(compiledRule(), []byte(c.answer))
		if got != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got, d, c.want)
		}
	}
	pols, err := findPolicies(mustJSON(t, `{"a":{"landlock":{}},"b":{"network_policies":{}},"c":{"x":{"landlock":{}}}}`))
	if err != nil || len(pols) != 3 {
		t.Fatalf("every depth: %d documents, %v", len(pols), err)
	}
	if ClassifyGlobalPolicy(true, []byte(`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}`)) != GlobalPolicyUnknown {
		t.Fatal("a global answer nested past the bound is unknown")
	}
}

// netOf returns the network_policies member of a test document.
func netOf(doc string) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(doc), &m); err != nil {
		panic(err)
	}
	return string(m["network_policies"])
}

// mustJSON decodes a test document.
func mustJSON(t *testing.T, s string) any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestPrefixCovered pins the union check, one case per shape.
func TestPrefixCovered(t *testing.T) {
	t.Parallel()
	halves := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	gap := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/2")}
	for _, c := range []struct {
		p    string
		want []netip.Prefix
		ok   bool
	}{
		{"0.0.0.0/0", halves, true},
		{"0.0.0.0/0", gap, false},
		{"192.168.0.0/16", gap, false},
		{"10.0.0.0/8", gap, true},
		{"::/0", halves, false},
		{"8.8.8.8/32", halves, true},
	} {
		if got := prefixCovered(netip.MustParsePrefix(c.p).Masked(), c.want, 0); got != c.ok {
			t.Errorf("prefixCovered(%s) = %v, want %v", c.p, got, c.ok)
		}
	}
}
