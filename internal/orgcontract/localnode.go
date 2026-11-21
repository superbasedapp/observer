package orgcontract

import "regexp"

// LocalNodePosture is the gen9 summary of the node-local settings that
// shape policy and enforcement on a managed machine outside the guard's own
// rule layers (managed policy visibility audit 2026-11-12, gaps G4 to G13):
// the guard's level and prompt lanes, the local budget, routing, launch,
// default workspace, proxy, hooks, sandbox and MCP relay settings, and the
// node's own [org_client.share] switches. It rides LocalGuardPosture.Node on
// the guard policy-ack row. Bools, closed values (checked by shape, the way
// detector ids are, so a newer node's new value is not a 400), counts and
// list shapes only: no path, host, tool name or pattern travels.
type LocalNodePosture struct {
	// GuardLevel is [guard].level ("" = none); GuardStrict [guard].strict.
	GuardLevel  string `json:"guard_level,omitempty"`
	GuardStrict bool   `json:"guard_strict"`
	// RulesCEL is [guard.rules].cel; EvasionWindowSeconds
	// [guard.rules].evasion_window_seconds (0 = the built-in window).
	RulesCEL             bool `json:"rules_cel"`
	EvasionWindowSeconds int  `json:"evasion_window_seconds"`
	// The [guard.prompt] lanes.
	PromptHookLane           bool `json:"prompt_hook_lane"`
	PromptProxyLane          bool `json:"prompt_proxy_lane"`
	PromptEnforceIndependent bool `json:"prompt_enforce_independent"`
	PromptSuppressInCode     bool `json:"prompt_suppress_in_code"`

	// BudgetLocalCaps counts the [guard.budget] dollar and token caps the
	// machine sets (0 to 8); BudgetWindow is the shape of the
	// [guard.budget.window] utilization thresholds (default: none set,
	// custom: some set). Hard / FromOrg / FailClosed are the switches.
	BudgetLocalCaps  int    `json:"budget_local_caps"`
	BudgetWindow     string `json:"budget_window"`
	BudgetHard       bool   `json:"budget_hard"`
	BudgetFromOrg    bool   `json:"budget_from_org"`
	BudgetFailClosed bool   `json:"budget_fail_closed"`

	// [routing]: the switch, the local mode, the policy name and the count
	// of local rules.
	RoutingEnabled   bool   `json:"routing_enabled"`
	RoutingMode      string `json:"routing_mode,omitempty"`
	RoutingPolicy    string `json:"routing_policy,omitempty"`
	RoutingRuleCount int    `json:"routing_rule_count"`

	// [terminal.launch]: the switches, and the shape and count of the tool
	// and project root allow-lists (an empty list allows everything).
	LaunchAllowFreshAgent     bool   `json:"launch_allow_fresh_agent"`
	LaunchAllowShell          bool   `json:"launch_allow_shell"`
	LaunchAllowInstall        bool   `json:"launch_allow_install"`
	LaunchAllowedTools        int    `json:"launch_allowed_tools"`
	LaunchAllowedProjectRoots int    `json:"launch_allowed_project_roots"`
	DefaultWorkspace          string `json:"default_workspace"` // default | custom

	// [proxy] and [observer.hooks].
	ProxyEnabled           bool   `json:"proxy_enabled"`
	ProxyMaintainRoutes    bool   `json:"proxy_maintain_routes"`
	ProxyRequireClientAuth bool   `json:"proxy_require_client_auth"`
	HooksAutoRegister      bool   `json:"hooks_auto_register"`
	HooksPeriodicRegister  string `json:"hooks_periodic_register,omitempty"`
	HooksTimeoutMS         int    `json:"hooks_timeout_ms"`

	// [terminal.sandbox]: the switches, the backend ids, the egress mode
	// and the minimum isolation class.
	SandboxEnabled      bool     `json:"sandbox_enabled"`
	SandboxDefaultOn    bool     `json:"sandbox_default_on"`
	SandboxBackend      string   `json:"sandbox_backend,omitempty"`
	SandboxBackends     []string `json:"sandbox_backends,omitempty"`
	SandboxEgress       string   `json:"sandbox_egress,omitempty"`
	SandboxMinIsolation string   `json:"sandbox_min_isolation,omitempty"`

	// [mcp_relay].
	MCPRelayEnabled   bool   `json:"mcp_relay_enabled"`
	MCPRelayMode      string `json:"mcp_relay_mode,omitempty"`
	MCPRelayAuditMode string `json:"mcp_relay_audit_mode,omitempty"`

	// Share is the node's own [org_client.share] switches by key, as its
	// config sets them (what is in force on a managed node also depends on
	// the organization's grant and the managed policy tiers).
	Share map[string]bool `json:"share,omitempty"`
}

// localNodeTokenRe is the shape of every closed string value in
// LocalNodePosture: a config enum, a backend id or a share key.
var localNodeTokenRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)

// LocalNodeTokenOK reports whether s may travel as a closed string value of
// LocalNodePosture.
func LocalNodeTokenOK(s string) bool { return localNodeTokenRe.MatchString(s) }

// MaxLocalNodeListLen bounds SandboxBackends and Share.
const MaxLocalNodeListLen = 64

// Valid reports whether n carries only shaped tokens, list shapes and
// bounded counts. A nil n is valid.
func (n *LocalNodePosture) Valid() bool {
	if n == nil {
		return true
	}
	for _, s := range []string{
		n.GuardLevel, n.RoutingMode, n.RoutingPolicy, n.HooksPeriodicRegister,
		n.SandboxBackend, n.SandboxEgress, n.SandboxMinIsolation, n.MCPRelayMode, n.MCPRelayAuditMode,
	} {
		if s != "" && !localNodeTokenRe.MatchString(s) {
			return false
		}
	}
	if n.BudgetWindow != LocalListDefault && n.BudgetWindow != LocalListCustom {
		return false
	}
	if n.DefaultWorkspace != LocalListDefault && n.DefaultWorkspace != LocalListCustom {
		return false
	}
	for _, c := range []int{n.EvasionWindowSeconds, n.BudgetLocalCaps, n.RoutingRuleCount, n.LaunchAllowedTools, n.LaunchAllowedProjectRoots, n.HooksTimeoutMS} {
		if c < 0 || c > MaxLocalGuardInputCount {
			return false
		}
	}
	if len(n.SandboxBackends) > MaxLocalNodeListLen || len(n.Share) > MaxLocalNodeListLen {
		return false
	}
	for _, b := range n.SandboxBackends {
		if !localNodeTokenRe.MatchString(b) {
			return false
		}
	}
	for k := range n.Share {
		if !localNodeTokenRe.MatchString(k) {
			return false
		}
	}
	return true
}

// LocalNodeWeakenings returns, in table order, the node settings on which n
// is weaker than the shipped defaults: a prompt lane switched off, hooks no
// longer registered, the proxy off, or the dashboard launching a fresh agent
// or a plain shell. A nil n reports nothing.
func LocalNodeWeakenings(n *LocalNodePosture) []string {
	if n == nil {
		return nil
	}
	checks := []struct {
		key  string
		weak bool
	}{
		{"guard.prompt.hook_lane", !n.PromptHookLane},
		{"guard.prompt.proxy_lane", !n.PromptProxyLane},
		{"guard.prompt.enforce_independent", !n.PromptEnforceIndependent},
		{"observer.hooks.auto_register", !n.HooksAutoRegister},
		{"observer.hooks.periodic_register", n.HooksPeriodicRegister == "off"},
		{"proxy.enabled", !n.ProxyEnabled},
		{"terminal.launch.allow_fresh_agent", n.LaunchAllowFreshAgent},
		{"terminal.launch.allow_shell", n.LaunchAllowShell},
	}
	var out []string
	for _, c := range checks {
		if c.weak {
			out = append(out, c.key)
		}
	}
	return out
}
