package sandboxkey

import (
	"slices"
	"strings"
)

// homekey.go decides whether a hosted run's model key can reach its agent
// under the configured key custody (audit
// docs/audits/hosted-sandbox-key-custody-2026-11-18.md). It is THE one
// owner of that question: the hosted probe (so the setup checklist and the
// New Terminal picker read it before Start), the launch (per tool, before
// any workspace is prepared or any box is made) and the per-tool line of
// the sandbox probe all walk this table. Before it, only the launch asked,
// with a rule of its own, so the checklist read ready while every launch
// was refused.
//
// A verdict that serves can still carry a Message: a line the person reads
// before Start that does not block it (which providers get a key, or that
// the agent starts with none). A refusal always carries one.
//
// The custody values are spelled as strings (the sandboxvocab spellings) so
// this package stays free of the vocabulary package, as Disclosure is.

// The custody spellings this table reads.
const (
	custodyHomeRelay      = "home_relay"
	custodyInBoxAPIKey    = "in_box_api_key" //nolint:gosec // G101: a custody spelling, not a credential
	custodyInBoxOAuthSeed = "in_box_oauth_seed"
)

// HomeKeyFacts are what the caller read, without opening a key, about how a
// hosted run's model key would reach the agent.
type HomeKeyFacts struct {
	// Custody is [terminal.sandbox.hosted].key_custody: "auto" (the default
	// since decision SBXD-1) or an explicit custody ("" reads as home_relay,
	// the value every node had before auto existed).
	Custody string
	// ToolCustody is [terminal.sandbox.hosted.key_custody_by_tool]'s value
	// for the tool ("" none); on a tool's launch it wins over Custody.
	ToolCustody string
	// InBoxRefused: the row the launch is judged for offers no in-box
	// custody (its capability row keeps every key on this machine, the
	// org-hosted row): auto resolves to home_relay there, and an explicit
	// in-box value is refused.
	InBoxRefused bool
	// OrgRoute: the org AI Gateway route is configured, which replaces any
	// credential with the org's own key at home.
	OrgRoute bool
	// InjectionSelected: the credential injection component is selected;
	// InjectionBuilt: this build has the proxy that swaps the box's
	// sentinel for the stored key.
	InjectionSelected bool
	InjectionBuilt    bool
	// StoredProviders are the providers that have a stored key (ids only).
	// An in-box custody takes them only while the component is selected.
	StoredProviders []string
	// InBoxEnvProviders are the providers whose in-box API-key variable
	// (Provider.InBoxEnv) is set in the daemon's own environment (ids only).
	InBoxEnvProviders []string
	// ForTool: one tool's launch is judged (the Tool* facts are then read);
	// false is the node-wide answer the probe and the setup step give.
	ForTool bool
	// ToolProviders are the providers credential injection may bind for the
	// tool (InjectableProviders); empty when it can serve none.
	ToolProviders []string
	// ToolUsable are the providers whose keys the tool can use at all
	// (UsableProviders): the ones an in-box custody gives it.
	ToolUsable []string
	// ToolName is the tool's display name, for the lines.
	ToolName string
	// ToolSavedKeys: the tool's own saved keys are a third in-box key source
	// (decision SBXD-4 (b): the person opted the tool in with
	// [terminal.sandbox.hosted.tool_keys] and its registry row grounds the
	// file); ToolSavedProviders are the providers that row reads. The file
	// itself is read only when the run starts.
	ToolSavedKeys      bool
	ToolSavedProviders []string
	// LoginSeed: the tool's login access token is copied into the box
	// (decision SBXD-4 (c): opted in with
	// [terminal.sandbox.hosted.login_seed] and the row grounds the file).
	LoginSeed bool
}

// The HomeKeyVerdict codes. The Served* codes and HomeKeyInBoxNoKey mean
// the launch goes ahead; every other code is a refusal of VerdictCode.
const (
	HomeKeyServedInBox     = "served_in_box"
	HomeKeyServedOrgRoute  = "served_org_route"
	HomeKeyServedInjection = "served_injection"
	// HomeKeyServedAuto: the node-wide answer under auto (each launch
	// resolves its own custody, and none is refused node-wide).
	HomeKeyServedAuto = "served_auto"
	// HomeKeyInBoxNoKey: the in-box custody finds no key this tool can use
	// on this machine; the agent starts without one (a tool that runs on
	// models needing no key, or one signed in inside the box, still works).
	HomeKeyInBoxNoKey = "in_box_no_key"

	HomeKeyLoginNotBuilt     = "in_box_login_not_built"
	HomeKeyCustodyNotOffered = "custody_not_offered"
	HomeKeyInjectionNotBuilt = "injection_not_built"
	HomeKeyNothingServes     = "nothing_serves_home_key"
	HomeKeyToolProvider      = "tool_provider_not_served"
	HomeKeyToolKeyMissing    = "tool_key_missing"
	// HomeKeyRowKeepsKeyHome: an in-box custody was chosen for a row that
	// keeps every model key on this machine.
	HomeKeyRowKeepsKeyHome = "row_keeps_key_home"
)

// VerdictCode is the refusal code every refused HomeKeyVerdict carries (the
// selection table's and the launch's spelling).
const VerdictCode = CodeCustodyNotOffered

// HomeKeyVerdict is the answer: OK, the closed Code, the plain Message a
// person reads (no config key, no enum value; on a served verdict an
// optional line that does not block), the Technical detail (the one place
// the internal names may appear: a "Technical details" tooltip, the CLI, a
// log), and the Providers whose key the agent gets (the bound set under
// injection, the key sources under an in-box custody; set for one tool).
type HomeKeyVerdict struct {
	OK        bool
	Code      string
	Message   string
	Technical string
	Providers []string
	// Resolution is the custody the launch runs with and why
	// (ResolveCustody); on a tool's launch the host helper runs with
	// Resolution.Custody.
	Resolution CustodyResolution
}

// homeKeyRule is one row: when match holds, the row decides.
type homeKeyRule struct {
	code      string
	ok        bool
	match     func(HomeKeyFacts) bool
	message   func(HomeKeyFacts) string
	tech      func(HomeKeyFacts) string
	providers func(HomeKeyFacts) []string
}

func fixed(s string) func(HomeKeyFacts) string { return func(HomeKeyFacts) string { return s } }

// homeKeyHowTo is the technical list of what serves home_relay, shared by
// the rows that refuse it.
const homeKeyHowTo = "key custody home_relay needs a key the proxy adds itself: a key stored with `observer sandbox credentials add <provider>` (component terminals.sandbox.credentials), or the org AI Gateway route ([proxy.org_route]); a [routing].key_pool never adds one. Or set [terminal.sandbox.hosted].key_custody = in_box_api_key (disclosed before the first upload)"

// inBoxSources are the providers whose key an in-box custody gives the
// tool: the ones it can use whose API-key variable the daemon's environment
// holds, or whose key is stored while the component is selected.
func inBoxSources(f HomeKeyFacts) []string {
	have := append([]string(nil), f.InBoxEnvProviders...)
	if f.InjectionSelected {
		have = append(have, f.StoredProviders...)
	}
	return Intersect(f.ToolUsable, have)
}

// inBoxSaved are the providers the tool's own saved keys may give it in the
// box (opted in, the row's providers the tool can use, not already given
// by a named source).
func inBoxSaved(f HomeKeyFacts) []string {
	if !f.ToolSavedKeys {
		return nil
	}
	named := inBoxSources(f)
	var out []string
	for _, id := range Intersect(f.ToolUsable, f.ToolSavedProviders) {
		if !slices.Contains(named, id) {
			out = append(out, id)
		}
	}
	return out
}

// inBoxAny reports whether an in-box custody has any key source for the
// tool: a named key, the tool's own saved keys, or its login.
func inBoxAny(f HomeKeyFacts) bool {
	return len(inBoxSources(f)) > 0 || len(inBoxSaved(f)) > 0 || f.LoginSeed
}

// toolLabel is the tool's display name, or "the agent".
func toolLabel(f HomeKeyFacts) string {
	if f.ToolName != "" {
		return f.ToolName
	}
	return "the agent"
}

// inBoxLine is the served in-box line: every source by name.
func inBoxLine(f HomeKeyFacts) string {
	var parts []string
	if ids := inBoxSources(f); len(ids) > 0 {
		parts = append(parts, "your "+ProviderLabels(ids, "and"))
	}
	if ids := inBoxSaved(f); len(ids) > 0 {
		parts = append(parts, "the "+ProviderLabels(ids, "or")+" "+toolLabel(f)+" saved itself, if it saved one (its key file is read when the run starts)")
	}
	msg := "This agent gets no API key in the box."
	if len(parts) > 0 {
		msg = "This agent gets " + joinWords(parts) + " in the box, where the agent and anyone with access to the box can read it."
	}
	if f.LoginSeed {
		msg += " Your " + toolLabel(f) + " login is copied into the box too: only its short-lived access token, never the refresh token, and only if it has not expired when the run starts."
	}
	return msg
}

// inBoxTech is the served in-box technical detail.
func inBoxTech(f HomeKeyFacts) string {
	t := "key custody in_box_api_key: the box gets the API key variables of " + joinIDs(inBoxSources(f)) + " from the daemon's environment, or from the keys stored with `observer sandbox credentials add` where the environment has none"
	if ids := inBoxSaved(f); len(ids) > 0 {
		t += "; then the tool's own saved keys of " + joinIDs(ids) + " ([terminal.sandbox.hosted.tool_keys], read at launch from the file its registry row names)"
	}
	if f.LoginSeed {
		t += "; and the tool's login access token without its refresh token ([terminal.sandbox.hosted.login_seed]), skipped when it has expired"
	}
	return t
}

// joinWords joins parts with commas and a final "and".
func joinWords(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// toolBound are the providers injection binds for the tool.
func toolBound(f HomeKeyFacts) []string { return Intersect(f.ToolProviders, f.StoredProviders) }

// keyVerb is "stays" for one key and "stay" for several.
func keyVerb(ids []string) string {
	if len(ids) == 1 {
		return "stays"
	}
	return "stay"
}

// homeKeyRules is the table, walked top-down; the first matching row
// decides (CLAUDE.md rule 5). The last row always matches.
var homeKeyRules = []homeKeyRule{
	{
		// An in-box custody chosen for a row that keeps every key on this
		// machine (the org-hosted row; its own probe row R2 says the same
		// node-wide): refused, never served in the box.
		code: HomeKeyRowKeepsKeyHome,
		match: func(f HomeKeyFacts) bool {
			return f.InBoxRefused && (f.Custody == custodyInBoxAPIKey || f.Custody == custodyInBoxOAuthSeed)
		},
		message: fixed("This sandbox keeps every model key on this machine, so a key cannot be put in its box. Choose to keep this agent's key on this machine."),
		tech:    fixed("an in-box key custody is set for a row whose capability row offers home_relay only; set [terminal.sandbox.hosted].key_custody (or the tool's key_custody_by_tool value) to auto or home_relay"),
	},
	{
		code:  HomeKeyServedAuto,
		ok:    true,
		match: func(f HomeKeyFacts) bool { return f.Custody == custodyAuto && !f.ForTool },
	},
	{
		code: HomeKeyServedInBox, ok: true,
		match: func(f HomeKeyFacts) bool {
			return f.Custody == custodyInBoxAPIKey && f.ForTool && inBoxAny(f)
		},
		message:   inBoxLine,
		tech:      inBoxTech,
		providers: inBoxSources,
	},
	{
		code: HomeKeyInBoxNoKey, ok: true,
		match:   func(f HomeKeyFacts) bool { return f.Custody == custodyInBoxAPIKey && f.ForTool },
		message: fixed("No API key this agent can use was found on this machine, so it starts in the box without one. It can still use models that need no key, or you can sign in inside the box. To give it a key, add yours from a terminal."),
		tech: func(f HomeKeyFacts) string {
			return "key custody in_box_api_key: none of the API key variables of " + joinIDs(f.ToolUsable) + " is set in the daemon's environment, and no key for them is stored with `observer sandbox credentials add <provider>` (read only while component terminals.sandbox.credentials is selected). A key the tool keeps in its own file, or its login, is copied only when the tool is opted in ([terminal.sandbox.hosted.tool_keys], [terminal.sandbox.hosted.login_seed]) and its registry row grounds the file"
		},
	},
	{
		code: HomeKeyServedInBox, ok: true,
		match: func(f HomeKeyFacts) bool { return f.Custody == custodyInBoxAPIKey },
	},
	{
		code:    HomeKeyLoginNotBuilt,
		match:   func(f HomeKeyFacts) bool { return f.Custody == custodyInBoxOAuthSeed },
		message: fixed("Copying a subscription login into a hosted box is not built yet. Choose another way for the agent to get its model key."),
		tech:    fixed("key custody in_box_oauth_seed is not built for hosted rows; use in_box_api_key or home_relay"),
	},
	{
		code:    HomeKeyCustodyNotOffered,
		match:   func(f HomeKeyFacts) bool { return f.Custody != "" && f.Custody != custodyHomeRelay },
		message: fixed("The chosen way of giving the agent its model key is not offered by any hosted sandbox. Choose another one."),
		tech:    func(f HomeKeyFacts) string { return "key custody " + f.Custody + " is not offered by any hosted row" },
	},
	{
		code: HomeKeyServedOrgRoute, ok: true,
		match: func(f HomeKeyFacts) bool { return f.OrgRoute },
	},
	{
		code:    HomeKeyInjectionNotBuilt,
		match:   func(f HomeKeyFacts) bool { return f.InjectionSelected && !f.InjectionBuilt },
		message: fixed("Keeping the model key on this machine needs the capture proxy, which this Observer build does not include. Put the API key in the box instead."),
		tech:    fixed("credential injection (terminals.sandbox.credentials) is selected, but this build has no capture proxy (sbo_omit_capture_proxy); " + homeKeyHowTo),
	},
	{
		code:    HomeKeyNothingServes,
		match:   func(f HomeKeyFacts) bool { return !f.InjectionSelected || len(f.StoredProviders) == 0 },
		message: fixed("The agent's model key is set to stay on this machine, but nothing here can add it to the agent's requests, so a hosted sandbox cannot start. Choose how the agent gets its model key."),
		tech:    fixed(homeKeyHowTo),
	},
	{
		code: HomeKeyServedInjection, ok: true,
		match: func(f HomeKeyFacts) bool { return !f.ForTool },
	},
	{
		code:    HomeKeyToolProvider,
		match:   func(f HomeKeyFacts) bool { return len(Known(f.ToolProviders)) == 0 },
		message: fixed("Observer cannot add a key kept on this machine to this agent's model requests. Put the API key in the box, or use your organization's AI gateway."),
		tech:    fixed("credential injection serves a tool whose model requests go through the proxy (a proxy route in its capability row) and whose provider is one it knows (anthropic, openai, google, xai, openrouter); " + homeKeyHowTo),
	},
	{
		code:  HomeKeyToolKeyMissing,
		match: func(f HomeKeyFacts) bool { return len(toolBound(f)) == 0 },
		message: func(f HomeKeyFacts) string {
			return "No " + ProviderLabels(Known(f.ToolProviders), "or") + " is stored on this machine, so it cannot be added for this agent. Add yours from a terminal, or put the API key in the box."
		},
		tech: func(f HomeKeyFacts) string {
			ids := Known(f.ToolProviders)
			if len(ids) == 1 {
				return "no " + ids[0] + " key is stored for credential injection: `observer sandbox credentials add " + ids[0] + "`"
			}
			return "no key of " + joinIDs(ids) + " is stored for credential injection: `observer sandbox credentials add <provider>`"
		},
	},
	{
		// Served by injection. A tool that can use several providers is told
		// which ones get a key (a one-provider tool's line would only repeat
		// the obvious, as before).
		code: HomeKeyServedInjection, ok: true,
		match: func(HomeKeyFacts) bool { return true },
		message: func(f HomeKeyFacts) string {
			if len(Known(f.ToolProviders)) < 2 {
				return ""
			}
			b := toolBound(f)
			msg := "Your " + ProviderLabels(b, "and") + " " + keyVerb(b) + " on this machine, and Observer adds each key only to this agent's requests to its own provider."
			if len(b) < len(Known(f.ToolProviders)) {
				msg += " Other providers this agent can use get no key from this machine."
			}
			return msg
		},
		tech: func(f HomeKeyFacts) string {
			if len(Known(f.ToolProviders)) < 2 {
				return ""
			}
			return "credential injection binds " + joinIDs(toolBound(f)) + " (one sentinel each, in each provider's key variable) of the tool's injectable providers " + joinIDs(Known(f.ToolProviders))
		},
		providers: toolBound,
	},
}

// joinIDs lists provider ids for a technical detail.
func joinIDs(ids []string) string {
	if len(ids) == 0 {
		return "no provider"
	}
	out := ids[0]
	for _, id := range ids[1:] {
		out += ", " + id
	}
	return out
}

// providerKeyLabel is a provider's key label ("Anthropic API key"), or a
// generic one for an id the table does not carry.
func providerKeyLabel(id string) string {
	if p, ok := ProviderFor(id); ok && p.KeyLabel != "" {
		return p.KeyLabel
	}
	return "API key for this agent's provider"
}

// HomeKey resolves the launch's custody (ResolveCustody) and walks the
// table with it. When the custody was not simply the node's setting (auto,
// or the tool's own value), the line says first which one this launch uses
// and why, so the dialog's key line always names it.
func HomeKey(f HomeKeyFacts) HomeKeyVerdict {
	rf, res := ResolvedFacts(f)
	v := homeKeyWalk(rf)
	v.Resolution = res
	if f.ForTool && res.Rule != CustodyRuleNodeSetting {
		v.Message = joinNonEmpty(" ", res.Why, v.Message)
		v.Technical = joinNonEmpty("; ", res.Technical, v.Technical)
	}
	return v
}

// joinNonEmpty joins the non-empty parts with sep.
func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// homeKeyWalk walks the table for one resolved custody.
func homeKeyWalk(f HomeKeyFacts) HomeKeyVerdict {
	for _, r := range homeKeyRules {
		if !r.match(f) {
			continue
		}
		v := HomeKeyVerdict{OK: r.ok, Code: r.code}
		if r.message != nil {
			v.Message = r.message(f)
		}
		if r.tech != nil {
			v.Technical = r.tech(f)
		}
		if r.providers != nil && f.ForTool {
			v.Providers = r.providers(f)
		}
		return v
	}
	return HomeKeyVerdict{OK: true, Code: HomeKeyServedInjection}
}

// Blocking reports whether a verdict keeps the launch from starting (a
// served verdict's Message is a line that does not block).
func (v HomeKeyVerdict) Blocking() bool { return !v.OK }
