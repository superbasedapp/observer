package sandboxselect

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// CaptureInput is what the capture level of one layer is computed from
// (section 4.4): the row, the tier and custody chosen for the run, and two
// facts about the tool.
type CaptureInput struct {
	Row     sandboxbackend.Capability
	Tier    vocab.Tier
	Custody vocab.KeyCustody
	// ProxyRouted: this launch actually goes through the Observer proxy:
	// the route the launch gets, not the registry row (a build without
	// capture.proxy, a proxy that is off, a gated route or a deliberate
	// third-party route all mean false).
	ProxyRouted bool
	// CredentialInReach: the agent can read a provider credential that
	// works without the proxy (bound tool state with an OAuth token, an
	// in-box seed or key, a key in the launch environment).
	CredentialInReach bool
	// ProviderDirect is the organization's direct provider egress posture
	// (DEC-9, OBS-8a): "" and capture_rule leave the table's result alone;
	// refuse_all and allow adjust it (providerDirectRules). The cmd layer
	// passes the value config.SandboxProviderDirect resolved, which is
	// capture_rule on every individual node.
	ProviderDirect vocab.ProviderDirect
}

// CaptureResult is the computed level, the rule that decided it and
// whether the run needs the model-provider host block (section 7.3).
type CaptureResult struct {
	Level vocab.CaptureLevel
	// Rule is the id of the first matching row ("C1" to "C8", or
	// RuleUnmatched).
	Rule string
	// ProviderBlock: the egress gateway must refuse the provider hosts and
	// every literal IP for this run (rule C6).
	ProviderBlock bool
	// GatewayGuarded: the level is full only through the provider-host
	// block; surfaces say "full (gateway-guarded)" and name the remaining
	// relay gap (D-752 Q42).
	GatewayGuarded bool
	// ProviderDirect names the organization posture that changed this
	// result (refuse_all or allow, DEC-9); "" when none did.
	ProviderDirect vocab.ProviderDirect
}

// RuleUnmatched names the conservative fallback when no row matches (for
// example a proxy_only tier whose source is only claimed).
const RuleUnmatched = "C-none"

// captureRule is one row of the ordered table.
type captureRule struct {
	id    string
	match func(in CaptureInput) bool
	level func(in CaptureInput) CaptureResult
}

func fixed(l vocab.CaptureLevel) func(CaptureInput) CaptureResult {
	return func(CaptureInput) CaptureResult { return CaptureResult{Level: l} }
}

// captureRules is section 4.4's table C1 to C8, first match wins. The
// result is then capped by the row's ceiling.
var captureRules = []captureRule{
	// C1: a verdict made inside the box is not trustworthy.
	{"C1", func(in CaptureInput) bool { return !in.Row.Capture.HookPath.ReachesHome() }, fixed(vocab.CaptureProxyAndTranscripts)},
	// C2: the provider's broker swaps the key for any request; counts are
	// box-reported.
	{"C2", func(in CaptureInput) bool { return in.Custody == vocab.CustodyProviderInjected }, fixed(vocab.CaptureProxyAndTranscripts)},
	// C3: a tool that is not proxy-routed keeps its unsandboxed capture:
	// hooks and transcripts, never the proxy's tokens. The plan's table says
	// "the ceiling"; lane sbx-p1a2 caps it at transcripts_only (audit
	// finding P-006 (2)), because a row whose ceiling is full would
	// otherwise label an unrouted run full.
	{"C3", func(in CaptureInput) bool { return !in.ProxyRouted }, func(in CaptureInput) CaptureResult {
		return CaptureResult{Level: vocab.MinCapture(in.Row.Capture.Ceiling, vocab.CaptureTranscriptsOnly)}
	}},
	// C4: no reusable credential in reach; the agent needs the proxy.
	{"C4", func(in CaptureInput) bool { return !in.CredentialInReach }, fixed(vocab.CaptureFull)},
	// C5: the network carries model traffic only through the proxy.
	{"C5", func(in CaptureInput) bool {
		return (in.Tier == vocab.TierProxyOnly || in.Tier == vocab.TierNone) && in.Row.Net.EgressSource[in.Tier].CountsForFloor()
	}, fixed(vocab.CaptureFull)},
	// C6: internet through Observer's gateway with a credential in reach:
	// full only with the provider-host block on.
	{"C6", func(in CaptureInput) bool {
		return in.Tier == vocab.TierInternet && in.Row.Net.Enforcer == sandboxbackend.EnforcerObserverGateway
	}, func(in CaptureInput) CaptureResult {
		if in.Row.Net.ProviderHostBlock {
			return CaptureResult{Level: vocab.CaptureFull, ProviderBlock: true, GatewayGuarded: true}
		}
		return CaptureResult{Level: vocab.CaptureProxyAndTranscripts}
	}},
	// C7: internet owned by a provider or a NetworkPolicy cannot refuse the
	// provider hosts reliably.
	{"C7", func(in CaptureInput) bool {
		return in.Tier == vocab.TierInternet && (in.Row.Net.Enforcer == sandboxbackend.EnforcerProvider || in.Row.Net.Enforcer == sandboxbackend.EnforcerK8sPolicy)
	}, fixed(vocab.CaptureProxyAndTranscripts)},
	// C8: the host network, or no network boundary at all.
	{"C8", func(in CaptureInput) bool {
		return in.Tier == vocab.TierHost || in.Row.Net.Enforcer == sandboxbackend.EnforcerNone || in.Row.Net.Enforcer == ""
	}, fixed(vocab.CaptureProxyAndTranscripts)},
}

// ComputeCapture walks the table and caps the result by the row's ceiling.
// A row with no grounded ceiling computes none.
func ComputeCapture(in CaptureInput) CaptureResult {
	res := CaptureResult{Level: vocab.CaptureProxyAndTranscripts, Rule: RuleUnmatched}
	for _, r := range captureRules {
		if r.match(in) {
			res = r.level(in)
			res.Rule = r.id
			break
		}
	}
	ceiling := in.Row.Capture.Ceiling
	if !ceiling.Valid() {
		ceiling = vocab.CaptureNone
	}
	capped := vocab.MinCapture(res.Level, ceiling)
	if capped != res.Level {
		res.ProviderBlock, res.GatewayGuarded = false, false
	}
	res.Level = capped
	for _, r := range providerDirectRules {
		if r.match(in, res) {
			res = r.apply(in, res)
			res.ProviderDirect = r.policy
			break
		}
	}
	return res
}

// providerDirectRule is one row of the organization's direct provider
// egress table (DEC-9). It runs after the C table and the ceiling cap, so
// it never changes which C rule decided the level: it only turns the one
// provider-host block (SBX-CAP-1) on where the org refuses provider hosts
// everywhere, or off where the org allows them, and keeps the level honest
// about that.
type providerDirectRule struct {
	policy vocab.ProviderDirect
	match  func(in CaptureInput, res CaptureResult) bool
	apply  func(in CaptureInput, res CaptureResult) CaptureResult
}

// gatewayEnforcesProviderBlock: this run's network goes through Observer's
// egress gateway on the internet tier and the row can refuse provider
// hosts there. Only such a run can carry the block; every other run's level
// already says it is not full through the block.
func gatewayEnforcesProviderBlock(in CaptureInput) bool {
	return in.Tier == vocab.TierInternet && in.Row.Net.Enforcer == sandboxbackend.EnforcerObserverGateway && in.Row.Net.ProviderHostBlock
}

// providerDirectRules is the DEC-9 table, first match wins. capture_rule
// (and "", and any unknown value) matches no row: today's C6 behaviour.
var providerDirectRules = []providerDirectRule{
	// refuse_all: the block goes on for every gateway-enforced internet run,
	// whatever rule decided the level. The level is unchanged: a run the
	// table already called full stays full, a lower one stays lower (a tool
	// that is not routed through the proxy cannot reach its provider then,
	// which is the organization's choice).
	{
		policy: vocab.ProviderDirectRefuseAll,
		match: func(in CaptureInput, res CaptureResult) bool {
			return in.ProviderDirect == vocab.ProviderDirectRefuseAll && !res.ProviderBlock && gatewayEnforcesProviderBlock(in)
		},
		apply: func(_ CaptureInput, res CaptureResult) CaptureResult {
			res.ProviderBlock = true
			return res
		},
	},
	// allow: no refusal. A run whose full capture rested on the block (C6,
	// gateway-guarded) drops to proxy_and_transcripts, so no surface claims
	// full capture for it. A run that is full without the block (C4: no
	// reusable credential in reach; C5: proxy only or no network) keeps it,
	// because a direct provider call cannot succeed there.
	{
		policy: vocab.ProviderDirectAllow,
		match: func(in CaptureInput, res CaptureResult) bool {
			return in.ProviderDirect == vocab.ProviderDirectAllow && res.ProviderBlock
		},
		apply: func(_ CaptureInput, res CaptureResult) CaptureResult {
			res.ProviderBlock, res.GatewayGuarded = false, false
			res.Level = vocab.MinCapture(res.Level, vocab.CaptureProxyAndTranscripts)
			return res
		},
	},
}

// CaptureByTier computes the level of every tier the row offers, for the
// probe's capture_by_tier map.
func CaptureByTier(row sandboxbackend.Capability, custody vocab.KeyCustody, proxyRouted, credentialInReach bool, providerDirect vocab.ProviderDirect) map[vocab.Tier]CaptureResult {
	out := map[vocab.Tier]CaptureResult{}
	for _, t := range row.Net.Egress {
		out[t] = ComputeCapture(CaptureInput{Row: row, Tier: t, Custody: custody, ProxyRouted: proxyRouted, CredentialInReach: credentialInReach, ProviderDirect: providerDirect})
	}
	return out
}

// CaptureLabel is the one display string for a computed level (the chip,
// the pill, the status line): "full (gateway-guarded)" for a C6 run.
func CaptureLabel(r CaptureResult) string {
	if r.Level == vocab.CaptureFull && r.GatewayGuarded {
		return "full (gateway-guarded)"
	}
	return string(r.Level)
}
