// Package controlcoverage joins Observer's two independent, deliberately
// separate control-plane classifiers into ONE per-tool row:
//
//   - internal/integration's EnforcementChannel() ladder — can a dangerous
//     TOOL CALL be stopped? — and its sibling BudgetAdmissionChannel() —
//     can an Observer-managed spend cap be enforced pre-request?
//   - internal/guard's ConformanceMatrix() — can the developer's PROMPT be
//     blocked/asked-about before it ever reaches the model?
//
// internal/integration imports neither internal/guard nor internal/policy;
// internal/guard reads the registry's hook bindings to GENERATE its
// conformance matrix (hook-parity Lane 0 step 5) but keeps its own
// enforcement vocabulary. This package is the one place that joins the two
// classifiers' answers, so each stays independently pure while still
// answering the combined question an operator or org admin
// actually asks: "what, if anything, controls this developer's use of this
// tool?"
//
// Pure join: no SQL/HTTP/fsnotify (both source packages are pure data
// packages themselves — see their own package docs). See
// docs/plans/adapter-coverage-parity-plan-2026-06-26.md §16 and the
// 2026-09-22 control-coverage investigation
// (~/sbo-scratch/s8/items/controls/ISSUE.md + PLAN.md) for the grounding.
package controlcoverage

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// PromptSubmitChannel names the prompt-submit intervention shape for a
// tool — a SEPARATE lever from integration.EnforcementChannel, which only
// credits stopping an already-issued TOOL CALL (ISSUE.md §1). Five
// buckets, not the four first imagined for this table:
// PromptSubmitProxyOnly is a real, distinct mechanism (the proxy
// request-path prompt scan, internal/guard/proxyguard.go's scanPrompt) for
// every PromptLaneProxyOnly tool — collapsing it into "none" would hide a
// real lever, and collapsing it into "block_ask" would claim a hook dialect
// that does not exist for that tool. Keeping it separate is the honest
// choice (see the package's REPORT for the full reasoning).
type PromptSubmitChannel string

const (
	// PromptSubmitNone: no grounded prompt-submit intervention at all.
	PromptSubmitNone PromptSubmitChannel = "none"
	// PromptSubmitBlockAsk: a verified hook dialect can both block and ask
	// (the developer sees a readable, actionable message).
	PromptSubmitBlockAsk PromptSubmitChannel = "block_ask"
	// PromptSubmitBlockOnly: a verified hook dialect can only hard-block —
	// either the wire protocol documents no ask/message channel at all
	// (Caps.CanAsk == false, e.g. devin), or the dialect documents an
	// ask-capable reply verb but cannot structurally key the ask-once/
	// reconsider workflow (guard.ConformanceEntry.AskOnceKeyless == true,
	// e.g. command-code, which carries no session id in its payload at
	// all, so every finding fails closed to an unconditional block
	// regardless of what the wire verb nominally allows).
	PromptSubmitBlockOnly PromptSubmitChannel = "block_only"
	// PromptSubmitProbeRequired: the vendor's own docs are silent or
	// contested on the exact wire shape; guard.ConformanceMatrix() carries a
	// zero-Capabilities row rather than a guessed one. `observer doctor
	// --probe-hook` is what promotes this.
	PromptSubmitProbeRequired PromptSubmitChannel = "probe_required"
	// PromptSubmitProxyOnly: no prompt-submit hook exists for this tool, but
	// it is proxy-routed, so the proxy's own request-path prompt scan is the
	// only prompt-submit lever available.
	PromptSubmitProxyOnly PromptSubmitChannel = "proxy_only"
)

// RouteProofState is a tri-state read of Capability.RouteProven(): whether a
// budget-admission proxy route exists for this tool at all, and — when one
// does — whether THIS invocation's route is proven to reach it (vs. an
// ambient override the launcher does not own, e.g. goose's GOOSE_PROVIDER or
// aider's per-model backend switch).
type RouteProofState string

const (
	// RouteProofStateNone: Capability.Proxy is nil — no proxy route exists
	// for this tool at all.
	RouteProofStateNone RouteProofState = "none"
	// RouteProofStateProven: the launcher's applied route is the ONLY thing
	// that selects the backend (Capability.RouteProven() == true).
	RouteProofStateProven RouteProofState = "proven"
	// RouteProofStateUnproven: a proxy route exists, but an ambient
	// selector this invocation might carry can override it, so the route
	// alone does not prove the request reached the Observer proxy.
	RouteProofStateUnproven RouteProofState = "unproven"
)

// Row is one tool's full control-coverage picture, joining the two
// independent classifiers above plus the budget route-proof read.
type Row struct {
	Tool string
	// ToolCallChannel is integration.Capability.EnforcementChannel(): can a
	// dangerous, already-decided tool CALL be stopped?
	ToolCallChannel integration.EnforcementChannel
	// PromptSubmit: can the developer's PROMPT be blocked/asked-about
	// before it reaches the model at all? See PromptSubmitChannel.
	PromptSubmit PromptSubmitChannel
	// BudgetChannel is integration.Capability.BudgetAdmissionChannel(): can
	// an Observer-managed spend cap be enforced pre-request?
	BudgetChannel integration.BudgetAdmissionChannel
	// RouteProof only means something when BudgetChannel ==
	// BudgetAdmissionObserverProxy; see RouteProofState.
	RouteProof RouteProofState
	// Note carries the grounded, verbatim reason behind PromptSubmit when
	// one exists (a guard.ConformanceEntry.Notes excerpt, or a short
	// honest-zero explanation) — never fabricated, never paraphrased away
	// from its source.
	Note string
	// PromptWarnBeforeModel is true for a tool with no pre-send prompt
	// seam whose hook can still WARN before the model sees a new prompt
	// (integration.HookSpec.PromptWarnOnly: Antigravity CLI's
	// PreInvocation). It never makes HasPreSendPromptSeam true.
	PromptWarnBeforeModel bool
	// RouteProbeRequired is true for a tool with no proxy route yet whose
	// registry Routability is probe_required: a documented API-key/BYOK
	// base-URL path exists but is not live-verified, so the default mode
	// is not proxy-routable.
	RouteProbeRequired bool
	// PromptHookScope is the registry's HookSpec.PromptScope: the
	// surfaces a prompt hook covers when it does not cover all of them.
	PromptHookScope string
	// PromptProxyScope is the registry's ProxyRoute.PromptScope: which of
	// a routed tool's turns the proxy actually carries.
	PromptProxyScope string
	// Caps is the per-capability hook coverage view (caps.go): for every
	// capability of the closed integration.HookCap vocabulary, how far
	// Observer reaches it on this tool and the first non-hook seam that can
	// stand in for it. Additive: every field above keeps its value.
	Caps map[integration.HookCap]CapCoverage
	// Surfaces is the per-capture-surface posture (surfaceposture.go): for
	// every surface the registry declares a route or hook row for, how far
	// the tool-call gate and the proxy route reach it. Empty when none is
	// declared. RouteProof above is the tool-wide answer: proven only when
	// every declared surface that produces sessions is (AW-48).
	Surfaces []SurfacePosture
	// RouteNotObserved names ("ide/xcode") the declared surfaces the
	// tool-wide RouteProof skipped: in a registry-only view (and its node
	// fallback), the surfaces no adapter can produce yet
	// (integration.SurfaceRoute.NoProducer); in an observed node view, every
	// surface with zero sessions on the node. PostureText words the reason
	// per RouteProofBasis, so a skip is never silent. Empty when nothing was
	// skipped.
	RouteNotObserved []string
	// RouteProofBasis says what RouteProof was computed from (AW-48).
	RouteProofBasis RouteProofBasis
	// RouteBasisNote says why a node view fell back to the registry
	// (RouteBasisRegistryFallback); empty otherwise.
	RouteBasisNote string
	// ReplayedVia lists the tools whose own hook registration this tool's
	// wired gates ride (HookBinding.ReplayedVia, W-2b).
	ReplayedVia []string
}

// promptSubmitEvents is the closed set of guard.ConformanceMatrix channel
// names (its "hook:<event>" spelling) that carry the prompt the developer is
// about to send — as opposed to a channel that inspects an already-decided
// TOOL CALL (hook:PreToolUse, Cursor's beforeShellExecution /
// beforeMCPExecution / beforeReadFile) or an observe-only notification
// channel (codex hook:notify, hermes hook:plugin). This is DATA, keyed by
// wire-shape/event name, not by tool name (CLAUDE.md #3/#5): any
// conformance row naming one of these events is a prompt-submit row
// regardless of which tool it belongs to.
var promptSubmitEvents = map[string]bool{
	"hook:UserPromptSubmit":    true,
	"hook:userPromptSubmit":    true, // kiro-cli's lowercase spelling
	"hook:BeforeAgent":         true, // gemini-cli
	"hook:beforeSubmitPrompt":  true, // cursor
	"hook:pre_user_prompt":     true, // devin / Windsurf-Cascade
	"hook:transformInput":      true, // command-code (Mods SDK, not a shell hook)
	"hook:userPromptSubmitted": true, // copilot-cli (command hook, live 2026-10-15)
	"hook:beforeModel":         true, // cline-cli (Plugin API, live 2026-10-15)
}

// Rows returns the full, tool-sorted control-coverage table: one row per
// integration.Capabilities() entry.
func Rows() []Row {
	caps := integration.Capabilities()
	sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	matrix := guard.ConformanceMatrix()
	rows := make([]Row, 0, len(caps))
	for _, c := range caps {
		rows = append(rows, buildRow(c, matrix))
	}
	return rows
}

// preSendPromptChannels is the closed set of PromptSubmitChannel values that
// are themselves a working pre-send seam (prompt-guard coverage audit
// 2026-10-02). probe_required and none are not: their hook wire shape is
// unverified or absent.
var preSendPromptChannels = map[PromptSubmitChannel]bool{
	PromptSubmitBlockAsk:  true,
	PromptSubmitBlockOnly: true,
	PromptSubmitProxyOnly: true,
}

// HasPreSendPromptSeam reports whether ANY lane can judge this tool's prompt
// before it reaches the model: a verified prompt-submit hook dialect, or a
// proxy route — the proxy request-path prompt scan runs on every proxied
// request whatever the row's PromptLane says, so a probe_required tool that
// is proxy-routable still has one. False means the prompt rules (R-172 /
// R-190) can only flag this tool's prompts AFTER they were sent, via the
// post-hoc capture lane (internal/guard/posthocprompt.go). The seam still
// has to be wired on the node (hook registered, traffic routed): this is the
// static capability, the same honesty level as every other Row field.
func (r Row) HasPreSendPromptSeam() bool {
	return preSendPromptChannels[r.PromptSubmit] || r.RouteProof != RouteProofStateNone
}

// PostHocOnlyPromptTools returns, sorted, every registry tool with no
// pre-send prompt seam at all (!HasPreSendPromptSeam) — the ONE list the
// node dashboard and the org coverage surface both render, so the two can
// never disagree about which tools a prompt rule cannot stop.
func PostHocOnlyPromptTools() []string {
	out := []string{}
	for _, r := range Rows() {
		if !r.HasPreSendPromptSeam() {
			out = append(out, r.Tool)
		}
	}
	return out
}

// For returns the single control-coverage row for tool. ok=false when tool
// is not a registered adapter.
func For(tool string) (Row, bool) {
	c, ok := integration.For(tool)
	if !ok {
		return Row{}, false
	}
	return buildRow(c, guard.ConformanceMatrix()), true
}

// ForObserved is For with the tool-wide RouteProof counted over the
// surfaces this node produced sessions on (AW-48): groups are the node's
// session groups of tool (store.LoadSurfaceSessionCounts). A declared
// surface with no observed session is skipped and named in
// RouteNotObserved. With no evidence, or with evidence it cannot judge, the
// row falls back to the registry proof and says why
// (RouteBasisRegistryFallback; observedBasisRules).
func ForObserved(tool string, groups []SurfaceSession) (Row, bool) {
	c, ok := integration.For(tool)
	if !ok {
		return Row{}, false
	}
	ev := placeSessions(c, groups)
	for _, rule := range observedBasisRules {
		if note, hit := rule.hit(c, ev); hit {
			basis := RouteBasisRegistryFallback
			if note == "" {
				basis = RouteBasisRegistry
			}
			row := buildRowSeen(c, guard.ConformanceMatrix(), nil, basis)
			row.RouteBasisNote = note
			return row, true
		}
	}
	return buildRowSeen(c, guard.ConformanceMatrix(), ev.seen, RouteBasisObserved), true
}

func buildRow(c integration.Capability, matrix []guard.ConformanceEntry) Row {
	return buildRowSeen(c, matrix, nil, RouteBasisRegistry)
}

// buildRowSeen builds a row; seen nil is the registry-only proof.
func buildRowSeen(c integration.Capability, matrix []guard.ConformanceEntry, seen SurfaceSeen, basis RouteProofBasis) Row {
	proof, skipped := toolRouteProofSeen(c, seen)
	row := Row{
		Tool:             c.Tool,
		ToolCallChannel:  c.EnforcementChannel(),
		BudgetChannel:    c.BudgetAdmissionChannel(),
		RouteProof:       proof,
		RouteNotObserved: skipped,
		RouteProofBasis:  basis,
	}
	row.PromptSubmit, row.Note = promptSubmitFor(c, matrix)
	row.PromptWarnBeforeModel = c.Hook.PromptWarnOnly && c.Hook.Mechanism != integration.HookNone
	row.RouteProbeRequired = c.Proxy == nil && c.Routability == integration.RouteStatusProbeRequired
	row.PromptHookScope = c.Hook.PromptScope
	if c.Proxy != nil {
		row.PromptProxyScope = c.Proxy.PromptScope
	}
	row.Caps = capsFor(c)
	row.Surfaces = SurfacePostures(c)
	row.ReplayedVia = replayedVia(c)
	return row
}

func promptSubmitFor(c integration.Capability, matrix []guard.ConformanceEntry) (PromptSubmitChannel, string) {
	switch c.PromptLane {
	case integration.PromptLaneNone:
		return PromptSubmitNone, ""
	case integration.PromptLaneProbeRequired:
		return PromptSubmitProbeRequired, "vendor prompt-submit wire shape unverified - `observer doctor --probe-hook` decides"
	case integration.PromptLaneProxyOnly:
		return PromptSubmitProxyOnly, "no prompt-submit hook exists; the proxy request-path prompt scan is this tool's only prompt-submit lever"
	case integration.PromptLaneHook:
		entry, found := lookupPromptSubmitEntry(c.Tool, matrix)
		if !found || !entry.Caps.CanBlock {
			// A PromptLaneHook row should always resolve a blocking
			// conformance row (the registry's own doc comment says so) —
			// but if a future edit ever breaks that pairing, degrade to
			// an honest "investigate" note rather than silently claiming
			// "none".
			return PromptSubmitProbeRequired, "PromptLane=hook declared but no blocking conformance row found - investigate"
		}
		// AskOnceKeyless is the STRUCTURAL capability that degrades
		// CanAsk=true to block-only (2026-09-22 review finding 12): the
		// conformance row itself declares whether the ask-once/
		// reconsider workflow can actually be keyed, so this branches on
		// that capability field — never on c.Tool (CLAUDE.md #3).
		if entry.Caps.CanAsk && !entry.AskOnceKeyless {
			return PromptSubmitBlockAsk, entry.Notes
		}
		return PromptSubmitBlockOnly, entry.Notes
	default:
		return PromptSubmitNone, "unrecognized PromptLane value"
	}
}

// lookupPromptSubmitEntry finds tool's prompt-submit conformance row (the
// one whose Channel is a promptSubmitEvents member). found=false means no
// such row exists in matrix.
func lookupPromptSubmitEntry(tool string, matrix []guard.ConformanceEntry) (guard.ConformanceEntry, bool) {
	for _, e := range matrix {
		if e.Client != tool || !promptSubmitEvents[e.Channel] {
			continue
		}
		return e, true
	}
	return guard.ConformanceEntry{}, false
}
