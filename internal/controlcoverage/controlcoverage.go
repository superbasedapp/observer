// Package controlcoverage joins Observer's two independent, deliberately
// separate control-plane classifiers into ONE per-tool row:
//
//   - internal/integration's EnforcementChannel() ladder — can a dangerous
//     TOOL CALL be stopped? — and its sibling BudgetAdmissionChannel() —
//     can an Observer-managed spend cap be enforced pre-request?
//   - internal/guard's ConformanceMatrix() — can the developer's PROMPT be
//     blocked/asked-about before it ever reaches the model?
//
// Neither source package imports the other (internal/guard imports only
// internal/models + internal/policy; internal/integration imports neither
// internal/guard nor internal/policy in production code — only a guard test
// cross-checks against the registry). This package is the one place
// permitted to depend on both, so the two classifiers stay independently
// pure while still answering the combined question an operator or org admin
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
	"hook:UserPromptSubmit":   true,
	"hook:userPromptSubmit":   true, // kiro-cli's lowercase spelling
	"hook:BeforeAgent":        true, // gemini-cli
	"hook:beforeSubmitPrompt": true, // cursor
	"hook:pre_user_prompt":    true, // devin / Windsurf-Cascade
	"hook:transformInput":     true, // command-code (Mods SDK, not a shell hook)
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

// For returns the single control-coverage row for tool. ok=false when tool
// is not a registered adapter.
func For(tool string) (Row, bool) {
	c, ok := integration.For(tool)
	if !ok {
		return Row{}, false
	}
	return buildRow(c, guard.ConformanceMatrix()), true
}

func buildRow(c integration.Capability, matrix []guard.ConformanceEntry) Row {
	row := Row{
		Tool:            c.Tool,
		ToolCallChannel: c.EnforcementChannel(),
		BudgetChannel:   c.BudgetAdmissionChannel(),
		RouteProof:      routeProofFor(c),
	}
	row.PromptSubmit, row.Note = promptSubmitFor(c, matrix)
	return row
}

func routeProofFor(c integration.Capability) RouteProofState {
	if c.Proxy == nil {
		return RouteProofStateNone
	}
	if c.RouteProven() {
		return RouteProofStateProven
	}
	return RouteProofStateUnproven
}

func promptSubmitFor(c integration.Capability, matrix []guard.ConformanceEntry) (PromptSubmitChannel, string) {
	switch c.PromptLane {
	case integration.PromptLaneNone:
		return PromptSubmitNone, ""
	case integration.PromptLaneProbeRequired:
		return PromptSubmitProbeRequired, "vendor prompt-submit wire shape unverified — `observer doctor --probe-hook` decides"
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
			return PromptSubmitProbeRequired, "PromptLane=hook declared but no blocking conformance row found — investigate"
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
