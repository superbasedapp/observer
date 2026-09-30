package controlcoverage

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// wantRow pins every registered adapter's four control-coverage enum
// fields — ToolCallChannel, PromptSubmit, BudgetChannel, RouteProof — into
// exactly one expected combination. Derived 2026-09-22 from the grounded
// join in Rows()/buildRow(); cross-checked against the
// ~/sbo-scratch/s8/items/controls/ISSUE.md investigation's own 45-row
// table (which independently classified every tool by reading
// internal/integration + internal/guard/conformance.go by hand).
//
// This map is a GOLDEN PIN, not the classification logic itself (mirrors
// internal/integration/enforcement_test.go's wantEnforcementChannel) — it
// exists to catch a silent reclassification when a future registry/
// conformance edit changes a row's Hook/Handoff/Proxy/PromptLane/Caps
// shape, not to duplicate the join.
//
// Two corrections versus the ISSUE.md table are deliberate, not bugs:
//
//   - PromptSubmit is "proxy_only" (never folded into "none") for every
//     tool whose registry row declares PromptLane == PromptLaneProxyOnly
//     (aider, cline-cli, copilot-cli, crush, gemini's proxy-routed
//     siblings, goose, grok, hermes, opencode, pi, prime-agent). ISSUE.md's
//     own table marks most of these "none" — an understatement: the
//     registry's PromptLaneProxyOnly doc comment (internal/integration/
//     capability.go) states the proxy request-path prompt scan "is built
//     and wired, not a future phase," so folding it into "none" would hide
//     a real, already-shipped lever.
//   - poolside's PromptSubmit is "block_ask" even though its
//     ToolCallChannel is "recorded_acceptance" — this is the exact
//     classification gap ISSUE.md §1 flags: poolside's prompt-submit hook
//     is wired and verified, but EnforcementChannel() (correctly) can't
//     credit it because it's not a tool-CALL-blocking mechanism. Surfacing
//     both fields side by side on the same row is the fix.
var wantRow = map[string]struct {
	ToolCallChannel integration.EnforcementChannel
	PromptSubmit    PromptSubmitChannel
	BudgetChannel   integration.BudgetAdmissionChannel
	RouteProof      RouteProofState
}{
	"aider":            {integration.EnforceOrgDisallow, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"antigravity":      {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"antigravity-cli":  {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"chatgpt-web":      {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"claude-code":      {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateProven},
	"claude-web":       {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"cline":            {integration.EnforceRecordedAcceptance, PromptSubmitProbeRequired, integration.BudgetAdmissionNone, RouteProofStateNone},
	"cline-cli":        {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"codex":            {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateProven},
	"command-code":     {integration.EnforceSandbox, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"copilot":          {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"copilot-cli":      {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateProven},
	"copilot-web":      {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"cowork":           {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"crush":            {integration.EnforceOrgDisallow, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"cursor":           {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"deepseek":         {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"devin":            {integration.EnforceSandbox, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"droid":            {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"freebuff":         {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"gemini-cli":       {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"gemini-web":       {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"goose":            {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"grok":             {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"grokbot":          {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"hermes":           {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"junie":            {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kilo-code":        {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kilo-code-cli":    {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kimi-code":        {integration.EnforceSandbox, PromptSubmitProbeRequired, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"kiro-cli":         {integration.EnforceSandbox, PromptSubmitProbeRequired, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kiro-crew":        {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"mistral-code":     {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"muse":             {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"open-interpreter": {integration.EnforceSandbox, PromptSubmitProbeRequired, integration.BudgetAdmissionNone, RouteProofStateNone},
	"openclaw":         {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"opencode":         {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateProven},
	"perplexity-web":   {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"pi":               {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"poolside":         {integration.EnforceRecordedAcceptance, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"prime-agent":      {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"qoder":            {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"qwen-code":        {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"zcode":            {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"zed":              {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
}

// TestRowsClassifiedForEveryAdapter pins every registered adapter into
// exactly its expected 4-tuple, and fails loudly (naming the tool and the
// drifted field) when a future registry/conformance edit silently
// reclassifies a row.
func TestControlCoverageRowsClassifiedForEveryAdapter(t *testing.T) {
	rows := Rows()
	if len(rows) != len(wantRow) {
		t.Fatalf("Rows() returned %d rows, wantRow pins %d — keep them in sync", len(rows), len(wantRow))
	}
	seen := make(map[string]bool, len(rows))
	for _, r := range rows {
		seen[r.Tool] = true
		want, ok := wantRow[r.Tool]
		if !ok {
			t.Errorf("%s: no pinned expectation in wantRow — add one", r.Tool)
			continue
		}
		if r.ToolCallChannel != want.ToolCallChannel {
			t.Errorf("%s: ToolCallChannel = %q, want %q", r.Tool, r.ToolCallChannel, want.ToolCallChannel)
		}
		if r.PromptSubmit != want.PromptSubmit {
			t.Errorf("%s: PromptSubmit = %q, want %q", r.Tool, r.PromptSubmit, want.PromptSubmit)
		}
		if r.BudgetChannel != want.BudgetChannel {
			t.Errorf("%s: BudgetChannel = %q, want %q", r.Tool, r.BudgetChannel, want.BudgetChannel)
		}
		if r.RouteProof != want.RouteProof {
			t.Errorf("%s: RouteProof = %q, want %q", r.Tool, r.RouteProof, want.RouteProof)
		}
	}
	for tool := range wantRow {
		if !seen[tool] {
			t.Errorf("wantRow pins %q but Rows() has no such row", tool)
		}
	}
}

// TestNoteHonestyInvariant asserts the presentation-layer honesty rule: a
// row with no prompt-submit lever at all (PromptSubmitNone) never carries a
// Note (nothing to explain), and every OTHER bucket always carries a
// non-empty, grounded Note — never a silent gap next to a claimed
// capability.
func TestNoteHonestyInvariant(t *testing.T) {
	for _, r := range Rows() {
		if r.PromptSubmit == PromptSubmitNone {
			if r.Note != "" {
				t.Errorf("%s: PromptSubmit=none but Note is non-empty (%q) — a none row should carry no note", r.Tool, r.Note)
			}
			continue
		}
		if r.Note == "" {
			t.Errorf("%s: PromptSubmit=%q carries no Note — every non-none bucket must ground its claim", r.Tool, r.PromptSubmit)
		}
	}
}

// TestRouteProofOnlyMeaningfulWithBudgetChannel asserts the documented
// relationship between BudgetChannel and RouteProof: RouteProof is "none"
// exactly when there is no proxy route at all (Capability.Proxy == nil),
// which is exactly when BudgetChannel is also the zero value. A tool can
// never claim a proven/unproven route with no budget channel, or vice
// versa.
func TestRouteProofOnlyMeaningfulWithBudgetChannel(t *testing.T) {
	for _, r := range Rows() {
		hasBudget := r.BudgetChannel == integration.BudgetAdmissionObserverProxy
		hasRoute := r.RouteProof != RouteProofStateNone
		if hasBudget != hasRoute {
			t.Errorf("%s: BudgetChannel=%q RouteProof=%q — these must agree on whether a proxy route exists",
				r.Tool, r.BudgetChannel, r.RouteProof)
		}
	}
}

// TestPromptSubmitFor_AskOnceKeylessDegradesByCapabilityNotName pins the
// FIX for 2026-09-22 review finding 12: internal/controlcoverage used to
// hard-code a `hardBlockOnlyTools` map keyed on the literal tool name
// "command-code" to decide when a structurally ask-capable conformance
// row must still degrade to block-only — a violation of CLAUDE.md #3
// (branch on capabilities, never on tool identity). This test proves the
// degrade now follows guard.ConformanceEntry.AskOnceKeyless alone, using
// a SYNTHETIC tool that is not command-code, is not registered in
// internal/integration's real registry, and appears in no table anywhere
// in this package — if the degrade still fired for it, it could only be
// because the code reads the capability field, not a name.
func TestPromptSubmitFor_AskOnceKeylessDegradesByCapabilityNotName(t *testing.T) {
	const fakeTool = "not-a-real-registered-tool"
	cap := integration.Capability{Tool: fakeTool, PromptLane: integration.PromptLaneHook}
	keylessRow := guard.ConformanceEntry{
		Client:         fakeTool,
		Channel:        "hook:UserPromptSubmit",
		Caps:           policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
		AskOnceKeyless: true,
		Notes:          "synthetic: ask-capable wire verb but no session id to key ask-once on",
	}

	got, note := promptSubmitFor(cap, []guard.ConformanceEntry{keylessRow})
	if got != PromptSubmitBlockOnly {
		t.Errorf("promptSubmitFor(AskOnceKeyless=true) = %q, want %q — the degrade must follow the capability field, not a tool-name table",
			got, PromptSubmitBlockOnly)
	}
	if note != keylessRow.Notes {
		t.Errorf("note = %q, want the conformance row's own Notes %q", note, keylessRow.Notes)
	}

	// Identical row, AskOnceKeyless=false: the SAME tool, same wire
	// Caps, must NOT degrade — proving the field (not the tool) drives
	// the outcome.
	notKeylessRow := keylessRow
	notKeylessRow.AskOnceKeyless = false
	got2, _ := promptSubmitFor(cap, []guard.ConformanceEntry{notKeylessRow})
	if got2 != PromptSubmitBlockAsk {
		t.Errorf("promptSubmitFor(AskOnceKeyless=false) = %q, want %q", got2, PromptSubmitBlockAsk)
	}
}

// TestForMatchesRows cross-checks the single-tool lookup against the full
// table for every adapter.
func TestForMatchesRows(t *testing.T) {
	for _, r := range Rows() {
		got, ok := For(r.Tool)
		if !ok {
			t.Errorf("%s: For() returned ok=false for a Rows() member", r.Tool)
			continue
		}
		if got != r {
			t.Errorf("%s: For() = %+v, want %+v", r.Tool, got, r)
		}
	}
	if _, ok := For("not-a-real-tool"); ok {
		t.Error(`For("not-a-real-tool") = ok, want ok=false`)
	}
}
