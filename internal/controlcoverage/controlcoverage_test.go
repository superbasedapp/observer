package controlcoverage

import (
	"reflect"
	"slices"
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
//     (aider, crush, gemini's proxy-routed
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
	"aider":            {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"antigravity":      {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"antigravity-cli":  {integration.EnforceHookBlock, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"chatgpt-web":      {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"claude-code":      {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven}, // OBS-4: proven per surface (CLI), not tool-wide; see TestRouteProofForSurface
	"claude-web":       {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"cline":            {integration.EnforceRecordedAcceptance, PromptSubmitProbeRequired, integration.BudgetAdmissionNone, RouteProofStateNone},
	"cline-cli":        {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateProven}, // T-208: providers.json read-back is launch evidence
	"codex":            {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateProven},
	"command-code":     {integration.EnforceSandbox, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"copilot":          {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"copilot-cli":      {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateProven},
	"copilot-web":      {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"cowork":           {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"crush":            {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"cursor":           {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"deepseek":         {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"devin":            {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"droid":            {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"freebuff":         {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"gemini-cli":       {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"gemini-web":       {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"goose":            {integration.EnforceHookBlock, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"grok":             {integration.EnforceHookBlock, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"grokbot":          {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"hermes":           {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"junie":            {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kilo-code":        {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kilo-code-cli":    {integration.EnforceHookBlock, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kimi-code":        {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"kiro-cli":         {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kiro-crew":        {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"mistral-code":     {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"muse":             {integration.EnforceHookBlock, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"open-interpreter": {integration.EnforceSandbox, PromptSubmitProbeRequired, integration.BudgetAdmissionNone, RouteProofStateNone},
	"openclaw":         {integration.EnforceSandbox, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"opencode":         {integration.EnforceHookBlock, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateProven},
	"perplexity-web":   {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"pi":               {integration.EnforceHookBlock, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"poolside":         {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"prime-agent":      {integration.EnforceSandbox, PromptSubmitProxyOnly, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"qoder":            {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"qwen-code":        {integration.EnforceHookBlock, PromptSubmitBlockAsk, integration.BudgetAdmissionObserverProxy, RouteProofStateUnproven},
	"zcode":            {integration.EnforceSandbox, PromptSubmitBlockAsk, integration.BudgetAdmissionNone, RouteProofStateNone},
	"zed":              {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	// The 2026-10-21 wave: no launcher or proxy route. The tools whose
	// tool-gate hook Observer registers live (IBM Bob, CodeBuddy, Deep
	// Agents, DimCode, Dirac, VT Code, Kimchi's bash pre-gate, and Cortex
	// Code through the rerouted Claude Code hooks) derive hook_block and a
	// block-only prompt gate. Autohand's pre-tool gate passed its live E2E
	// on 2026-10-22 (docs/guard.md "Live grounding: 2026-10-21 wave"), so
	// it derives hook_block too, though it stays `observer init`-only
	// (device sync); its prompt gate stays probe_required because the
	// guard conformance matrix has no blocking prompt-submit row for it.
	// Stakpak (no hook surface) stays recorded_acceptance.
	"autohand":        {integration.EnforceHookBlock, PromptSubmitProbeRequired, integration.BudgetAdmissionNone, RouteProofStateNone},
	"codebuddy":       {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"cortex-code":     {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"deepagents-code": {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"dimcode":         {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"dirac":           {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"ibm-bob":         {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"kimchi":          {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
	"stakpak":         {integration.EnforceRecordedAcceptance, PromptSubmitNone, integration.BudgetAdmissionNone, RouteProofStateNone},
	"vtcode":          {integration.EnforceHookBlock, PromptSubmitBlockOnly, integration.BudgetAdmissionNone, RouteProofStateNone},
}

// wantRouteNotObserved pins, per tool, the surfaces the registry-only route
// proof skips (integration.SurfaceRoute.NoProducer).
var wantRouteNotObserved = map[string][]string{
	"claude-code": {"ide/xcode"},
	"codex":       {"ide/xcode"},
}

// TestControlCoverageRowsClassifiedForEveryAdapter pins every registered
// adapter into exactly its expected 4-tuple, and fails loudly (naming the
// tool and the drifted field) when a future registry/conformance edit
// silently reclassifies a row.
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
		// AW-48: the registry-only view skips the surfaces no adapter can
		// produce yet, and names them; codex stays proven only because its
		// ide/xcode row (settings_ignored, MAC-1) is such a surface.
		if got, want := r.RouteNotObserved, wantRouteNotObserved[r.Tool]; !slices.Equal(got, want) {
			t.Errorf("%s: RouteNotObserved = %v, want %v", r.Tool, got, want)
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
		if !reflect.DeepEqual(got, r) {
			t.Errorf("%s: For() = %+v, want %+v", r.Tool, got, r)
		}
	}
	if _, ok := For("not-a-real-tool"); ok {
		t.Error(`For("not-a-real-tool") = ok, want ok=false`)
	}
}

// wantPostHocOnlyPromptTools is the GOLDEN PIN of PostHocOnlyPromptTools
// (prompt-guard coverage audit 2026-10-02,
// docs/audits/prompt-guard-coverage-audit-2026-10-02.md): the tools on which
// a prompt rule (R-172 / R-190) has NO pre-send seam at all — no verified
// prompt-submit hook and no proxy route — and so can only flag a prompt
// after it was sent. A registry edit that moves a tool in or out of this
// set must be a deliberate one: update this list and the audit's table.
var wantPostHocOnlyPromptTools = []string{
	"antigravity", "antigravity-cli", "autohand", "chatgpt-web", "claude-web", "cline",
	"copilot", "copilot-web", "cowork", "deepseek", "freebuff", "gemini-web",
	"grokbot", "junie", "kilo-code", "kilo-code-cli", "kiro-cli", "kiro-crew",
	"mistral-code", "muse", "open-interpreter", "openclaw", "perplexity-web",
	"stakpak", "zed",
}

func TestPostHocOnlyPromptTools(t *testing.T) {
	got := PostHocOnlyPromptTools()
	if len(got) != len(wantPostHocOnlyPromptTools) {
		t.Fatalf("PostHocOnlyPromptTools() = %v (%d), want %v (%d)", got, len(got), wantPostHocOnlyPromptTools, len(wantPostHocOnlyPromptTools))
	}
	for i := range got {
		if got[i] != wantPostHocOnlyPromptTools[i] {
			t.Fatalf("PostHocOnlyPromptTools()[%d] = %q, want %q (full: %v)", i, got[i], wantPostHocOnlyPromptTools[i], got)
		}
	}
}

// TestHasPreSendPromptSeam is the table for the seam predicate itself: one
// row per PromptSubmit bucket, with and without a proxy route.
func TestHasPreSendPromptSeam(t *testing.T) {
	cases := []struct {
		prompt PromptSubmitChannel
		route  RouteProofState
		want   bool
	}{
		{PromptSubmitBlockAsk, RouteProofStateNone, true},
		{PromptSubmitBlockOnly, RouteProofStateNone, true},
		{PromptSubmitProxyOnly, RouteProofStateProven, true},
		{PromptSubmitProbeRequired, RouteProofStateNone, false},
		{PromptSubmitProbeRequired, RouteProofStateUnproven, true},
		{PromptSubmitNone, RouteProofStateNone, false},
		{PromptSubmitNone, RouteProofStateProven, true},
	}
	for _, tc := range cases {
		r := Row{PromptSubmit: tc.prompt, RouteProof: tc.route}
		if got := r.HasPreSendPromptSeam(); got != tc.want {
			t.Errorf("prompt=%s route=%s: got %v want %v", tc.prompt, tc.route, got, tc.want)
		}
	}
}

// TestCapsCoverEveryCapabilityAndReadBindings: every row carries a coverage
// entry for every capability of the closed vocabulary, every state and seam
// comes from its closed set, and the states agree with the bindings: a
// wired gate the guard matrix lists is "wired", a probe_required prompt
// lane reports probe_required, and a hook-less row reports none throughout.
func TestCapsCoverEveryCapabilityAndReadBindings(t *testing.T) {
	states := map[CoverageState]bool{
		CoverageWired: true, CoverageRegistered: true,
		CoverageProbeRequired: true, CoverageVendorOnly: true, CoverageNone: true,
	}
	seams := map[string]bool{
		AltSeamNone: true, AltSeamProxy: true, AltSeamNativeCompile: true,
		AltSeamSandbox: true, AltSeamWatcher: true, AltSeamCaptureLane: true,
	}
	for _, r := range Rows() {
		if len(r.Caps) != len(integration.HookCaps()) {
			t.Errorf("%s: %d capability entries, want %d", r.Tool, len(r.Caps), len(integration.HookCaps()))
		}
		for cp, cov := range r.Caps {
			if !states[cov.State] || !seams[cov.AltSeam] {
				t.Errorf("%s/%s: out-of-vocabulary %+v", r.Tool, cp, cov)
			}
		}
	}
	cases := []struct {
		tool  string
		cap   integration.HookCap
		state CoverageState
		seam  string
	}{
		{"claude-code", integration.HookCapToolGate, CoverageWired, AltSeamNativeCompile},
		{"codex", integration.HookCapToolGate, CoverageWired, AltSeamSandbox},
		{"gemini-cli", integration.HookCapToolGate, CoverageWired, AltSeamSandbox},
		{"kimi-code", integration.HookCapToolGate, CoverageWired, AltSeamSandbox},
		{"kimi-code", integration.HookCapPromptGate, CoverageWired, AltSeamProxy},
		{"opencode", integration.HookCapToolGate, CoverageWired, AltSeamNativeCompile},
		{"openclaw", integration.HookCapToolGate, CoverageVendorOnly, AltSeamSandbox},
		{"zed", integration.HookCapToolGate, CoverageNone, AltSeamWatcher},
		{"chatgpt-web", integration.HookCapPromptGate, CoverageNone, AltSeamCaptureLane},
	}
	for _, tc := range cases {
		r, ok := For(tc.tool)
		if !ok {
			t.Fatalf("%s: no row", tc.tool)
		}
		got := r.Caps[tc.cap]
		if got.State != tc.state || got.AltSeam != tc.seam {
			t.Errorf("%s/%s = %+v, want state %s seam %q", tc.tool, tc.cap, got, tc.state, tc.seam)
		}
	}
}
