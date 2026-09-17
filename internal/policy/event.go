package policy

import "time"

// EventKind classifies the surface a policy Event originated from.
// Rules declare which kinds they apply to (Rule.AppliesTo); the engine
// never inspects the originating client, only the kind plus
// capability flags (spec §3.3).
type EventKind string

// EventKind values (spec §3.4). G1 ships rules for KindShellExec and
// KindFileAccess; the remaining kinds are defined now so boundary code
// written in later commits classifies against a stable vocabulary.
const (
	// KindToolCall is a generic (non-shell, non-file) tool
	// invocation observed at a hook or in a transcript.
	KindToolCall EventKind = "tool_call"
	// KindFileAccess is a file read/write/edit; Target is the path
	// and ActionType carries the models-taxonomy verb.
	KindFileAccess EventKind = "file_access"
	// KindShellExec is a shell command execution; Target is the raw
	// command string (or Args the pre-split argv).
	KindShellExec EventKind = "shell_exec"
	// KindMCPCall is an MCP tool invocation.
	KindMCPCall EventKind = "mcp_call"
	// KindAPIRequest is an outbound LLM API request (proxy seam).
	KindAPIRequest EventKind = "api_request"
	// KindAPIResponse is an LLM API response (proxy seam).
	KindAPIResponse EventKind = "api_response"
	// KindConfigChange is a change to a watched client/MCP/guard
	// configuration file.
	KindConfigChange EventKind = "config_change"
	// KindSessionMeta is session-level metadata (posture signals
	// such as yolo flags or sandbox state).
	KindSessionMeta EventKind = "session_meta"
	// KindUserPrompt is the developer's own prompt text at
	// submit-time (hook lane) or the latest user turn extracted from
	// an outbound LLM API request (proxy lane) — the prompt-submit
	// intervention feature (docs/plans/
	// prompt-submit-intervention-exploration-2026-09-07.md). Target
	// is empty; the prompt text itself is NEVER carried on the
	// Event (only PIIFindings/Secrets, the compute-at-the-owner
	// detector output) — this package never sees prompt content.
	KindUserPrompt EventKind = "user_prompt"
)

// Dialect identifies the shell dialect of a command string so the
// parser can apply the right tokenization and alias rules. It is
// resolved AT THE BOUNDARY per client+OS — capability-style data, not
// tool identity (approved deviation 1, guard-g1-design-note §4).
// Regardless of the hint, nested `powershell -Command` / `cmd /c`
// invocations are detected mid-parse and switch dialect for their
// payloads.
type Dialect string

// Dialect values. An empty Dialect means DialectPosix.
const (
	// DialectPosix covers sh/bash/zsh-style command lines (also the
	// Git-Bash-on-Windows hook path).
	DialectPosix Dialect = "posix"
	// DialectPowerShell covers Windows PowerShell / pwsh command
	// lines.
	DialectPowerShell Dialect = "powershell"
	// DialectCmd covers cmd.exe command lines.
	DialectCmd Dialect = "cmd"
)

// Capabilities describes what the originating channel can do, resolved
// at the boundary (hook receiver / adapter / proxy) per client+OS.
// Rules and emission logic branch on these flags, never on tool
// identity (spec §3.3). The per-client values live in the conformance
// matrix (G6) — a data table, not code.
type Capabilities struct {
	// PreExecution is true when the event arrives BEFORE the action
	// executes (hook, proxy) and false on post-hoc surfaces
	// (watcher ingest).
	PreExecution bool
	// CanBlock is true when the channel can actually stop the
	// action (documented deny semantics — spec §0.1 Q4: probed per
	// client, never assumed).
	CanBlock bool
	// CanAsk is true when the client renders a native ask/permission
	// prompt. Without it, ask degrades per spec §6.2 — never to a
	// silent allow.
	CanAsk bool
	// HasNativeDeny is true when the client has its own deny-rule
	// dialect that observer compiles policy into (spec §13.2).
	HasNativeDeny bool
	// Sandboxed is true when the session runs inside an OS sandbox
	// (posture signal, spec §13.1).
	Sandboxed bool
	// ProxyRouted is true when the client's API traffic flows
	// through the observer proxy.
	ProxyRouted bool
}

// TaintMark records one untrusted-source observation in a session
// (spec §4.5): a web fetch result, an MCP result from an unpinned
// server, a read of an externally-modified file, and so on.
type TaintMark struct {
	// Source is the source class (the TaintSourceXxx constants in
	// rules_taint.go: "web_fetch", "mcp_unpinned", "external_file",
	// "attachment", "secrets_read").
	Source string
	// Origin is a bounded human-readable description of where the
	// taint came from (a URL host, a server name — never content).
	Origin string
	// Imperative is set when the source CONTENT carried
	// imperative-instruction patterns (the §8.4 injection
	// heuristics, proxy-side — G9). Watcher-path marks never set it:
	// content is not inspected post-hoc. T-501 consumes it.
	Imperative bool
	// Turn is the session turn index at which the mark was set;
	// taint decays after [guard.taint].decay_turns.
	Turn int
	// At is when the mark was set.
	At time.Time
}

// TaintState is the per-session set of active taint marks. The state
// is OWNED by the guard composition layer (G3) — it tracks
// cross-event session state and decay; this package only ever reads
// the snapshot it receives on the Event (spec §17.4 one-owner rule).
// In G1 the type exists so the Event shape is complete; the T-5xx
// rules that consume it land with the guard layer.
type TaintState struct {
	// Marks are the active (not yet decayed) taint marks.
	Marks []TaintMark
}

// Tainted reports whether any taint mark is active.
func (t TaintState) Tainted() bool { return len(t.Marks) > 0 }

// HasSource reports whether any active mark carries the given source
// class. Used by rules and by the user-rule taint_source matcher.
func (t TaintState) HasSource(source string) bool {
	for _, m := range t.Marks {
		if m.Source == source {
			return true
		}
	}
	return false
}

// Event is one normalized agent action presented for evaluation — the
// only input type that crosses the seam (spec §3.4). Boundaries (hook
// receiver, proxy, ingest) build an Event and call Engine.Evaluate;
// nothing in this package reaches back out for more context.
type Event struct {
	// Kind classifies the originating surface; rules filter on it.
	Kind EventKind
	// ActionType carries the models-taxonomy verb ("read_file",
	// "write_file", "edit_file", "run_command", ...) when the event
	// is sourced from a normalized Action. The string values mirror
	// internal/models; they are not imported to keep this package
	// dependency-free (see actionIsWrite in rules_boundary.go).
	ActionType string
	// Tool is the client name. It is REPORTING data for every rule in
	// this package except the SUBJECT budget rows (B-626/B-627), which
	// compare it against an organization cap the admin authored FOR
	// that tool (bundle BUD-N).
	//
	// That is not the branch §17.3 forbids. The forbidden shape is a
	// hardcoded comparison against a vendor's name — behaviour this
	// repo decided for one client. A subject cap is DATA: the org
	// authored a row naming a subject, the rule walks the rows it was
	// given, and the same code path serves a tool nobody here has
	// heard of. Nothing in this package enumerates tool names.
	Tool string
	// Model is the model id the capture path recorded for this event
	// ("claude-sonnet-4-5-20250929", ...), stamped by the boundary that
	// built the event. Like Tool it is reporting data everywhere except
	// the subject budget rows (B-628/B-629), which compare it against an
	// organization cap authored for that model. "" means the boundary
	// does not know one (every hook-path and most watcher-path events),
	// and a model cap then simply does not match — never a guess.
	Model string
	// Target is the path / URL / command string the action operates
	// on.
	Target string
	// Args is the pre-split argv when the boundary already has one
	// (some hook payloads deliver argv rather than a command
	// string). When empty, shell events are parsed from Target.
	Args []string
	// Dialect is the shell dialect hint for Target/Args (approved
	// deviation 1). Empty means DialectPosix.
	Dialect Dialect
	// Cwd is the working directory the action runs in, when the
	// boundary knows it (hook payloads carry it). Relative path
	// targets resolve against Cwd, falling back to ProjectRoot.
	// Additive field discovered during G1 implementation: without
	// it, relative targets ("rm -rf ./src", "../other") cannot be
	// resolved at all.
	Cwd string
	// ProjectRoot is the resolved project root (internal/git
	// resolution, done by the caller — never here).
	ProjectRoot string
	// SessionID identifies the agent session for reporting and
	// session-scoped state lookups.
	SessionID string
	// Caps are the channel capabilities resolved at the boundary.
	Caps Capabilities
	// Taint is the session's current taint snapshot (owned by the
	// guard layer; G1 rules do not yet consume it).
	Taint TaintState
	// Raw is a bounded (≤4 KiB by convention at the boundary) slice
	// of the raw payload for matcher access. The proxy seam (G9) is
	// the documented exception to the bound: KindAPIRequest events
	// built for the §8.4 injection heuristics carry one full
	// tool-result/web-content segment (already segment-capped at the
	// boundary) because injected instructions can sit anywhere in the
	// segment. Raw is in-memory only — it never persists.
	Raw []byte
	// Secrets are typed secret-detector findings stamped by the
	// boundary that built the event (the proxy egress seam, §8.2 —
	// the same compute-at-the-owner pattern as Taint). The R-172
	// api_request row consumes them; this package never runs
	// detectors over message content itself.
	Secrets []SecretFinding
	// PIIFindings are typed PII-detector findings stamped by the
	// boundary that built the event (internal/scrub's typed PII
	// detectors, injected — the same compute-at-the-owner pattern as
	// Secrets/Taint) — the prompt-submit intervention feature
	// (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
	// §4.2/§4.4). The R-190 row (KindUserPrompt) consumes them; this
	// package never runs detectors or reads prompt content itself.
	PIIFindings []PIIFinding
	// PromptTruncated reports whether the boundary's PII detection pass
	// over this event's prompt text was skipped because the body
	// exceeded scrub.MaxRawInputBytes (scrub.DetectPromptFindings'
	// truncated return, FIX-2 round-2 re-review). Only meaningful on a
	// KindUserPrompt event; the guard layer's EvaluatePrompt reads it to
	// degrade an oversize, unscanned prompt to warn (or block under
	// mode=block) instead of silently treating "not scanned" the same
	// as "scanned clean" — an empty PIIFindings slice is otherwise
	// indistinguishable between the two.
	PromptTruncated bool
	// PromptFieldMissing reports whether the boundary's dialect
	// extractor could not find ANY of its known prompt-field names in
	// the raw hook payload at all (FIX-2, phase-2 review) — schema
	// drift (a vendor renamed or removed the field this repo's
	// extractor expects), NOT a developer who genuinely submitted an
	// empty prompt. Only meaningful on a KindUserPrompt event; like
	// PromptTruncated, EvaluatePrompt degrades this to warn (or block
	// under mode=block) rather than silently treating "the extractor
	// found nothing to scan because the field doesn't exist" the same
	// as "scanned clean" — an empty PIIFindings slice can't tell the
	// two apart on its own.
	PromptFieldMissing bool
	// MCPFindings are MCP config-layer security findings stamped by
	// the guard composition layer (the §9.2/§9.3 pin-diff and
	// poisoning results computed in guard/mcpsec — the same
	// compute-at-the-owner pattern as Taint and Secrets). The
	// R-301/302/303/305 rows consume them; this package never reads
	// configs or pin state itself.
	MCPFindings []MCPFinding
	// PostureFindings are client-posture findings stamped by the
	// guard composition layer (the §13.2 native-dialect drift check —
	// the same compute-at-the-owner pattern as MCPFindings). The
	// R-204 row consumes them; this package never reads native
	// client configs itself.
	PostureFindings []PostureFinding
	// SessionCostUSD / DailyCostUSD are the spend-so-far stamps for
	// the §12.1 budget rules and the §4.4 session_cost_usd_gt user
	// matcher, stamped by the guard layer's TTL-cached budget lookup
	// (the compute-at-the-owner pattern; this package never queries
	// cost data). 0 means unknown/unstamped — budget rules treat it
	// as no-match, never as "free". Hook-path events are never
	// stamped (the lookup lives in the daemon).
	// USDUnavailable / TokensUnavailable distinguish a failed or incomplete
	// accounting read from measured zero usage. They are stamped at the proxy
	// admission boundary; a configured hard window cannot admit on unknown spend.
	USDUnavailable    BudgetUnavailableWindows
	TokensUnavailable BudgetUnavailableWindows
	SessionCostUSD    float64
	DailyCostUSD      float64
	// WeeklyCostUSD / MonthlyCostUSD are the rolling-7-day and
	// calendar-month spend-so-far stamps for the B-604 / B-603 budget
	// windows, stamped by the same TTL-cached budget lookup. 0 means
	// unknown/unstamped (treated as no-match, never "free").
	WeeklyCostUSD  float64
	MonthlyCostUSD float64
	// SessionTokens / DailyTokens / WeeklyTokens / MonthlyTokens are the
	// TOKEN-denominated siblings of the four spend stamps above, for the
	// B-621..B-624 rows (org-budget plan §3.3c). Stamped by the SAME
	// TTL-cached guard budget lookup, over the same windows, so a token
	// budget and a dollar budget can never disagree about which turns they
	// are counting. 0 means unknown/unstamped (no-match, never "free").
	SessionTokens int64
	DailyTokens   int64
	WeeklyTokens  int64
	MonthlyTokens int64
	// OrgBaseline is the ORGANIZATION's own measurement of what this
	// caller already spent in each window ON ITS OTHER MACHINES —
	// the cross-machine baseline (bundle BUD-N / P1-9), stamped by the
	// guard from the composed org budget, not from a store read.
	//
	// The budget rows compare `OrgBaseline.<window> + <window> stamp`
	// against the ceiling, because one developer with a laptop and a
	// devbox burns ONE org budget from two nodes and a node that counted
	// only its own rows would enforce a cap the org already considers
	// breached.
	//
	// It is zero unless the org supplied a baseline that was FRESH and
	// measured with this machine excluded (internal/orgbudget decides;
	// see orgcontract.BudgetPolicyCap.SpentExcludesMachine). A stale,
	// absent or uncomposable baseline leaves it zero and the node
	// enforces on local spend alone — never a refusal to run.
	OrgBaseline BudgetWindowAmounts
	// OrgBaselineFlagOnly says the baseline above may raise a WARNING and may
	// not deny (orgcontract.BudgetBaselineAppliedFlagOnly). The org's measure
	// counted rows it could not attribute to any machine, so it may overlap
	// this node's own spend, and a request refused — or a process stopped — on
	// a total that may have counted the same turns twice is not a ceiling, it
	// is a coin toss.
	//
	// The budget rows therefore drop the baseline from any comparison that can
	// DENY (the node-wide rows under [guard.budget].hard, and a subject cap the
	// org authored hard) and keep it for the flag comparisons. The
	// process-control pass evaluates only protected deny rows, so it inherits
	// the same local-only arithmetic without a second rule.
	OrgBaselineFlagOnly bool
	// ToolSubjectID / ModelSubjectID are Tool / Model folded onto the SAME
	// identity the organization's subject caps were composed onto — the
	// price-table alias ladder for a model (so `claude-sonnet-5` and
	// `claude-sonnet-5-20260501` are one subject), the plain normalisation for
	// a tool. The guard stamps them beside ToolUsage / ModelUsage from one
	// resolver, so the cap, the accounting key and the event all spell the
	// subject the same way.
	//
	// Empty falls back to normalizing Tool / Model here, which is exactly the
	// pre-resolver behaviour: an unstamped event (a hook path) or a node with
	// no price table still matches on the plain spelling.
	ToolSubjectID  string
	ModelSubjectID string
	// ToolUsage / ModelUsage are THIS MACHINE's own spend in each window
	// narrowed to the event's Tool / Model, stamped by the same TTL-cached
	// guard budget lookup that fills the node-wide stamps, from the same
	// query over the same windows. They feed the subject budget rows
	// (B-626..B-629) and nothing else. Zero means unknown/unstamped or
	// simply no usage — the rows treat it as no-match either way, exactly
	// like every other budget stamp.
	ToolUsage  BudgetWindowAmounts
	ModelUsage BudgetWindowAmounts
	// Window5hUtil / Window7dUtil are the provider's own 5h and weekly
	// usage-window utilization (0..1), stamped from the latest
	// limit_snapshots row for the B-610..B-613 limit rules. 0 means
	// unknown/unstamped (no window observed yet) — rules treat it as
	// no-match.
	Window5hUtil float64
	Window7dUtil float64
	// RepeatCount is the consecutive-identical-action run length
	// INCLUDING this event, stamped by the guard layer's repeat
	// tracker on the watcher ingest path (the A-610 stuck-loop
	// signal and the §4.4 repeat_count_gt user matcher). 0 means
	// untracked (hook path, proxy path).
	RepeatCount int
	// Now is the evaluation timestamp, injected for determinism.
	Now time.Time
}

// SecretFinding is one typed secret detection stamped onto an Event
// by the boundary (internal/scrub's typed detectors, injected — this
// package imports zero observer packages). It deliberately carries NO
// raw value: rules only ever see what KIND of secret appeared.
//
// SpanLen/Hash (round-2 review B1, added after the original "gains
// nothing" phase-1 comment on this type): the prompt-submit
// intervention feature's reconsider-once fingerprint (§5.2) needs a
// one-way digest of the matched span to distinguish "the developer
// resent the identical secret" from "the developer edited it" — the
// SAME ingredient PIIFinding.Hash already supplies. Phase 1 shipped
// without these fields and compensated by stricting every ask-once/
// redact secret finding to block-every-time; that stricten branch is
// gone now that the boundary can populate them. Every OTHER consumer
// of SecretFinding (R-172's shell-arg/api-request matchers,
// SummarizeSecretFindings) ignores both fields and is unaffected.
type SecretFinding struct {
	// Type is the stable detector name ("github_pat", "entropy", ...).
	Type string
	// Certain reports a pattern-certain detection; the entropy
	// heuristic reports false (spec §8.2 gates masking on certainty).
	Certain bool
	// SpanLen is the length in bytes of the matched span — reporting
	// only (mirrors PIIFinding.SpanLen); never enough on its own to
	// reconstruct the value.
	SpanLen int
	// Hash is sha256 hex of the NORMALIZED matched span (separators
	// stripped, ASCII-lowered — see the reconsider-once fingerprint
	// spec §5.2), computed by the boundary from the in-memory match.
	// Empty means the boundary could not (or chose not to) compute one
	// — EvaluatePrompt treats an empty Hash as "cannot participate in
	// the identical-resend refinement" and degrades that ONE finding
	// to block, exactly as an unhashable finding always has; a
	// populated Hash participates in the fingerprint like any
	// PIIFinding.
	Hash string
}

// PIIFinding is one deterministic PII-detector finding stamped onto
// an Event by the boundary (internal/scrub's typed PII detectors,
// injected — this package imports zero observer packages), for the
// prompt-submit intervention feature (docs/plans/
// prompt-submit-intervention-exploration-2026-09-07.md §4.2/§4.4/§5.2).
// Like SecretFinding it carries NO raw value; unlike SecretFinding it
// also carries a per-span Hash so the guard layer's reconsider-once
// state machine can distinguish "the developer resent the identical
// finding" from "the developer edited the value" without a whole-
// prompt hash (which would break that distinction — a developer who
// adds a sentence around an unchanged secret should still count as an
// identical resend, §5.2).
type PIIFinding struct {
	// Type is the stable detector name ("credit_card", "us_ssn", ...).
	Type string
	// Class is "pii" for every row today; carried for symmetry with
	// internal/scrub's TypedFinding.Class and to keep the field
	// meaningful if a future detector class is ever added here.
	Class string
	// SpanLen is the length in bytes of the matched span — reporting
	// only (guard_events reason renders "credit_card×1 (16 chars)");
	// never enough on its own to reconstruct the value.
	SpanLen int
	// Hash is sha256 hex of the NORMALIZED matched span (separators
	// stripped, ASCII-lowered — see the reconsider-once fingerprint
	// spec §5.2), computed by the boundary from the in-memory match.
	// It is a one-way digest of the value, never the value itself,
	// and this package never computes or interprets it — it is pure
	// pass-through cargo for whatever layer builds the reconsider-once
	// fingerprint.
	//
	// UPDATE (round-2 review B1): the contract's original §4.4/§10 item
	// 9 said "policy.SecretFinding gains nothing", which forced every
	// secret-shaped ask-once/redact prompt finding to degrade to
	// block-every-time (no per-span hash to fingerprint on). That
	// asymmetry broke the operator's core requirement — ask-once for
	// API tokens typed into a prompt — so SecretFinding now carries the
	// same SpanLen/Hash shape as this type; see its doc comment.
	Hash string
}
