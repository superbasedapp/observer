package routing

import "time"

// Tier is an equivalence class of models (§R7). Tiers are quality classes,
// not provider families: "opus-class" includes non-Anthropic flagship models.
type Tier string

// The shipped tier vocabulary (§R4, §R7.1). TierUnclassified is the catch-all
// for models the seed table cannot place — never auto-routed to, only ever
// routed from by explicit rule.
const (
	TierOpusClass    Tier = "opus-class"
	TierSonnetClass  Tier = "sonnet-class"
	TierHaikuClass   Tier = "haiku-class"
	TierFree         Tier = "free"
	TierLocal        Tier = "local"
	TierUnclassified Tier = "unclassified"
)

// tierRanks orders tiers by quality class for downshift comparisons.
// Higher rank = more capable class. Free and local share the bottom paid
// rank: their quality varies too much to order against each other, and
// neither is a default downshift destination in P0. Unclassified ranks 0 —
// comparisons against it are meaningless and callers must treat it as
// non-routable.
var tierRanks = map[Tier]int{
	TierOpusClass:    40,
	TierSonnetClass:  30,
	TierHaikuClass:   20,
	TierFree:         10,
	TierLocal:        10,
	TierUnclassified: 0,
}

// Rank returns the tier's quality-class ordering value (higher = more
// capable). Unknown tiers rank 0, same as TierUnclassified.
func (t Tier) Rank() int { return tierRanks[t] }

// Known reports whether t is one of the shipped tier vocabulary values.
func (t Tier) Known() bool {
	_, ok := tierRanks[t]
	return ok
}

// DownshiftTargetable reports whether the tier may be selected as a
// route-to destination. TierUnclassified is never a target (§R7.1); an
// unknown tier string is likewise refused.
func (t Tier) DownshiftTargetable() bool {
	return t.Known() && t != TierUnclassified
}

// AllTiers enumerates the shipped tier vocabulary in descending rank order.
// Used by lint, the dashboard, and table-driven tests.
func AllTiers() []Tier {
	return []Tier{
		TierOpusClass, TierSonnetClass, TierHaikuClass,
		TierFree, TierLocal, TierUnclassified,
	}
}

// TurnKind is the classified function of a request (§R8.2).
type TurnKind string

// The v1 turn-kind taxonomy (§R8.2). TurnUnknown means the classifier
// declined to guess (missing/lagged signals) — an unknown turn is never
// downshifted (§R8.3, §R9.2).
const (
	TurnPlan         TurnKind = "plan"
	TurnReadOnly     TurnKind = "read_only"
	TurnEdit         TurnKind = "edit"
	TurnTestRun      TurnKind = "test_run"
	TurnHousekeeping TurnKind = "housekeeping"
	TurnSubagent     TurnKind = "subagent"
	TurnLongContext  TurnKind = "long_context"
	TurnUnknown      TurnKind = "unknown"
)

// AllTurnKinds enumerates the v1 taxonomy. Used by lint and tests.
func AllTurnKinds() []TurnKind {
	return []TurnKind{
		TurnPlan, TurnReadOnly, TurnEdit, TurnTestRun,
		TurnHousekeeping, TurnSubagent, TurnLongContext, TurnUnknown,
	}
}

// Soft reports whether the turn-kind is a "soft" kind — one whose floors
// budget/rate-limit modifiers may degrade and that downshift templates
// target by default (§R14). Plan and edit floors hold; long-context and
// unknown are never soft.
func (k TurnKind) Soft() bool {
	switch k {
	case TurnReadOnly, TurnHousekeeping, TurnSubagent, TurnTestRun:
		return true
	default:
		return false
	}
}

// Mode is the per-policy activation state (§R4).
type Mode string

// Modes. P0 ships nothing beyond advisory surfaces, so live traffic is
// always effectively ModeOff; the vocabulary exists for decision rows and
// status surfaces.
const (
	ModeOff     Mode = "off"
	ModeAdvise  Mode = "advise"
	ModeEnforce Mode = "enforce"
)

// Channel is how a decision takes effect (§R4): A = agent config,
// B = proxy in-transit rewrite.
type Channel string

// Channels.
const (
	ChannelAgentConfig Channel = "A"
	ChannelProxy       Channel = "B"
)

// ReasonCode is a closed-enum decision annotation (§R9.1) so the dashboard
// can aggregate and users can filter. New codes are added here, never
// free-text on a decision row.
type ReasonCode string

// Reason codes. The set covers the P0 surfaces (simulate, recommendations)
// plus the spec-named P1 codes so the enum is stable across phases.
const (
	// ReasonOverpoweredRead: a read-only turn ran on a tier above the
	// policy's floor for exploration work.
	ReasonOverpoweredRead ReasonCode = "overpowered_read"
	// ReasonOverpoweredHousekeeping: commits/summaries/titles on a
	// flagship tier (Aider's weak-model class).
	ReasonOverpoweredHousekeeping ReasonCode = "overpowered_housekeeping"
	// ReasonOverpoweredSubagent: a sidechain turn on a tier the
	// sub-agent's observed profile doesn't need.
	ReasonOverpoweredSubagent ReasonCode = "overpowered_subagent"
	// ReasonOverpoweredTestRun: build/test/lint command turns on a
	// flagship tier.
	ReasonOverpoweredTestRun ReasonCode = "overpowered_test_run"
	// ReasonPhasePin: a phase rule pinned the tier (opusplan-style).
	ReasonPhasePin ReasonCode = "phase_pin"
	// ReasonCacheHold: switching would forfeit a warm prompt cache worth
	// more than the switch saves (§R13) — the decision is "stay".
	ReasonCacheHold ReasonCode = "cache_hold"
	// ReasonStickinessHold: a proposed switch landed inside the policy's
	// min-turns-between-switches coherence floor (§R13) — held.
	ReasonStickinessHold ReasonCode = "stickiness_hold"
	// ReasonBudgetBand50/80/95: the budget modifier demoted the max
	// allowed tier at a burn band (§R14). P1.
	ReasonBudgetBand50 ReasonCode = "budget_band_50"
	ReasonBudgetBand80 ReasonCode = "budget_band_80"
	ReasonBudgetBand95 ReasonCode = "budget_band_95"
	// ReasonAvailabilityFallback: health-degraded target, fallback chain
	// engaged (§R12). P1.
	ReasonAvailabilityFallback ReasonCode = "availability_fallback"
	// ReasonRateLimitWindow: subscription-window headroom preservation
	// demoted a soft turn-kind (§R15). P1.
	ReasonRateLimitWindow ReasonCode = "rate_limit_window"
	// ReasonEntitlementHold: subscription traffic outside the plan's
	// native model set — advise-only (§R11.3).
	ReasonEntitlementHold ReasonCode = "entitlement_hold"
	// ReasonEscalation: a downshifted turn failed; the session escalated
	// back to the pre-downshift tier (§R7.4).
	ReasonEscalation ReasonCode = "escalation"
	// ReasonFailOpen: any engine error, missing snapshot, or timeout —
	// the original model passes through untouched (§R9.2).
	ReasonFailOpen ReasonCode = "fail_open"
	// ReasonUnknownTurnKind: the classifier degraded to unknown, so no
	// routing applies (§R8.3).
	ReasonUnknownTurnKind ReasonCode = "unknown_turn_kind"
	// ReasonUnclassifiedModel: the original model isn't in the tier
	// table; the engine refuses to reason about it (§R7.1).
	ReasonUnclassifiedModel ReasonCode = "unclassified_model"
	// ReasonNoCandidate: a rule matched but no same-shape candidate
	// exists in the target tier (§R11.4 same-shape constraint).
	ReasonNoCandidate ReasonCode = "no_candidate"
	// ReasonNoRoute: an explicit exemption rule matched (§R6.3 no_route).
	ReasonNoRoute ReasonCode = "no_route"
	// ReasonInsufficientEvidence: the move lacks per-project calibration
	// parity evidence — surfaced as a quality-risk flag (§R7.2, §R18.1).
	ReasonInsufficientEvidence ReasonCode = "insufficient_evidence"
	// ReasonCustomRule: a user-defined [[routing.rules]] row fired
	// without declaring its own reason code (§R6.3).
	ReasonCustomRule ReasonCode = "custom_rule"
	// ReasonPrivacyHold: a privacy rule (§R16) constrained the decision;
	// the row records the path-class hit hash, never the path.
	ReasonPrivacyHold ReasonCode = "privacy_hold"
	// ReasonQualityFloorHold: the quality_floor basis denied the
	// proposed target (§R6.2) — the turn stays on its model.
	ReasonQualityFloorHold ReasonCode = "quality_floor_hold"
	// ReasonCapabilityHold: the capability basis denied the switch
	// (provider shape, context window, tool support) — §R11.2 filters
	// illegal moves before ranking, never as upstream 4xx.
	ReasonCapabilityHold ReasonCode = "capability_hold"
	// ReasonEffortDownshift: the decision lowers effort/thinking/speed
	// instead of switching model (§R6.5) — zero cache loss.
	ReasonEffortDownshift ReasonCode = "effort_downshift"
	// ReasonBudgetExhausted: a budget scope hit 100% and its configured
	// exhaustion behavior fired (§R14).
	ReasonBudgetExhausted ReasonCode = "budget_exhausted"
	// ReasonBudgetHardStop: the exhausted scope's configured behavior is
	// hard_stop (§R14). Recorded alongside ReasonBudgetExhausted so decision
	// rows distinguish hard_stop from degrade_all (gap register G1-HARDSTOP);
	// the engine itself still never breaks a turn (G7) — the boundary channel
	// decides what a stop means (see Decision.HardStop).
	ReasonBudgetHardStop ReasonCode = "budget_hard_stop"
	// ReasonCalibrationDemoted: the calibration job graded this rule's
	// downshift as regressing (§R18.3 auto_demote) — the decision is
	// logged but never applied until evidence clears.
	ReasonCalibrationDemoted ReasonCode = "calibration_demoted"
)

// KnownReasonCodes enumerates the closed enum, for lint and dashboards.
func KnownReasonCodes() []ReasonCode {
	return []ReasonCode{
		ReasonOverpoweredRead, ReasonOverpoweredHousekeeping,
		ReasonOverpoweredSubagent, ReasonOverpoweredTestRun, ReasonPhasePin,
		ReasonCacheHold, ReasonStickinessHold, ReasonBudgetBand50,
		ReasonBudgetBand80, ReasonBudgetBand95, ReasonAvailabilityFallback,
		ReasonRateLimitWindow, ReasonEntitlementHold, ReasonEscalation,
		ReasonFailOpen, ReasonUnknownTurnKind, ReasonUnclassifiedModel,
		ReasonNoCandidate, ReasonNoRoute, ReasonInsufficientEvidence,
		ReasonCustomRule, ReasonPrivacyHold, ReasonQualityFloorHold,
		ReasonCapabilityHold, ReasonEffortDownshift, ReasonBudgetExhausted,
		ReasonCalibrationDemoted,
	}
}

// Entitlement classes, resolved at the boundary (§R11.3): API-key
// traffic accepts full enforcement; subscription traffic (OAuth / plan
// JWTs) only within the plan's native model set. Empty = unknown —
// treated as the more restrictive class.
const (
	EntitlementAPIKey       = "api_key"
	EntitlementSubscription = "subscription"
)

// Effort levels (§R6.5) — the set_effort action vocabulary. The
// boundary translates them to each provider's native field (Anthropic
// thinking budget / speed; OpenAI reasoning_effort).
const (
	EffortMinimal = "minimal"
	EffortLow     = "low"
	EffortMedium  = "medium"
	EffortHigh    = "high"
)

// ProviderShape is the wire-protocol family a model is served over,
// resolved at the boundary (§24.3). Enforce-mode candidate sets are
// same-shape only until cross-provider translation ships (§R11.4); P0
// simulate honors the same constraint so its counterfactuals stay honest.
type ProviderShape string

// Provider shapes. ShapeUnknown candidates are never selected.
const (
	ShapeAnthropic ProviderShape = "anthropic"
	ShapeOpenAI    ProviderShape = "openai"
	ShapeGoogle    ProviderShape = "google"
	ShapeUnknown   ProviderShape = ""
)

// TurnShape is the pure-logic mirror of the proxy's per-request view
// (§R8.1). It carries no body content — counts, hashes, and flags only.
// Boundary code (proxy seam in P1, replay loaders in P0) builds it; this
// package never parses a request.
type TurnShape struct {
	// Model is the requested model id, verbatim.
	Model string
	// MessageCount is the request's message count.
	MessageCount int
	// ToolUseCount is the number of tool definitions on the request.
	ToolUseCount int
	// SystemPromptHash identifies the system prompt without content.
	SystemPromptHash string
	// Stream is the request's stream flag.
	Stream bool
	// Speed mirrors the request's fast-tier field ("fast" when the
	// premium low-latency tier was requested).
	Speed string
	// PromptTokens is the observed (replay) or estimated (live) prompt
	// window — input + cache_read + cache_creation — used for prompt-size
	// banding and the long_context turn-kind.
	PromptTokens int64
}

// CommandClass categorizes a run_command action, resolved at the boundary
// from the command text so classifier rules never see content (§24.3).
type CommandClass string

// Command classes. CommandNone is the zero value for non-command actions.
const (
	CommandNone  CommandClass = ""
	CommandTest  CommandClass = "test"
	CommandBuild CommandClass = "build"
	CommandLint  CommandClass = "lint"
	CommandVCS   CommandClass = "vcs"
	CommandOther CommandClass = "other"
)

// ActionSignal is one normalized recent action, as the classifier sees it
// (§R8.1): the spec §5 action_type vocabulary plus boundary-resolved flags.
// No targets, no paths, no command text.
type ActionSignal struct {
	// Type is the normalized action_type (models.Action* vocabulary).
	Type string
	// CommandClass is set for run_command actions only.
	CommandClass CommandClass
	// Success mirrors the action's success flag.
	Success bool
	// IsSidechain marks actions emitted inside a sub-agent runtime.
	IsSidechain bool
}

// SessionState is the session-coherence view the engine consumes alongside
// the request shape (§R8.1, §R9.3).
type SessionState struct {
	// RecentActions is the last-N normalized action window, oldest
	// first. Empty when no actions are attributable to this session yet.
	RecentActions []ActionSignal
	// ActionsLagged is set by the boundary when the action stream is
	// known to trail the request (hooks near-real-time, watcher tails
	// seconds behind) badly enough that RecentActions may be missing the
	// last 1–2 turns. The classifier degrades to TurnUnknown rather than
	// guessing (§R8.3).
	ActionsLagged bool
	// ClientPhase is the client-declared phase where visible ("plan"
	// from plan-mode markers / opusplan state). Empty otherwise.
	ClientPhase string
	// IsSidechain marks the turn itself as sub-agent traffic.
	IsSidechain bool
	// TurnsSinceSwitch counts turns since the session last changed
	// model. Coherence constraints (§R13) read it; 0 means the switch
	// just happened (or the session just started).
	TurnsSinceSwitch int
	// PriorCacheReadTokens is the most recent turn's cache_read volume
	// on the current model — the warm-prefix size the cache-forfeit
	// estimate prices (§R13).
	PriorCacheReadTokens int64
	// SessionAgeTurns is the session's total turn count so far —
	// the session_age_turns rule matcher reads it (§R6.3).
	SessionAgeTurns int
	// EscalatedKinds lists turn-kinds under an active §R7.4
	// escalation: a downshifted turn of that kind failed, so the
	// session's next turns of the kind run at their pre-downshift
	// tier (no routing) until the boundary's cooldown lapses. The
	// boundary (live adapter) detects failures and maintains the
	// cooldown; the engine just honors the flag — deterministically.
	EscalatedKinds []TurnKind
}

// DecisionInput is everything the engine evaluates for one request:
// shape + session state + boundary-resolved flags. Deterministic given
// equal inputs (§R9.3). The identity-shaped fields (Project, ScopeKeys,
// Entitlement, PathClassHits) are resolved at the boundary into plain
// matchable strings — the engine never sees a tool name, a path, or an
// auth header (§24.3).
type DecisionInput struct {
	Shape   TurnShape
	Session SessionState
	// ObservedUsage carries the turn's realized token bundle on replay
	// paths (simulate), enabling exact counterfactual dollar math. Nil
	// on the live hot path — the engine then skips dollar estimates
	// rather than inventing them.
	ObservedUsage *PromptUsage
	// Project is the boundary-resolved project name; rule when.project
	// and privacy rules match against it. Empty = unknown.
	Project string
	// ScopeKeys are the budget-scope keys this turn belongs to
	// ("global", "project:<name>", "tool:<name>", "tier:<tier>") —
	// resolved at the boundary so the engine matches strings, never
	// source identity (§R14, §24.3).
	ScopeKeys []string
	// PathClassHits are the [routing.path_classes] names whose globs
	// matched the turn's recent action targets — resolved at the
	// boundary; no path content enters the engine (§R16).
	PathClassHits []string
	// PathClassHitsHash identifies the matched targets for decision
	// rows without recording any path (§R16: hash only).
	PathClassHitsHash string
	// Entitlement is the boundary-resolved entitlement class (§R11.3):
	// EntitlementAPIKey, EntitlementSubscription, or "" (unknown —
	// treated as subscription-restrictive).
	Entitlement string
}

// ModelCandidate is one routable model with its boundary-resolved
// attributes. Bases evaluate candidates; the engine never invents one.
type ModelCandidate struct {
	// Model is the candidate model id.
	Model string
	// Tier is the candidate's tier-table placement.
	Tier Tier
	// Shape is the candidate's provider wire shape; selection is
	// same-shape only (§R11.4).
	Shape ProviderShape
}

// PromptUsage is the token shape PriceFn prices. A deliberate local mirror
// of the cost engine's bundle so this package stays import-free of the
// intelligence tree; the boundary adapts cost.TokenBundle into it.
type PromptUsage struct {
	Input           int64
	Output          int64
	CacheRead       int64
	CacheCreation   int64
	CacheCreation1h int64
	Reasoning       int64
	// WebSearchRequests counts server-side web_search invocations
	// (flat per-call fee at the boundary's pricing engine).
	WebSearchRequests int64
	// Fast marks the turn as served on the provider's premium
	// low-latency tier (priced at the model's fast multiplier).
	Fast bool
}

// PriceFn prices a usage bundle against a model. ok=false means the model
// has no pricing entry — the engine then refuses dollar claims rather than
// inventing them. Backed by cost.Engine.ComputeBreakdown at the boundary.
type PriceFn func(model string, u PromptUsage) (usd float64, ok bool)

// Snapshot is the immutable, periodically refreshed view of signals the
// decision engine reads (§R9.2). A store-side refresher builds it and swaps
// it in via atomic.Pointer (the pricing-table hot-reload pattern); the
// engine itself never performs I/O. P0 populates it from replay loaders.
type Snapshot struct {
	// GeneratedAt stamps when the snapshot was assembled.
	GeneratedAt time.Time
	// Price is the injected pricing seam. Nil disables dollar math —
	// decisions still resolve, with zero estimates.
	Price PriceFn
	// Tiers is the tier-table snapshot decisions resolve against. Nil
	// fails open (§R9.2): no table, no routing.
	Tiers *TierTable
	// Stale is set by the refresher when the snapshot is older than
	// its staleness horizon — the engine fails open (§R9.2): better an
	// unrouted turn than a decision off dead signals.
	Stale bool
	// Health carries the §R12.3 passive health state per model
	// (boundary-aggregated from the observed http_status stream). A
	// model absent from the map is healthy.
	Health map[string]HealthState
	// LatencyP75Ms is the observed p75 total-latency per model — the
	// latency basis ranks on it. A model absent ranks last among
	// observed candidates (no data, no preference).
	LatencyP75Ms map[string]int64
	// BudgetBurn carries the configured budget scopes with their
	// window-to-date spend, computed store-side from cost_usd rollups
	// (§R14 — authoritative, never estimated).
	BudgetBurn []BudgetBurnState
	// Window is the §R15 learned subscription-window state. Nil when
	// the rate_limit_window feature is off or no cadence is learned.
	Window *WindowState
	// SessionCacheRead maps session id → the most recent observed
	// turn's cache_read volume on that session (warm-prefix size for
	// §R13 forfeit pricing on the live path, where ObservedUsage is
	// nil). Boundary-populated; sessions absent are cache-cold.
	SessionCacheRead map[string]int64
	// Sessions maps session id → its boundary-resolved classifier
	// inputs (§R8.1). A session absent from the map has no recent
	// activity — the classifier degrades to unknown (no routing).
	Sessions map[string]SessionActivity
}

// SessionActivity is the per-session classifier input the refresher
// assembles (§R8.1): the normalized recent-action window plus the
// boundary-resolved identity flags. No targets, no paths, no command
// text — all content resolved away store-side (§24.3).
type SessionActivity struct {
	// RecentActions is the last-N normalized window, oldest first.
	RecentActions []ActionSignal
	// ActionsLagged marks a window known to trail the request stream
	// badly enough to miss the last 1–2 turns (§R8.3): the classifier
	// then degrades to unknown rather than guessing.
	ActionsLagged bool
	// ClientPhase is the latest client-declared phase ("plan").
	ClientPhase string
	// TurnCount is the session's recent turn count (SessionAgeTurns).
	TurnCount int
	// Project is the session's project name (root basename).
	Project string
	// ScopeKeys are the §R14 budget-scope keys this session belongs to.
	ScopeKeys []string
	// PathClassHits are the [routing.path_classes] names whose globs
	// matched recent action targets — matching happens store-side;
	// only the class names (flags) reach the engine (§R16).
	PathClassHits []string
	// PathClassHitsHash identifies the matched targets for decision
	// rows without recording any path (§R16: hash only).
	PathClassHitsHash string
	// LastSidechain reports whether the most recent action was
	// sidechain-flagged — the live approximation of "the in-flight
	// turn is sub-agent traffic" (stated as such; token rows carry no
	// sidechain flag).
	LastSidechain bool
}

// HealthState is the §R12.3 circuit-breaker state per model.
type HealthState string

// Health states. A model absent from Snapshot.Health is HealthHealthy.
const (
	HealthHealthy  HealthState = "healthy"
	HealthDegraded HealthState = "degraded"
	HealthOpen     HealthState = "open"
	HealthHalfOpen HealthState = "half_open"
)

// BudgetBurnState is one budget scope's window-to-date burn (§R14).
// The store-side refresher computes SpentUSD from cost_usd rollups.
type BudgetBurnState struct {
	Scope     string
	LimitUSD  float64
	SpentUSD  float64
	Window    string
	Bands     []float64
	Exhausted string
}

// Burn returns the scope's burn fraction (0 when the limit is unset).
func (b BudgetBurnState) Burn() float64 {
	if b.LimitUSD <= 0 {
		return 0
	}
	return b.SpentUSD / b.LimitUSD
}

// WindowState is the §R15 learned subscription-window pressure view.
// All fields boundary-computed; the engine only reads them.
type WindowState struct {
	// BurnFraction is the estimated fraction of the window's learned
	// capacity consumed so far.
	BurnFraction float64
	// ProjectedExhaustion is true when current cadence projects the
	// cap to be hit before the window resets, beyond the configured
	// headroom.
	ProjectedExhaustion bool
}

// Decision is the router's output for one request (§R9.1): the selected
// model (or "no change"), the closed-enum reasons, and the counterfactual
// dollars. No prompt content, no paths.
type Decision struct {
	// OriginalModel is the model the request carried.
	OriginalModel string
	// SelectedModel is the model the policy selects. Equal to
	// OriginalModel when the decision is "no change".
	SelectedModel string
	// Changed is true when SelectedModel differs from OriginalModel.
	Changed bool
	// TurnKind is the classified function of the request.
	TurnKind TurnKind
	// RuleName names the policy rule that fired (transparency surface);
	// empty when no rule matched.
	RuleName string
	// ReasonCodes are the closed-enum annotations for this decision.
	ReasonCodes []ReasonCode
	// PolicyName and PolicyHash attribute the decision to the exact
	// policy content that made it (§R6.6).
	PolicyName string
	PolicyHash string
	// EstSavingsUSD is the estimated per-turn saving of the selected
	// model vs the original (zero when unchanged or unpriceable).
	EstSavingsUSD float64
	// CacheForfeitUSD prices the warm-cache loss a switch would incur
	// (§R13); informational in P0.
	CacheForfeitUSD float64
	// EstimateVersion versions the savings/forfeit math so calibration
	// can grade estimates against realized outcomes (§R13).
	EstimateVersion string
	// SetEffort, when non-empty, downshifts effort/thinking/speed
	// instead of (or alongside no) model change (§R6.5): minimal |
	// low | medium | high. Zero cache loss — the lowest-risk enforce
	// action.
	SetEffort string
	// AdviseOnly forces the decision to log-without-acting even in
	// enforce mode (entitlement holds §R11.3, budget advise_only
	// exhaustion §R14).
	AdviseOnly bool
	// HardStop is the §R14 hard_stop exhaustion signal, threaded from the
	// budget modifier (G1-HARDSTOP fix — previously set on the modifier but
	// never copied here, so hard_stop and degrade_all were identical). The
	// engine applies the same degrade_all cap and NEVER blocks (G7, fail-open
	// outside enforce mode is unchanged); it is the boundary channel's
	// signal: the proxy channel may refuse the request in enforce mode once
	// its RouterVerdict grows a deny outcome (spec'd in docs/plans/arc1-
	// stream-d-enforcement-notes-2026-09-02.md), the routing-apply channel
	// surfaces it, and the decision row carries ReasonBudgetHardStop.
	HardStop bool
	// FallbackModels is the ordered same-shape §R12.1 fallback chain
	// for this turn — consumed by the proxy's retry layer on
	// 429/5xx/timeout. Empty = no chain configured.
	FallbackModels []string
}
