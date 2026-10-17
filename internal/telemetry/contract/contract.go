// Package contract is the W1 telemetry contract v1 — the only coupling
// between the observer client (this repo, internal/telemetry) and the
// central server (observer_reporter, contract/). Versioned artifact:
// changes require a version bump and a mirrored update in BOTH repos (see
// docs/plans/telemetry-rail-plan-2026-09-13.md §D1, the contract-sync
// protocol).
//
// Client-mirror discipline: contract.go is kept TEXTUALLY IDENTICAL to
// observer_reporter/contract/contract.go except this header, so
// `diff internal/telemetry/contract/contract.go
// ../observer_reporter/contract/contract.go` stays a valid drift check.
// The golden artifacts (golden/contract.json, sample_batch*.json.gz) are
// byte-identical in both repos and pinned by verify-telemetry-contract
// (Makefile) + TestGolden* below.
package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Version is the contract semver. Additions are minor bumps; any change of
// meaning is a new event name (never mutation) plus a major bump here.
const Version = "1.2.0"

// EnvelopeVersion is the value expected in Envelope.EnvelopeVersion.
const EnvelopeVersion = "v1"

// MaxUncompressedBytes bounds one ingest body (plan §D3: 1 MiB uncompressed).
const MaxUncompressedBytes = 1 << 20

// Envelope is one batch push (plan §D3). Idempotency: the server dedupes on
// BatchUUID. Ordering: events carry client UTC timestamps; the server never
// trusts arrival order.
type Envelope struct {
	EnvelopeVersion string  `json:"envelope_version"`
	BatchUUID       string  `json:"batch_uuid"`
	InstallID       string  `json:"install_id"`
	SeqStart        int64   `json:"seq_start"`
	SeqEnd          int64   `json:"seq_end"`
	ClientVersion   string  `json:"client_version"`
	OS              string  `json:"os"`
	Arch            string  `json:"arch"`
	EventCount      int     `json:"event_count"`
	ClientTS        string  `json:"client_ts"`
	Events          []Event `json:"events"`
}

// Event is one telemetry record (plan §D5). Classification and Purpose are
// mandatory and must form a valid pair — the CI gate rejects unclassified
// events (the VS Code lesson, plan §C).
type Event struct {
	Event          string         `json:"event"`
	EventVersion   int            `json:"event_version"`
	SchemaVersion  string         `json:"schema_version"`
	TS             string         `json:"ts"` // client UTC, RFC 3339
	InstallID      string         `json:"install_id"`
	Seq            int64          `json:"seq"`
	SessionSpan    string         `json:"session_span,omitempty"`
	Classification string         `json:"classification"`
	Purpose        string         `json:"purpose"`
	Fields         map[string]any `json:"fields"`
}

// Consent tiers (plan §D2):
//
//	off        — nothing collected, staged, or sent.
//	baseline   — Point-2 per-prompt-cycle (prompt_cycle) plus the content-free
//	             lifecycle / tool / error / token counters. On by default in both
//	             observer builds for new installs.
//	enrichment — opt-in prompts + session history for task identification / quality
//	             inputs, scoped to functionalities. Placeholder tier constant now;
//	             event set defined in the enrichment work. Never on by default.
//	error      — error classes + batch meta only.
//	usage      — legacy alias for baseline during the deprecation window (one
//	             release). EffectiveTier normalizes it to baseline.
//	deep       — baseline + deep diagnostics (own consent receipt).
const (
	TierOff        = "off"
	TierBaseline   = "baseline"
	TierEnrichment = "enrichment"
	TierError      = "error"
	TierUsage      = "usage"
	TierDeep       = "deep"
)

// ValidTiers lists all consent tiers in escalation order.
var ValidTiers = []string{TierOff, TierBaseline, TierEnrichment, TierError, TierUsage, TierDeep}

// ValidTier reports whether s is a known consent tier.
func ValidTier(s string) bool {
	switch s {
	case TierOff, TierBaseline, TierEnrichment, TierError, TierUsage, TierDeep:
		return true
	}
	return false
}

// EffectiveTier normalizes deprecated tier labels to the current canonical
// tier. During the deprecation window the legacy "usage" tier is an alias for
// "baseline", so existing usage-tier installs keep shipping without a client
// upgrade.
func EffectiveTier(s string) string {
	switch s {
	case TierUsage:
		return TierBaseline
	default:
		return s
	}
}

// Event names (plan §D5). Static names, versioned — PostHog discipline.
const (
	EventAppStart     = "app_start"
	EventAppStop      = "app_stop"
	EventSessionEnd   = "session_end"
	EventSessionStart = "session_start"
	EventToolUse      = "tool_use"
	EventError        = "error"
	EventTokenUse     = "token_use"
	EventDayActive    = "day_active"
	EventBatchMeta    = "batch_meta"
	EventDiagCommand  = "diag_command"
	EventPromptCycle  = "prompt_cycle"
)

// ToolName is the closed tool vocabulary (plan §D5). Unknown values must be
// bucketed as ToolOther by the client; the server quarantines them.
var ToolName = map[string]bool{
	"read": true, "edit": true, "write": true, "glob": true, "grep": true,
	"shell": true, "apply_patch": true, "browser_click": true,
	"browser_navigate": true, "terminal_write": true, "planner": true,
	"web_search": true, "read_url": true, "todo_write": true,
	"ask_user": true, "other": true,
}

// ErrorClass is the closed error-class vocabulary.
var ErrorClass = map[string]bool{
	"tool_timeout": true, "tool_failed": true, "hook_failed": true,
	"proxy_5xx": true, "proxy_4xx": true, "adapter_parse": true,
	"db_locked": true, "scrub_reject": true, "consent_missing": true,
	"network_unreachable": true, "other": true,
}

// ErrorSurface is the closed surface vocabulary.
var ErrorSurface = map[string]bool{
	"tool": true, "hook": true, "proxy": true, "adapter": true,
	"db": true, "watcher": true, "batcher": true,
}

// ModelTier is the closed model-tier vocabulary.
var ModelTier = map[string]bool{
	"frontier": true, "standard": true, "fast": true, "local": true,
}

// Model is the closed model-identity vocabulary (baseline prompt_cycle).
// Unknown model strings must be bucketed as "other" by the client; the server
// quarantines anything else. This is a model identifier, NOT prompt text.
var Model = map[string]bool{
	"anthropic": true, "openai": true, "google": true,
	"cursor": true, "copilot": true, "codex": true,
	"antigravity": true, "cline": true, "other": true,
}

// Provider is the closed model-provider vocabulary (baseline prompt_cycle).
// Provider is the API provider the turn was sent to, distinct from the client /
// adapter that initiated it.
var Provider = map[string]bool{
	"anthropic": true, "openai": true, "google": true,
	"cursor": true, "copilot": true, "codex": true,
	"antigravity": true, "cline": true, "other": true,
}

// Segment is the closed per-prompt-cycle segment vocabulary (baseline
// prompt_cycle). It segregates user-authored prompt text from system nudges and
// tool-call segments. "other" is the unclassified fallback so the classifier
// never has to omit a label; it improves over time locally and only the tag is
// ever transmitted.
var Segment = map[string]bool{
	"user_prompt":  true,
	"system_nudge": true,
	"tool_call":    true,
	"other":        true,
}

// Role is the closed role vocabulary.
var Role = map[string]bool{"user": true, "assistant": true, "tool": true}

// Adapter is the closed adapter vocabulary (observer repo registered set).
var Adapter = map[string]bool{
	"claudecode": true, "codex": true, "cursor": true, "cline": true,
	"copilot": true, "copilot-cli": true, "gemini": true,
	"antigravity": true, "hermes": true, "other": true,
}

// Classification / purpose values (plan §C — VS Code-shaped, machine-checkable).
const (
	ClassSystemMeta    = "SystemMetaData"
	ClassCallstack     = "CallstackOrException"
	ClassPseudonymized = "EndUserPseudonymizedInformation"

	PurposePerfHealth = "PerformanceAndHealth"
	PurposeFeature    = "FeatureInsight"
	PurposeBusiness   = "BusinessInsight"
)

// classificationPairs is the valid classification × purpose matrix per event.
var classificationPairs = map[string][2]string{
	EventAppStart:     {ClassSystemMeta, PurposePerfHealth},
	EventAppStop:      {ClassSystemMeta, PurposePerfHealth},
	EventSessionStart: {ClassSystemMeta, PurposeFeature},
	EventSessionEnd:   {ClassSystemMeta, PurposeFeature},
	EventToolUse:      {ClassSystemMeta, PurposeFeature},
	EventError:        {ClassCallstack, PurposePerfHealth},
	EventTokenUse:     {ClassSystemMeta, PurposeBusiness},
	EventDayActive:    {ClassSystemMeta, PurposeFeature},
	EventBatchMeta:    {ClassSystemMeta, PurposePerfHealth},
	EventDiagCommand:  {ClassPseudonymized, PurposeFeature},
	EventPromptCycle:  {ClassSystemMeta, PurposeBusiness},
}

// baselineEventSet is the canonical set of events the baseline tier admits.
// It is the source of truth for TierBaseline and for the cross-repo drift gate
// (verify-telemetry-contract). Deep allows baseline events plus deep-only events;
// enrichment allows baseline + deep + enrichment events (placeholder until the
// enrichment work defines its event set).
var baselineEventSet = map[string]bool{
	EventAppStart:     true,
	EventAppStop:      true,
	EventSessionStart: true,
	EventSessionEnd:   true,
	EventToolUse:      true,
	EventError:        true,
	EventTokenUse:     true,
	EventDayActive:    true,
	EventBatchMeta:    true,
	EventPromptCycle:  true,
}

// tierAllows maps each tier to the events it may emit (plan §D2).
var tierAllows = map[string]map[string]bool{
	TierOff:        {},
	TierBaseline:   baselineEventSet,
	TierEnrichment: baselineEventSet, // placeholder until enrichment events are defined
	TierError:      {EventError: true, EventBatchMeta: true},
	TierUsage:      baselineEventSet, // legacy "usage" is now an alias for baseline
	TierDeep:       nil,              // nil = baseline + deep-only events
}

// deepOnly is the set of events only the deep tier may emit.
var deepOnly = map[string]bool{EventDiagCommand: true}

// MaxArgvLen caps diag_command.argv_trunc (plan §D5: ≤120 chars, scrubbed).
const MaxArgvLen = 120

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	installRe = regexp.MustCompile(`^inst-[0-9a-f]{12}$`)
	tsRe      = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)
	// identRe bounds every free-form string the contract admits (versions,
	// os/arch, correlation spans): an identifier, never prose — no spaces, no
	// punctuation beyond . _ + -, at most 64 bytes. Contract 1.2.0.
	identRe = regexp.MustCompile(`^[A-Za-z0-9._+-]{1,64}$`)
)

// eventFields is the closed field-name allow-list per event (contract 1.2.0).
// Any other key in an event's fields is refused, so no event can carry prompt,
// output or other free text under an unlisted name. Mirrored in the golden
// contract.json ("fields") and pinned by TestEventFieldsMatchGolden.
var eventFields = map[string][]string{
	EventAppStart:     {"arch", "os", "version"},
	EventAppStop:      {"arch", "os", "version"},
	EventSessionStart: {"adapter"},
	EventSessionEnd:   {"adapter", "duration_ms", "outcome"},
	EventToolUse:      {"count", "tool_name"},
	EventError:        {"error_class", "surface"},
	EventTokenUse:     {"cache_read", "model_tier", "role", "tokens_in", "tokens_out"},
	EventDayActive:    {},
	EventBatchMeta:    {"dropped_count", "retry_count"},
	EventDiagCommand:  {"argv_trunc", "exit", "tool_name"},
	EventPromptCycle: {
		"cache_percentage", "end_to_end_duration_ms", "input_size", "model",
		"output_size", "provider", "segment", "session_span", "turn_id",
	},
}

// EventFields returns the allowed field names for event (sorted), or nil for
// an unknown event.
func EventFields(event string) []string {
	f, ok := eventFields[event]
	if !ok {
		return nil
	}
	return append(make([]string, 0, len(f)), f...)
}

// validIdent reports whether s is empty-allowed-or-identifier per identRe.
func validIdent(s string, allowEmpty bool) bool {
	if s == "" {
		return allowEmpty
	}
	return identRe.MatchString(s)
}

// Validation errors — closed vocabulary (plan §D3 error taxonomy).
var (
	ErrBadSchema      = errors.New("bad_schema")
	ErrUnknownVersion = errors.New("unknown_version")
	ErrConsentMissing = errors.New("consent_missing")
	ErrRateLimited    = errors.New("rate_limited")
	ErrInstallRevoked = errors.New("install_revoked")
)

// ValidateEnvelope structurally validates the envelope and every event
// against the v1 schema. It returns one of the Err* above wrapped with
// context, or nil when the batch is admissible.
func ValidateEnvelope(e *Envelope) error {
	if e.EnvelopeVersion != EnvelopeVersion {
		return fmt.Errorf("%w: envelope_version %q", ErrUnknownVersion, e.EnvelopeVersion)
	}
	if !uuidRe.MatchString(e.BatchUUID) {
		return fmt.Errorf("%w: batch_uuid not a uuid", ErrBadSchema)
	}
	if !installRe.MatchString(e.InstallID) {
		return fmt.Errorf("%w: install_id", ErrBadSchema)
	}
	if e.EventCount != len(e.Events) {
		return fmt.Errorf("%w: event_count %d != len(events) %d", ErrBadSchema, e.EventCount, len(e.Events))
	}
	if len(e.Events) == 0 {
		return fmt.Errorf("%w: empty batch", ErrBadSchema)
	}
	if e.SeqEnd < e.SeqStart {
		return fmt.Errorf("%w: seq_end < seq_start", ErrBadSchema)
	}
	if !tsRe.MatchString(e.ClientTS) {
		return fmt.Errorf("%w: client_ts not RFC3339 UTC", ErrBadSchema)
	}
	if !validIdent(e.ClientVersion, true) || !validIdent(e.OS, true) || !validIdent(e.Arch, true) {
		return fmt.Errorf("%w: client_version/os/arch must be identifiers", ErrBadSchema)
	}
	for i := range e.Events {
		if err := validateEvent(&e.Events[i], e.InstallID); err != nil {
			return fmt.Errorf("event[%d]: %w", i, err)
		}
	}
	return nil
}

// validateEvent checks one event: closed vocabularies, classification ×
// purpose pair, ts shape, install binding.
func validateEvent(ev *Event, installID string) error {
	if _, ok := classificationPairs[ev.Event]; !ok {
		return fmt.Errorf("%w: unknown event %q", ErrBadSchema, ev.Event)
	}
	if ev.EventVersion != 1 {
		return fmt.Errorf("%w: event_version %d", ErrBadSchema, ev.EventVersion)
	}
	if !tsRe.MatchString(ev.SchemaVersion) {
		return fmt.Errorf("%w: schema_version not RFC3339 UTC", ErrBadSchema)
	}
	if !validIdent(ev.SessionSpan, true) {
		return fmt.Errorf("%w: session_span must be an identifier", ErrBadSchema)
	}
	if !tsRe.MatchString(ev.TS) {
		return fmt.Errorf("%w: ts not RFC3339 UTC", ErrBadSchema)
	}
	if ev.InstallID != installID {
		return fmt.Errorf("%w: event install_id mismatch", ErrBadSchema)
	}
	pair, ok := classificationPairs[ev.Event]
	if !ok || ev.Classification != pair[0] || ev.Purpose != pair[1] {
		return fmt.Errorf("%w: classification/purpose pair for %q", ErrBadSchema, ev.Event)
	}
	if err := validateFields(ev); err != nil {
		return err
	}
	// No-text-fields enforcement (every event, contract 1.2.0): a field name
	// outside the event's allow-list is refused.
	allowed := eventFields[ev.Event]
	for k := range ev.Fields {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%w: %s unknown field %q", ErrBadSchema, ev.Event, k)
		}
	}
	return nil
}

// validateFields checks the per-event closed vocabularies and bounds.
//
//nolint:gocyclo // one case per closed event type; splitting would scatter the field allowlists the no-text guarantee rests on
func validateFields(ev *Event) error {
	f := ev.Fields
	get := func(k string) string {
		s, _ := f[k].(string)
		return s
	}
	// num accepts JSON-decoded float64 and native Go integers — clients may
	// build envelopes natively without round-tripping through encoding/json.
	num := func(k string) (float64, bool) {
		switch v := f[k].(type) {
		case float64:
			return v, true
		case int:
			return float64(v), true
		case int64:
			return float64(v), true
		default:
			return 0, false
		}
	}
	switch ev.Event {
	case EventToolUse:
		if !ToolName[get("tool_name")] {
			return fmt.Errorf("%w: tool_name %q", ErrBadSchema, get("tool_name"))
		}
		if n, ok := num("count"); !ok || n < 1 || n > 1000 {
			return fmt.Errorf("%w: tool_use.count", ErrBadSchema)
		}
	case EventError:
		if !ErrorClass[get("error_class")] {
			return fmt.Errorf("%w: error_class %q", ErrBadSchema, get("error_class"))
		}
		if !ErrorSurface[get("surface")] {
			return fmt.Errorf("%w: surface %q", ErrBadSchema, get("surface"))
		}
	case EventTokenUse:
		if !ModelTier[get("model_tier")] {
			return fmt.Errorf("%w: model_tier", ErrBadSchema)
		}
		if !Role[get("role")] {
			return fmt.Errorf("%w: role", ErrBadSchema)
		}
		for _, k := range []string{"tokens_in", "tokens_out", "cache_read"} {
			if _, ok := num(k); !ok {
				return fmt.Errorf("%w: token_use.%s", ErrBadSchema, k)
			}
		}
	case EventSessionEnd:
		if !Adapter[get("adapter")] {
			return fmt.Errorf("%w: adapter %q", ErrBadSchema, get("adapter"))
		}
		if _, ok := num("duration_ms"); !ok {
			return fmt.Errorf("%w: session_end.duration_ms", ErrBadSchema)
		}
		switch get("outcome") {
		case "ok", "user_stop", "error", "cancelled":
		default:
			return fmt.Errorf("%w: session_end.outcome %q", ErrBadSchema, get("outcome"))
		}
	case EventSessionStart:
		if !Adapter[get("adapter")] {
			return fmt.Errorf("%w: adapter %q", ErrBadSchema, get("adapter"))
		}
	case EventAppStart, EventAppStop:
		if !validIdent(get("version"), false) {
			return fmt.Errorf("%w: version must be an identifier", ErrBadSchema)
		}
		// os / arch (plan §D5) are optional identifiers.
		if !validIdent(get("os"), true) || !validIdent(get("arch"), true) {
			return fmt.Errorf("%w: os/arch must be identifiers", ErrBadSchema)
		}
	case EventDiagCommand:
		if !ToolName[get("tool_name")] {
			return fmt.Errorf("%w: diag tool_name", ErrBadSchema)
		}
		argv := get("argv_trunc")
		if argv == "" || len(argv) > MaxArgvLen {
			return fmt.Errorf("%w: argv_trunc length", ErrBadSchema)
		}
		if _, ok := num("exit"); !ok {
			return fmt.Errorf("%w: diag exit", ErrBadSchema)
		}
	case EventBatchMeta:
		for _, k := range []string{"dropped_count", "retry_count"} {
			if n, ok := num(k); !ok || n < 0 {
				return fmt.Errorf("%w: batch_meta.%s", ErrBadSchema, k)
			}
		}
	case EventDayActive:
		// no fields
	case EventPromptCycle:
		if !Model[get("model")] {
			return fmt.Errorf("%w: prompt_cycle.model", ErrBadSchema)
		}
		if !Provider[get("provider")] {
			return fmt.Errorf("%w: prompt_cycle.provider", ErrBadSchema)
		}
		if _, ok := num("input_size"); !ok {
			return fmt.Errorf("%w: prompt_cycle.input_size", ErrBadSchema)
		}
		if _, ok := num("output_size"); !ok {
			return fmt.Errorf("%w: prompt_cycle.output_size", ErrBadSchema)
		}
		if cp, ok := num("cache_percentage"); !ok || cp < 0 || cp > 100 {
			return fmt.Errorf("%w: prompt_cycle.cache_percentage", ErrBadSchema)
		}
		if _, ok := num("end_to_end_duration_ms"); !ok {
			return fmt.Errorf("%w: prompt_cycle.end_to_end_duration_ms", ErrBadSchema)
		}
		if !Segment[get("segment")] {
			return fmt.Errorf("%w: prompt_cycle.segment", ErrBadSchema)
		}
		// correlation-only optional fields — identifiers when present.
		for _, k := range []string{"session_span", "turn_id"} {
			if v, ok := f[k]; ok {
				s, _ := v.(string)
				if !validIdent(s, false) {
					return fmt.Errorf("%w: prompt_cycle.%s must be an identifier", ErrBadSchema, k)
				}
			}
		}
	}
	return nil
}

// TierAllows reports whether the given consent tier may emit the event.
// EffectiveTier is applied first by callers that accept user-supplied tier labels,
// so the legacy "usage" alias resolves to baseline before this check.
func TierAllows(tier, event string) bool {
	tier = EffectiveTier(tier)
	if deepOnly[event] {
		return tier == TierDeep
	}
	switch tier {
	case TierBaseline, TierUsage, TierDeep:
		return tierAllows[TierBaseline][event]
	case TierEnrichment:
		return tierAllows[TierEnrichment][event]
	case TierError:
		return tierAllows[TierError][event]
	default:
		return false
	}
}

// TierCovers reports whether want is at or below have (tier escalation).
// Rank order: off < baseline < deep < enrichment. Legacy "usage" is an alias for
// baseline at the same rank, so a usage-tier install still covers baseline events.
func TierCovers(have, want string) bool {
	rank := map[string]int{
		TierOff:        0,
		TierBaseline:   1,
		TierUsage:      1,
		TierDeep:       2,
		TierEnrichment: 3,
	}
	return rank[EffectiveTier(have)] >= rank[EffectiveTier(want)]
}

// BaselineTierEvents returns the canonical set of event names the baseline tier
// admits. It is the drift-gate anchor: every repo's verify-telemetry-contract + the
// no-text-fields test assert against this same set, so the three contracts cannot
// diverge on what "baseline" means.
// BaselineTierEvents returns the canonical baseline event set in the order the
// contract_test.go drift gate asserts against. Map iteration order is not
// stable, so we emit in a fixed order rather than ranging the map.
func BaselineTierEvents() []string {
	return []string{
		EventAppStart,
		EventAppStop,
		EventSessionStart,
		EventSessionEnd,
		EventToolUse,
		EventError,
		EventTokenUse,
		EventDayActive,
		EventBatchMeta,
		EventPromptCycle,
	}
}

// NormalizeUUID lowercases and trims a uuid string.
func NormalizeUUID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// DeepDisclosure is the canonical deep-tier disclosure text (BR-10.7). It is
// part of the contract: the client prints it verbatim at consent time and
// binds the consent request to its digest, and the server accepts a deep
// tier grant only when the request carries THIS text's digest — a consent
// recorded against wording the client never showed is void. The text is
// content-frozen: any wording change is a contract change (mirror both
// repos, regenerate the golden, bump the version).
const DeepDisclosure = `Deep diagnostics consent.

This tier adds truncated, scrubbed command lines and tool arguments to the
counters collected by the base tiers. It is the most sensitive tier: the
lines are shortened and pass a scrubber that strips secrets, paths are
reduced to their base names, and the raw payload is sealed at rest with a
90-day hard cap — after 90 days deep-tier raw is deleted automatically.
Downgrading your consent tier deletes all staged deep data immediately,
locally and server-side.
`

// DeepDisclosureDigest returns the hex sha256 of DeepDisclosure — the value
// consent requests must carry. Computed from the constant (never stored
// stale) so the digest and the shown text can never drift apart.
func DeepDisclosureDigest() string {
	sum := sha256.Sum256([]byte(DeepDisclosure))
	return hex.EncodeToString(sum[:])
}

// ValidDeepDigest reports whether d is the canonical deep-disclosure digest.
func ValidDeepDigest(d string) bool {
	return d == DeepDisclosureDigest()
}
