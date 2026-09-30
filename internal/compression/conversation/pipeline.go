package conversation

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/compression/conversation/types"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/stash"
)

// PipelineConfig mirrors the [config.ConversationConfig] knobs the
// pipeline consults at runtime. Copied (rather than shared) so config
// reloads don't race with in-flight compression.
type PipelineConfig struct {
	// Enabled gates the whole pipeline. When false, Run is a no-op that
	// returns the original body and OriginalBytes == CompressedBytes.
	Enabled bool
	// Mode selects drop strategy: [ModeToken] or [ModeCache]. Empty
	// string defaults to [ModeToken].
	Mode string
	// TargetRatio is the fraction of the input byte count to target.
	// Defaults to 0.85 when zero.
	TargetRatio float64
	// PreserveLastN messages are pinned at score 1.0 and are never
	// dropped.
	PreserveLastN int
	// CompressTypes names the content types eligible for per-type
	// compression. An empty map means "no per-type compression" (drops
	// still run).
	CompressTypes []string
	// DisableDrops turns off the budget enforcer's lossy Pass-2 eviction
	// on EVERY provider lane. When true the budget target is best-effort:
	// only content-preserving per-type compressors run and the body ships
	// with whatever they achieve (even 0%), never dropped or truncated.
	// Mirrors [compression.conversation].disable_drops. Provider-neutral
	// — distinct from the Anthropic-shaped cache_aware mode (which also
	// skips drops but additionally narrows per-type eligibility to
	// tool_result messages for prefix-cache determinism).
	DisableDrops bool
	// PrefixBytes is the byte budget used to compute the
	// message_prefix_hash. Defaults to 8KB.
	PrefixBytes int
}

// Pipeline is the top-level compression driver the proxy wires into its
// pre-forward path. Safe for concurrent use after construction.
type Pipeline struct {
	cfg                    PipelineConfig
	registry               *Registry
	scrubber               *scrub.Scrubber
	stash                  *stash.Stash
	stashThreshold         int
	summarizerFactory      SummarizerFactory
	summarizerByProvider   map[string]SummarizerFactory
	rollingThresholdTokens int
	summaryCache           *summaryCache
	rollingState           *rollingState
	symbolLookup           SymbolLookup
	aggressiveCode         aggressiveCodeConfig
}

// aggressiveCodeConfig holds the opt-in aggressive code-collapse
// settings (codeintel Phase 2). The zero value is fully disabled — the
// default, content-preserving posture. allowedExts is the set of file
// extensions (leading dot, lowercase) whose bodies may be collapsed;
// empty means none even when enabled (the plan's per-language opt-in
// default). previewOnly records what WOULD collapse without changing
// anything.
type aggressiveCodeConfig struct {
	enabled     bool
	allowedExts map[string]bool
	previewOnly bool
	minLines    int
}

// WithAggressiveCode enables opt-in, exact-span-gated body-collapse for
// the given file extensions. It requires a stash (set via WithStash) to
// hold collapsed originals; without one the feature stays off. Returns
// the same pipeline for chaining. Pass enabled=false (or empty exts) to
// disable — the content-preserving default.
func (p *Pipeline) WithAggressiveCode(enabled bool, allowedExts map[string]bool, previewOnly bool, minLines int) *Pipeline {
	p.aggressiveCode = aggressiveCodeConfig{
		enabled:     enabled,
		allowedExts: allowedExts,
		previewOnly: previewOnly,
		minLines:    minLines,
	}
	return p
}

// buildCodeCollapser returns the per-block collapse hook for
// compressToolResults, or nil when the feature is disabled / unwired.
// The closure performs STORE LOOKUPS ONLY (hintsForFile) — never an
// inline parse — honouring ADR-0002's hot-path rule.
func (p *Pipeline) buildCodeCollapser(ctx context.Context) codeCollapser {
	ac := p.aggressiveCode
	if !ac.enabled || len(ac.allowedExts) == 0 {
		return nil
	}
	// Collapse no longer hard-requires the stash. When a stash is wired,
	// the elided body is written there so the model can retrieve_stashed
	// it. When it isn't (the codex-safe profile pins stash off for
	// OpenAI implicit-cache reasons), we still collapse and emit a
	// re-read marker instead — write returns ("", nil) and
	// applyCodeCollapse picks the stash-less marker. Collapse is a
	// compression concern; stash is a separate retrievability concern.
	write := func([]byte) (string, error) { return "", nil }
	if p.stash != nil {
		write = p.stash.Write
	}
	return func(filename string, body []byte, msgIndex int) ([]byte, []Event, bool) {
		ext := strings.ToLower(filepath.Ext(filename))
		if !ac.allowedExts[ext] {
			return body, nil, false
		}
		hints := p.hintsForFile(ctx, filename) // available + !stale + symbols, all store reads
		if len(hints.Symbols) == 0 {
			return body, nil, false
		}
		plans := planCodeCollapse(body, hints.Symbols, collapseOptions{MinLines: ac.minLines})
		if len(plans) == 0 {
			return body, nil, false
		}
		if ac.previewOnly {
			return body, previewCollapseEvents(plans, msgIndex), false
		}
		return applyCodeCollapse(body, plans, msgIndex, write)
	}
}

// SymbolLookup is the narrow read-only interface the conversation
// package needs from the code-intelligence engine. Defined here so this
// package never imports internal/codeintel (one-way dep). The adapter at
// cmd/observer/proxy.go wraps a codeintel.Provider to satisfy it.
//
// All three methods MUST be safe to call concurrently from many
// per-block compression goroutines.
type SymbolLookup interface {
	// Available reports whether the code index is open and reachable.
	// Pipeline callers MUST gate every SymbolsInFile / Stale call on
	// this to avoid wasted lookups.
	Available() bool
	// Stale advises whether absPath's mtime is newer than the index's
	// last pass. When true, callers SHOULD skip the symbol pre-fetch —
	// stale enrichment misleads the agent.
	Stale(absPath string) bool
	// SymbolsInFile returns the top-N user-facing symbols defined in
	// absPath, sorted by start_line ASC for byte-stable marker
	// rendering. Returns nil on schema-missing / availability errors —
	// never an error in the failure case.
	SymbolsInFile(ctx context.Context, absPath string) ([]CompressorSymbol, error)
}

// WithSymbolLookup attaches a [SymbolLookup] so per-block compression
// can pre-fetch symbols for the V7-11 / v1.7.7 marker enrichment.
// Pass nil to disable. Returns the same pipeline pointer for chaining
// (mirrors [Pipeline.WithStash]).
//
// The pipeline never opens the index itself — the caller
// (cmd/observer/proxy.go) builds the codeintel.Provider and wraps it in
// an adapter satisfying SymbolLookup.
func (p *Pipeline) WithSymbolLookup(c SymbolLookup) *Pipeline {
	p.symbolLookup = c
	return p
}

// hintsForFile builds a [CompressHints] for the given filename,
// pre-fetching code-index symbols when available and the index isn't
// stale. Best-effort — any error path degrades to filename-only
// hints. Returns the zero CompressHints when filename is empty.
//
// Called from the per-block compression call sites (anthropic.go,
// openai.go) just before invoking the per-type compressor. The
// symbol-lookup query happens here so the pipeline owns the
// "available + !stale + pre-fetch" composition; the compressor
// stays a pure transform.
func (p *Pipeline) hintsForFile(ctx context.Context, filename string) CompressHints {
	if filename == "" {
		return CompressHints{}
	}
	hints := CompressHints{Filename: filename}
	if p.symbolLookup == nil || !p.symbolLookup.Available() {
		return hints
	}
	if p.symbolLookup.Stale(filename) {
		return hints
	}
	syms, err := p.symbolLookup.SymbolsInFile(ctx, filename)
	if err != nil || len(syms) == 0 {
		return hints
	}
	hints.Symbols = syms
	return hints
}

// Summarizer condenses a slice of messages into a single short
// summary string suitable for replacing them inline. Implementations
// typically call a small model (Claude Haiku) but the interface stays
// API-agnostic so tests can mock it.
type Summarizer interface {
	Summarize(ctx context.Context, msgs []Message) (string, error)
}

// SummarizerFactory returns the Summarizer to use for a given session.
// Production passes a factory that pulls the session's most recently
// observed Anthropic Authorization header out of an in-memory cache so
// the summary call rides the same auth as the user's regular
// requests. Returns nil when no Summarizer is available for the
// session — the pipeline degrades gracefully (rolling-summ no-ops).
type SummarizerFactory interface {
	For(sessionID string) Summarizer
}

// NewPipeline constructs a Pipeline. Either registry or scrubber may be
// nil: a nil registry disables per-type compression; a nil scrubber
// disables the final scrub pass. Nil scrubber is only appropriate for
// tests — production callers MUST pass a real scrubber.
func NewPipeline(cfg PipelineConfig, registry *Registry, scrubber *scrub.Scrubber) *Pipeline {
	return &Pipeline{cfg: cfg, registry: registry, scrubber: scrubber}
}

// WithSummarizerFactory attaches a per-session summarizer factory for
// the D20 (rolling summarisation) feature. When the conversation token
// estimate exceeds thresholdTokens, the pipeline calls
// `factory.For(sessionID).Summarize(...)` on the messages older than
// the preserve-last-N tail and replaces them with a synthetic system
// message carrying the summary.
//
// Returns the same pipeline pointer for chaining. Pass nil factory or
// thresholdTokens ≤ 0 to disable.
//
// Token estimation: rough char-count / 4 heuristic. Good enough to
// pick a "is this conversation long?" threshold; not load-bearing for
// correctness.
func (p *Pipeline) WithSummarizerFactory(f SummarizerFactory, thresholdTokens int) *Pipeline {
	p.summarizerFactory = f
	p.rollingThresholdTokens = thresholdTokens
	if p.rollingState == nil {
		p.rollingState = newRollingState()
	}
	return p
}

// WithSummarizerFactoryFor binds a [SummarizerFactory] to a specific
// provider so the pipeline picks the right summariser at request time.
// Multiple calls accumulate — bind one factory per provider.
//
// Example:
//
//	pipeline.
//	    WithSummarizerFactoryFor("anthropic", anthFactory, 80000).
//	    WithSummarizerFactoryFor("openai",   oaiFactory,  80000)
//
// The thresholdTokens parameter sets a SHARED token threshold (the
// pipeline holds one). The first call's value sticks; subsequent calls
// only update the factory map. To use different thresholds per
// provider, run separate pipelines.
//
// The legacy [Pipeline.WithSummarizerFactory] still works — it sets a
// fallback factory used when the request's provider isn't in the
// per-provider map. Pass the same factory to both methods if you want
// it to fire on every provider.
func (p *Pipeline) WithSummarizerFactoryFor(provider string, f SummarizerFactory, thresholdTokens int) *Pipeline {
	if p.summarizerByProvider == nil {
		p.summarizerByProvider = make(map[string]SummarizerFactory, 2)
	}
	p.summarizerByProvider[provider] = f
	if p.rollingThresholdTokens == 0 {
		p.rollingThresholdTokens = thresholdTokens
	}
	if p.rollingState == nil {
		p.rollingState = newRollingState()
	}
	return p
}

// summarizerFor returns the [SummarizerFactory] bound to the given
// provider, falling back to the legacy field set via
// [Pipeline.WithSummarizerFactory]. Returns nil when neither is set.
func (p *Pipeline) summarizerFor(provider string) SummarizerFactory {
	if f, ok := p.summarizerByProvider[provider]; ok && f != nil {
		return f
	}
	return p.summarizerFactory
}

// WithStash attaches a content-addressed stash for the CCR (Compressed
// Content Retrieval) feature. When set, tool_result bodies whose post-
// per-type-compression size still exceeds thresholdBytes are written
// to the stash and replaced inline with a deterministic marker; the
// model retrieves originals via the `retrieve_stashed` MCP tool. Pass
// nil to disable. Returns the same pipeline pointer for chaining.
//
// thresholdBytes defaults to 8192 when ≤ 0.
func (p *Pipeline) WithStash(s *stash.Stash, thresholdBytes int) *Pipeline {
	if thresholdBytes <= 0 {
		thresholdBytes = 8192
	}
	p.stash = s
	p.stashThreshold = thresholdBytes
	return p
}

// PipelineResult carries the compressed body plus per-turn counters for
// observability.
type PipelineResult struct {
	// Body is the compressed, scrubbed request body ready to forward
	// upstream. When Skipped, Body is the unmodified input.
	Body []byte
	// Skipped is true when the pipeline did nothing (disabled, non-JSON
	// body, non-Anthropic provider). Stats fields still populate
	// OriginalBytes / CompressedBytes with len(body).
	Skipped bool
	// Provider the pipeline dispatched against. Empty for non-supported
	// providers.
	Provider string
	// MessagePrefixHash is a stable SHA-256 of the first
	// [PipelineConfig.PrefixBytes] bytes of message content after
	// compression. Empty when no messages were observable.
	MessagePrefixHash string
	// OriginalBytes is len(body) before compression.
	OriginalBytes int
	// CompressedBytes is len(Body) after compression.
	CompressedBytes int
	// CompressedCount is the number of tool_result messages whose
	// bodies were rewritten by a per-type compressor.
	CompressedCount int
	// DroppedCount is the number of source messages replaced by a
	// marker.
	DroppedCount int
	// MarkerCount is the number of marker messages emitted (consecutive
	// drops collapse into one marker).
	MarkerCount int
	// MessageCount is the number of messages in the final body.
	MessageCount int
	// Events is the per-decision detail (one record per compress or
	// drop). Empty when the pipeline skipped or no decisions were made.
	// Persisted into compression_events by the store layer.
	Events []Event
}

// Run compresses body when the pipeline is enabled and the provider is
// supported. Returns the original body unchanged on any skip path so the
// proxy can always forward.
//
// Run is the legacy entry point kept for tests and callers that don't
// have a session_id available. Production callers should use
// [Pipeline.RunInSessionContext] so v1.4.42+ features (rolling-summ,
// read-cache auto-substitution, post-compact injection) can fire —
// they need session-scoped state.
func (p *Pipeline) Run(provider string, body []byte) PipelineResult {
	return p.RunInSession(provider, body, "")
}

// RunInSession is the session-aware variant of [Pipeline.Run]. The
// `sessionID` is used by features that need cross-turn state within a
// single session (D20 rolling summaries, C16 read-cache auto-
// substitution). Pass "" for sessionID when no session context is
// available — the pipeline degrades gracefully (those features no-op).
//
// Equivalent to [Pipeline.RunInSessionContext] with a background
// context. Production callers (the proxy) should use the context-
// aware form so HTTP-bearing features (D20 summariser) respect the
// proxy request's cancellation.
func (p *Pipeline) RunInSession(provider string, body []byte, sessionID string) PipelineResult {
	return p.RunInSessionContext(context.Background(), provider, body, sessionID)
}

// RunInSessionContext is the v1.4.43+ context-aware entry point that
// the proxy adapter calls so D20 rolling summarisation HTTP requests
// respect the parent request's cancellation. Behaviour is otherwise
// identical to [Pipeline.RunInSession].
func (p *Pipeline) RunInSessionContext(ctx context.Context, provider string, body []byte, sessionID string) PipelineResult {
	result := PipelineResult{
		Body:            body,
		Skipped:         true,
		Provider:        provider,
		OriginalBytes:   len(body),
		CompressedBytes: len(body),
	}
	if !p.cfg.Enabled || len(body) == 0 {
		return result
	}
	switch provider {
	case "anthropic":
		return p.runAnthropic(ctx, provider, body, result, sessionID)
	case "openai":
		return p.runOpenAI(ctx, provider, body, result, sessionID)
	case "google":
		return p.runGoogle(ctx, provider, body, result, sessionID)
	default:
		return result
	}
}

// runGoogle compresses a Gemini generateContent request body: per-type
// compression of functionResponse tool-output string values + tool-definition
// trim, with a byte-stable fast-path that forwards the original unchanged when
// nothing fires (so Gemini's implicit prefix cache keeps hitting). See
// gemini.go for the v1 scope + the follow-ups deferred from the OpenAI parity
// (stash, rolling, score/enforce).
func (p *Pipeline) runGoogle(ctx context.Context, provider string, body []byte, skipped PipelineResult, sessionID string) PipelineResult {
	_ = sessionID // reserved for the rolling-summ follow-up (see gemini.go)
	envelope, contents, ok := geminiExtract(body)
	if !ok || len(contents) == 0 {
		return skipped
	}
	droppedCount := 0
	allow := buildAllow(p.cfg.CompressTypes)
	cctx := geminiCompressCtx{
		registry: p.registry,
		allow:    allow,
		buildHints: func(fn string) CompressHints {
			return p.hintsForFile(ctx, fn)
		},
	}
	// CCR stash parity with runOpenAI: a functionResponse string leaf still
	// over the threshold AFTER per-type compression is stashed + replaced
	// with a retrieve_stashed marker. Gated on a stash being wired; a typed
	// nil *stash.Stash must NOT become a non-nil interface (would panic on
	// Write), so guard before assigning.
	if p.stash != nil {
		cctx.stash = p.stash
		cctx.stashThreshold = p.stashThreshold
	}
	var events []Event
	events = append(events, compressGeminiFunctionResponses(contents, cctx)...)
	if allow[types.Tools] {
		events = append(events, compressGeminiToolDefinitions(envelope)...)
	}
	// Budget drop pass (parity-with-runOpenAI follow-up): when the body is
	// still over target, drop the oldest complete tool round-trips. The pass
	// is pairing- and alternation-SAFE by construction and fails safe toward
	// a valid body — see gemini.go::enforceGeminiBudget for the invariants.
	//
	// Provider-neutral no-drop capability: when disable_drops is set (the
	// codex-safe profile) the lossy eviction pass is skipped entirely, the
	// SAME semantics the OpenAI/Anthropic lanes get via BudgetOptions.SkipDrops.
	// enforceGeminiBudget is a pure drop pass (no per-type compression lives
	// inside it — that already ran above via compressGeminiFunctionResponses /
	// compressGeminiToolDefinitions), so gating the whole call keeps every
	// legitimate per-type compression while turning off only eviction. The
	// body may end up 0% compressed and over-budget, but it stays valid with
	// zero fabricated drop events (fail-open toward a valid larger body).
	if !p.cfg.DisableDrops {
		dropEvents := enforceGeminiBudget(contents, geminiBudgetOptions{
			TargetRatio:       p.cfg.TargetRatio,
			PreserveLastN:     p.cfg.PreserveLastN,
			OriginalBodyBytes: len(body),
		})
		if len(dropEvents) > 0 {
			events = append(events, dropEvents...)
			for i := range contents {
				if contents[i].dropped {
					droppedCount++
				}
			}
		}
	}

	// Fast-path: nothing fired → forward the original body unchanged (only
	// scrub-forward), preserving Gemini's implicit prefix cache.
	if len(events) == 0 {
		scrubbed := body
		if p.scrubber != nil {
			scrubbed = p.scrubber.ScrubForward(body)
		}
		return PipelineResult{
			Body:            scrubbed,
			Skipped:         false,
			Provider:        provider,
			OriginalBytes:   len(body),
			CompressedBytes: len(scrubbed),
			MessageCount:    len(contents),
		}
	}

	newBody, err := serializeGemini(envelope, contents)
	if err != nil || !geminiBodyValid(newBody) {
		return skipped // never poison the forward path with invalid JSON
	}
	br := BudgetResult{Stats: BudgetStats{
		CompressedCount: len(events) - droppedCount,
		DroppedCount:    droppedCount,
		MessageCount:    len(contents) - droppedCount,
		Events:          events,
	}}
	return p.finalize(provider, body, newBody, br, "")
}

// runAnthropic handles the Messages API body: extract → per-block
// pre-compression of tool_result bodies → score → enforce → serialize
// (with cache_control injection when mode=cache) → scrub.
//
// Per-block pre-compression runs before scoring so Score and Enforce
// see the post-compression byte counts and the budget pass uses
// accurate sizes. It also fixes a long-standing bug where messages
// carrying parallel tool_results (Claude Code's common multi-Read
// pattern) had Enforce's flat-text compression silently discarded by
// the serializer.
func (p *Pipeline) runAnthropic(ctx context.Context, provider string, body []byte, skipped PipelineResult, sessionID string) PipelineResult {
	envelope, extracted, ok := anthropicExtract(body)
	if !ok || len(extracted) == 0 {
		return skipped
	}
	cacheAware := strings.EqualFold(p.cfg.Mode, ModeCacheAware)
	// Cache-aware mode no longer "protects" the cache_control marker block
	// from compression. The SDK rolls that marker forward each turn (last
	// block of the latest message), so leaving the marked block uncompressed
	// made the same logical message go on the wire with two different byte
	// representations across consecutive turns — breaking Anthropic's prefix
	// cache from that block onward and inflating cache_creation. Every block
	// is compressed uniformly (each compressor is a pure function of the
	// block's bytes), so a block's serialisation is identical whether or not
	// it currently carries the marker. cacheAware still gates Enforce's
	// drop-skip below.
	//
	// Order: C16 read-cache substitution first (most aggressive — drops
	// the body entirely and skips per-type), then per-type compression
	// on what's left, then tool-definitions trim, then CCR stash on
	// anything still over the threshold.
	readCacheEvents := substituteRedundantReads(extracted, sessionID)
	allow := buildAllow(p.cfg.CompressTypes)
	preEvents := compressToolResults(extracted, p.registry, allow, func(fn string) CompressHints {
		return p.hintsForFile(ctx, fn)
	}, p.buildCodeCollapser(ctx))
	preEvents = append(readCacheEvents, preEvents...)
	// V7-21: tool-defs trim is gated by the "tools" sentinel in
	// compress_types. Default lists do NOT include it; operators opt in
	// via `compress_types = [..., "tools"]`. Pre-v1.7.21 this ran
	// unconditionally and re-marshaled the envelope on every turn,
	// adding ~10% net-input overhead even when the recipe said
	// "compress nothing". See docs/v1.7.21-tools-defs-gate-plan-2026-06-01.md.
	if allow[types.Tools] {
		toolDefEvents := compressToolDefinitions(envelope)
		preEvents = append(preEvents, toolDefEvents...)
	}
	if p.stash != nil {
		stashEvents := stashLargeBodies(extracted, p.stash, p.stashThreshold)
		preEvents = append(preEvents, stashEvents...)
	}
	msgs := toConversationMessages(extracted)
	// D20 rolling summarisation: when the conversation has crossed
	// the token threshold, replace older messages with a summary
	// marker so subsequent turns stay under Anthropic's context cap.
	// Sticky boundary preserves cross-turn invariance — see
	// rolling.go::summarizeIfThreshold for the full contract.
	if rollingMsgs, rollingEvents := p.summarizeIfThreshold(ctx, msgs, sessionID, provider); len(rollingEvents) > 0 {
		msgs = rollingMsgs
		preEvents = append(preEvents, rollingEvents...)
	}
	br, splitAt, prefixHash := p.compressMessagesCacheAware(msgs, len(body), cacheAware)
	if len(preEvents) > 0 {
		br.Stats.Events = append(preEvents, br.Stats.Events...)
		br.Stats.CompressedCount += len(preEvents)
	}

	// Fast path: when nothing changed (no compression events, no drops,
	// no cache_control injection), forward the original body unchanged.
	// Re-marshaling through serializeAnthropic+marshalEnvelope rewrites
	// HTML chars (`<` → `<`) and reorders top-level keys, producing
	// byte-different output that's semantically identical but causes:
	//   1. Anthropic prompt-cache lookup to miss (byte-hash sensitive).
	//   2. Subtle on-wire differences in system-reminder tags that the
	//      model may sample around differently.
	// This was the root cause of the live A/B regression where ON took
	// ~2× turns on multi-file exploration prompts vs OFF — the model's
	// tool-use strategy diverged because we were silently reformatting
	// the body.
	wantInject := strings.EqualFold(p.cfg.Mode, ModeCache) && splitAt > 0
	if len(br.Stats.Events) == 0 && br.Stats.DroppedCount == 0 && !wantInject {
		scrubbed := body
		if p.scrubber != nil {
			scrubbed = p.scrubber.ScrubForward(body)
		}
		return PipelineResult{
			Body:              scrubbed,
			Skipped:           false,
			Provider:          provider,
			MessagePrefixHash: prefixHash,
			OriginalBytes:     len(body),
			CompressedBytes:   len(scrubbed),
			MessageCount:      br.Stats.MessageCount,
		}
	}

	cacheBreakpointIdx := -1
	if wantInject {
		cacheBreakpointIdx = splitAt - 1
	}
	newBody, err := serializeAnthropic(envelope, extracted, br.Messages, cacheBreakpointIdx)
	if err != nil {
		return skipped
	}
	return p.finalize(provider, body, newBody, br, prefixHash)
}

// runOpenAI handles Chat Completions and Responses API bodies. Cache_control
// not applied — Chat Completions has no standard cache marker today, and
// Responses API uses session-keyed `prompt_cache_key` rather than block
// markers.
//
// Order of operations mirrors runAnthropic's pre-pass chain: read-cache
// substitution → per-type compression on tool outputs → tool-definitions
// trim → G31 stash on anything still oversized → score+enforce.
//
// Fast-path early-return when zero events fire is critical — OpenAI's
// `prompt_cache_key`-keyed cache is byte-hash sensitive (both wires use
// the same key), and re-marshaling through serializeOpenAI* +
// marshalEnvelope rewrites HTML chars and reorders top-level keys,
// producing byte-different output that misses the cache. Mirrors the
// Anthropic-side fix pinned by `TestPipelineCacheAware_Determinism`.
func (p *Pipeline) runOpenAI(ctx context.Context, provider string, body []byte, skipped PipelineResult, sessionID string) PipelineResult {
	envelope, extracted, ok := openaiExtract(body)
	if ok && len(extracted) > 0 {
		// Chat Completions full pre-pass chain (mirror of Responses API).
		// Order: C16 read-cache (most aggressive — drops the body
		// entirely) → per-type → tool-defs trim → CCR stash on anything
		// still over threshold → score+enforce.
		readCacheEvents := substituteOpenAIChatRedundantReads(extracted, sessionID)
		allow := buildAllow(p.cfg.CompressTypes)
		preEvents := compressOpenAIChatToolResults(extracted, p.registry, allow, func(fn string) CompressHints {
			return p.hintsForFile(ctx, fn)
		}, p.buildCodeCollapser(ctx))
		preEvents = append(readCacheEvents, preEvents...)
		// V7-21: tool-defs gate. See runAnthropic for the rationale.
		if allow[types.Tools] {
			toolDefEvents := compressOpenAIChatToolDefinitions(envelope)
			preEvents = append(preEvents, toolDefEvents...)
		}
		if p.stash != nil {
			stashEvents := stashOpenAIChatLargeBodies(extracted, p.stash, p.stashThreshold)
			preEvents = append(preEvents, stashEvents...)
		}

		msgs := openaiToConversationMessages(extracted)
		// D20 rolling summarisation — same gate / sticky-boundary
		// contract as the other two providers.
		if rollingMsgs, rollingEvents := p.summarizeIfThreshold(ctx, msgs, sessionID, provider); len(rollingEvents) > 0 {
			msgs = rollingMsgs
			preEvents = append(preEvents, rollingEvents...)
		}
		br, _, prefixHash := p.compressMessages(msgs, len(body))
		if len(preEvents) > 0 {
			br.Stats.Events = append(preEvents, br.Stats.Events...)
			br.Stats.CompressedCount += len(preEvents)
		}

		// Fast-path early-return: forward the original body unchanged
		// when nothing fired so OpenAI's `prompt_cache_key` cache lookup
		// hits. Re-serializing reorders map keys and rewrites HTML
		// chars, producing byte-different output that breaks cache
		// prefixes even when semantically identical.
		if len(br.Stats.Events) == 0 && br.Stats.DroppedCount == 0 {
			scrubbed := body
			if p.scrubber != nil {
				scrubbed = p.scrubber.ScrubForward(body)
			}
			return PipelineResult{
				Body:              scrubbed,
				Skipped:           false,
				Provider:          provider,
				MessagePrefixHash: prefixHash,
				OriginalBytes:     len(body),
				CompressedBytes:   len(scrubbed),
				MessageCount:      br.Stats.MessageCount,
			}
		}

		newBody, err := serializeOpenAI(envelope, extracted, br.Messages, -1)
		if err != nil {
			return skipped
		}
		return p.finalize(provider, body, newBody, br, prefixHash)
	}

	responsesEnvelope, responsesExtracted, responsesOK := openaiResponsesExtract(body)
	if !responsesOK || len(responsesExtracted) == 0 {
		return skipped
	}

	// Tier 0/1 pre-pass chain. Order matches runAnthropic:
	// read-cache (most aggressive — drops the body entirely) → per-type
	// → tool-defs trim → CCR stash on anything still over threshold.
	mcpSet := collectOpenAIMCPToolNames(responsesEnvelope)
	readCacheEvents := substituteOpenAIRedundantReads(responsesExtracted, sessionID)
	allow := buildAllow(p.cfg.CompressTypes)
	preEvents := compressOpenAIResponsesToolResults(responsesExtracted, p.registry, allow, mcpSet, func(fn string) CompressHints {
		return p.hintsForFile(ctx, fn)
	}, p.buildCodeCollapser(ctx))
	preEvents = append(readCacheEvents, preEvents...)
	// V7-21: tool-defs gate. See runAnthropic for the rationale.
	if allow[types.Tools] {
		toolDefEvents := compressOpenAIResponsesToolDefinitions(responsesEnvelope)
		preEvents = append(preEvents, toolDefEvents...)
	}
	if p.stash != nil {
		stashEvents := stashOpenAIResponsesLargeBodies(responsesExtracted, p.stash, p.stashThreshold, mcpSet)
		preEvents = append(preEvents, stashEvents...)
	}

	msgs := openaiResponsesToConversationMessages(responsesExtracted, mcpSet)
	// D20 rolling summarisation: when the conversation has crossed the
	// token threshold, replace older messages with a summary marker so
	// subsequent turns stay under the OpenAI Responses API context cap.
	// Sticky boundary preserves cross-turn invariance — see
	// rolling.go::summarizeIfThreshold for the full contract.
	if rollingMsgs, rollingEvents := p.summarizeIfThreshold(ctx, msgs, sessionID, provider); len(rollingEvents) > 0 {
		msgs = rollingMsgs
		preEvents = append(preEvents, rollingEvents...)
	}
	br, _, prefixHash := p.compressMessages(msgs, len(body))
	if len(preEvents) > 0 {
		br.Stats.Events = append(preEvents, br.Stats.Events...)
		br.Stats.CompressedCount += len(preEvents)
	}

	// Fast-path early-return: when nothing changed, forward the original
	// body unchanged so codex's `prompt_cache_key` cache lookup hits.
	// Re-serializing through json.Marshal reorders top-level map keys
	// and rewrites HTML chars (`<` → `<`), producing byte-different
	// output that breaks cache prefixes even when semantically identical.
	if len(br.Stats.Events) == 0 && br.Stats.DroppedCount == 0 {
		scrubbed := body
		if p.scrubber != nil {
			scrubbed = p.scrubber.ScrubForward(body)
		}
		return PipelineResult{
			Body:              scrubbed,
			Skipped:           false,
			Provider:          provider,
			MessagePrefixHash: prefixHash,
			OriginalBytes:     len(body),
			CompressedBytes:   len(scrubbed),
			MessageCount:      br.Stats.MessageCount,
		}
	}

	newBody, err := serializeOpenAIResponses(responsesEnvelope, responsesExtracted, br.Messages)
	if err != nil {
		return skipped
	}
	return p.finalize(provider, body, newBody, br, prefixHash)
}

// compressMessages runs the provider-agnostic middle of the pipeline:
// score → enforce → split. The scrubber is NOT applied here — each
// caller scrubs the serialized body in [finalize].
//
// originalBodyBytes is the size of the request body BEFORE any
// pre-compression. Passing it through to Enforce keeps the budget
// reference anchored to the true original size, so per-block
// pre-compression (anthropic.go::compressToolResults) shrinking
// individual tool_result bodies before scoring doesn't proportionally
// shrink the drop-trigger threshold.
func (p *Pipeline) compressMessages(msgs []Message, originalBodyBytes int) (BudgetResult, int, string) {
	return p.compressMessagesCacheAware(msgs, originalBodyBytes, false)
}

// compressMessagesCacheAware is the cache-aware-aware variant. When
// cacheAware is true Enforce skips drops and narrows per-type
// compression to RoleTool only. (Per-block tool_result compression
// already happens uniformly in compressToolResults, so there is no
// marker-block exception to thread through here.) Independently,
// p.cfg.DisableDrops feeds Enforce's provider-neutral SkipDrops
// capability so any lane can turn off lossy eviction while keeping full
// per-type compression eligibility.
func (p *Pipeline) compressMessagesCacheAware(msgs []Message, originalBodyBytes int, cacheAware bool) (BudgetResult, int, string) {
	scored := Score(msgs, ScoreOptions{PreserveLastN: p.cfg.PreserveLastN})
	compressAllow := buildAllow(p.cfg.CompressTypes)
	br := Enforce(scored, BudgetOptions{
		TargetRatio:       p.cfg.TargetRatio,
		Registry:          p.registry,
		CompressTypes:     compressAllow,
		Mode:              p.cfg.Mode,
		OriginalBodyBytes: originalBodyBytes,
		CacheAware:        cacheAware,
		// Provider-neutral no-drop capability. Threaded here (the shared
		// middle the OpenAI + Anthropic lanes funnel through) so both
		// honour disable_drops uniformly. The Google lane does NOT reach
		// this middle — it runs its own Gemini-safe drop pass and gates
		// it on p.cfg.DisableDrops directly in runGoogle, giving the same
		// semantics (drops skipped, per-type compression kept, fail-open).
		// On the Anthropic lane cacheAware may already skip drops; OR-ing
		// SkipDrops in is harmless (both routes just skip Pass 2).
		SkipDrops: p.cfg.DisableDrops,
	})
	prefixBytes := p.cfg.PrefixBytes
	if prefixBytes <= 0 {
		prefixBytes = 8 * 1024
	}
	splitAt := SplitIndex(br.Messages, prefixBytes)
	prefixHash := PrefixHash(br.Messages, splitAt)
	return br, splitAt, prefixHash
}

// finalize scrubs the serialized body and packs the PipelineResult so
// both provider paths share the same exit shape.
func (p *Pipeline) finalize(provider string, original, newBody []byte, br BudgetResult, prefixHash string) PipelineResult {
	if p.scrubber != nil {
		newBody = p.scrubber.ScrubForward(newBody)
	}
	return PipelineResult{
		Body:              newBody,
		Skipped:           false,
		Provider:          provider,
		MessagePrefixHash: prefixHash,
		OriginalBytes:     len(original),
		CompressedBytes:   len(newBody),
		CompressedCount:   br.Stats.CompressedCount,
		DroppedCount:      br.Stats.DroppedCount,
		MarkerCount:       br.Stats.MarkerCount,
		MessageCount:      br.Stats.MessageCount,
		Events:            br.Stats.Events,
	}
}

// buildAllow converts a string slice of type names (from config.toml)
// into a ContentType set for the budget enforcer.
//
// V7-19: returns a non-nil empty map for empty input — historically
// this returned nil, which downstream `if allow != nil && !allow[ct]`
// gates short-circuited to "allow all", silently inverting the
// codex-variant recipe (compress_types = [] → most aggressive
// compression instead of none). Empty list now correctly expresses
// "allow nothing" because `!allow[ct]` on an empty map returns true
// for every key. See `docs/v4-codex-compression-recipe-and-issues.md`
// V7-19 row + the v1.7.19 plan doc for the full investigation.
func buildAllow(names []string) map[types.ContentType]bool {
	allow := make(map[types.ContentType]bool, len(names))
	for _, n := range names {
		allow[types.ContentType(n)] = true
	}
	return allow
}
