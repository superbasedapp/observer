package cachetrack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Engine is the single owner of per-session CacheModel state and
// the single seam through which both the proxy (Tier 1) and the
// store-side watcher path (Tier 2) drive cache-tracking work
// (spec §24.2 + R-engine = Option A).
//
// Engine is safe for concurrent use; a per-session sync.Mutex
// guards each CacheModel. The proxy hot path and the watcher
// share the same Engine instance — owned by the store layer at
// daemon wiring time.
type Engine struct {
	mu       sync.Mutex
	sessions map[engineSessionKey]*sessionState
	// maxSessions is the LRU bound on sessions; ≤0 disables.
	// Config: [cachetrack].max_tracked_sessions, default 64.
	maxSessions int
	// Clock is injected for testability. Defaults to time.Now.
	Clock func() time.Time

	// CalibrateSink, when non-nil, receives one JSON-Lines
	// entry per block fed to ObserveTurn. Off by default
	// (config: [cachetrack].calibrate_log_path empty). When
	// set, the sink writes the first CalibrateBlockCap blocks
	// then auto-stops (atomic counter trips, subsequent writes
	// short-circuit). Diagnostic tool only — the chain hash
	// path never consults this. The wire shape is documented at
	// docs/plans/cache-tracking-implementation-spec-2026-06-08.md
	// (post-Fix-B sidecar) and at cachetrack.CalibrateEntry.
	CalibrateSink io.Writer
	// calibrateRemaining counts blocks left to emit; decremented
	// atomically per block. Set to CalibrateBlockCap when
	// CalibrateSink is wired; auto-stops when it hits 0.
	calibrateRemaining atomic.Int64

	// Counter surface for §15.3 (c) phase-4 G2/G3 instrumentation.
	// bucketMispredictTotal counts every turn where
	// ReconcilePrediction's bucket(predicted) != bucket(observed)
	// after the skip-bucket exclusion — the rate-blind regression
	// surface (a growth-turn `predicted=Hit observed=Write` would
	// fire here while §10 outcome.Kind stays at Write and
	// MispredictRateGraded sees nothing). Read by the cache-health
	// CLI's `--json` output for the G2 soak gate.
	// triggerMispredictCalls counts the strictly tighter subset
	// where the engine also fires matched.Apply(TriggerMispredict)
	// — i.e. mispredict AND matched != nil. G3 reads this for the
	// entry-demotion-frequency gate.
	bucketMispredictTotal  atomic.Int64
	triggerMispredictCalls atomic.Int64
}

// EngineCounters is the load-bearing surface for phase-4 G2/G3
// gating. Returned by [Engine.Counters] without locking — each
// field is an atomic counter so the surface is consistent under
// concurrent ObserveTurn calls. Read by the cache-health CLI +
// tests; cmd/observer/cache_health.go pairs these with the
// persisted (predicted_kind, kind) pairs to compute G2 on real
// data (the persisted-pair path covers historical data; this
// counter covers a live-process snapshot).
type EngineCounters struct {
	// BucketMispredictTotal is the count of ObserveTurn calls
	// since engine construction whose ReconcilePrediction returned
	// Mispredicted=true (bucket(predicted) != bucket(observed),
	// neither skipped). The §10 rate is STRUCTURALLY blind to a
	// growth-turn regression where this fires but outcome.Kind
	// stays Write/InvalidationRewrite (see c489ddb proof). The G2
	// gate reads this counter, not the rate.
	BucketMispredictTotal int64
	// TriggerMispredictCalls is the subset of
	// BucketMispredictTotal where matched != nil at the time the
	// mispredict fired — i.e. the engine actually demoted an
	// entry via TriggerMispredict. Companion G3 metric; directly
	// measures entry-state churn.
	TriggerMispredictCalls int64
}

// Counters returns a snapshot of the engine's mispredict counters
// for §15.3 (c) phase-4 G2/G3 gating. Lockless — each field is an
// atomic.Load.
func (e *Engine) Counters() EngineCounters {
	return EngineCounters{
		BucketMispredictTotal:  e.bucketMispredictTotal.Load(),
		TriggerMispredictCalls: e.triggerMispredictCalls.Load(),
	}
}

// CalibrateBlockCap is the auto-stop ceiling for the calibrate
// sidecar (per spec §0 R6 — keep the file small + bounded). 200
// blocks ≈ 6 turns of a 30-block-tools-array Claude Code session
// — enough for a useful 2-turn diff without unbounded growth.
const CalibrateBlockCap = 200

// CalibrateTextPrefix is the maximum number of canonical-bytes
// prefix characters emitted for tools+system blocks. Trimmed
// because the diff workflow is "find the lowest-seq block where
// canonical bytes differ" — the operator only needs enough
// context to see WHICH field differs, not the whole block.
// Message-level blocks emit NO prefix (user content; CLAUDE.md
// "no content" Don't).
const CalibrateTextPrefix = 120

// CalibrateEntry is one block's entry in the calibrate sidecar
// log. JSON-Lines: one entry per line; fields are stable so
// `jq` and `sort` over the file work cleanly. Encoded with
// json.NewEncoder(SetEscapeHTML(false)).
type CalibrateEntry struct {
	Timestamp   string `json:"ts"`
	SessionID   string `json:"session_id"`
	APITurnID   int64  `json:"api_turn_id,omitempty"`
	Seq         int    `json:"seq"`
	Level       string `json:"level"`
	Kind        string `json:"kind"`
	LenRaw      int    `json:"len_raw"`
	ShaRaw      string `json:"sha_raw"`
	LenCanon    int    `json:"len_canon"`
	ShaCanon    string `json:"sha_canon"`
	CanonPrefix string `json:"canon_prefix,omitempty"`
}

// engineSessionKey scopes per-session state by (SessionID, Model,
// CacheScope) since spec §6 entry identity is keyed on those
// three. Two agents in one workspace through one proxy share the
// same scope and CAN share entries (that's a feature, not a bug).
type engineSessionKey struct {
	SessionID string
	Model     string
	Scope     string
}

// sessionState wraps a CacheModel with the per-session mutex and
// last-touch timestamp the LRU sweeper consults.
type sessionState struct {
	mu        sync.Mutex
	model     *CacheModel
	lastTouch time.Time
}

// NewEngine returns an Engine bound to the given session cap.
// maxSessions ≤ 0 disables LRU eviction.
func NewEngine(maxSessions int) *Engine {
	return &Engine{
		sessions:    make(map[engineSessionKey]*sessionState),
		maxSessions: maxSessions,
		Clock:       time.Now,
	}
}

// EnableCalibrateSink wires the per-block diagnostic sidecar and
// seeds the auto-stop counter at CalibrateBlockCap. Idempotent —
// calling twice resets the counter (lets a re-enable after the
// cap surface a fresh window without re-constructing the Engine).
// Pass io.Discard to disable without nilling the sink.
func (e *Engine) EnableCalibrateSink(w io.Writer) {
	e.CalibrateSink = w
	e.calibrateRemaining.Store(CalibrateBlockCap)
}

// ObserveBlock is one block of a per-turn observation handed to
// the Engine. The proxy populates these from a single pass over
// the request body (Tier 1); adapters populate Tier-2 equivalents
// via [models.CacheTurnObservation]. The engine canonicalizes
// internally — adapters do NOT canonicalize (operator design
// decision after C7: engine owns canonicalization as the single
// boundary site).
type ObserveBlock struct {
	Level          BlockLevel
	Kind           string
	CanonicalBytes []byte
	Role           string
	// RawBytes carries the pre-canonicalize source bytes for
	// this block — for Tier-1 these are the verbatim
	// json.RawMessage slice extracted from reqShapeBody; for
	// Tier-2 the adapter's emitted raw block JSON. Used ONLY
	// by the calibrate-log sidecar (config
	// [cachetrack].calibrate_log_path) to distinguish "source
	// drifted" from "canonicalize drifted" — the chain hash
	// path NEVER reads RawBytes. Leave nil when the calibrate
	// sidecar is off; the engine handles either shape.
	RawBytes []byte
	// MarkerPresent indicates that this block carries an
	// explicit cache_control marker (Tier-1 only). Tier-2
	// leaves it false. (assumedBreakpoints holds the Tier-2
	// breakpoint model, but the engine does not consume it yet.)
	MarkerPresent bool
	// TTL is the marker's TTL tier when MarkerPresent=true;
	// otherwise unset.
	TTL BlockTTL
}

// ObserveInput is the seam type the proxy (Tier 1) and the
// store-side ingest (Tier 2) hand to [Engine.ObserveTurn]. Per
// §24.2 it is the ONLY cachetrack type that may appear in the
// proxy or store call sites.
type ObserveInput struct {
	// Identity.
	SessionID string
	Model     string
	Scope     string
	Tier      Tier
	MessageID string
	Now       time.Time

	// Caps gates the §7 attribution rules that depend on
	// Tier-1-only visibility. Set via CapabilitiesFor(Tier) at
	// the seam boundary.
	Caps Capabilities

	// Per-turn signals.
	Fast           bool
	CompactionSeen bool

	// HandoffMarker flags that this turn's request / transcript
	// content carries the session-handoff marker
	// (`superbased-handoff <id>`). Threaded into AttributeInput so
	// the first turn of a handoff TARGET session attributes as
	// cause=handoff_rehydration instead of plain reanchor. Set at
	// the boundary (proxy parseRequest / store
	// observationToObserveInput); the engine never derives it.
	HandoffMarker bool

	// Blocks is the in-order block sequence for this turn. For
	// Tier-1, the proxy enumerates ALL request body blocks
	// (tools + system + messages, in that order). For Tier-2,
	// the adapter emits the message-chain delta since the last
	// observation.
	Blocks []ObserveBlock

	// Breakpoints (Tier 1 only) names the explicit marker
	// positions in Blocks. Tier-2 leaves this nil. (The
	// assumedBreakpoints model is reserved for Tier-2 and not
	// consumed by the engine yet.) Each Breakpoint's
	// BlockIndex references Blocks[i].
	Breakpoints []ObserveBreakpoint

	// Observed usage from the provider envelope.
	Usage CacheUsageObserved

	// Anchor IDs for persisted rows. Exactly one of these is
	// non-zero per call: APITurnID for tier='proxy', TokenUsageID
	// for tier='transcript' / 'counts'.
	APITurnID    int64
	TokenUsageID int64
}

// ObserveBreakpoint marks one cache_control marker position in
// the request blocks array (Tier 1).
type ObserveBreakpoint struct {
	BlockIndex int
	Level      BlockLevel
	TTL        BlockTTL
}

// CacheUsageObserved is the engine-internal flat shape of the
// per-turn usage envelope. Mirrors [models.CacheUsage] so the
// store-side ingest can copy directly; kept here so the engine
// stays free of models imports beyond what is already documented.
type CacheUsageObserved struct {
	NetInputTokens        int64
	OutputTokens          int64
	CacheReadTokens       int64
	CacheCreationTokens   int64
	CacheCreation1hTokens int64
}

// ObserveResult is what the seam returns to the caller. The
// caller (proxy.insertTurnDetached / store.Ingest) translates
// these into the store row types and persists. cachetrack types
// stop at this boundary.
type ObserveResult struct {
	Segments []SegmentOut
	Entries  []EntryOut
	Events   []EventOut
}

// SegmentOut describes one cache_segments row to persist.
type SegmentOut struct {
	Seq           int
	Level         BlockLevel
	Kind          string
	PrefixHash    string
	TokenEstimate int
	IsBreakpoint  bool
	TTL           BlockTTL
}

// EntryOut describes one cache_entries row to upsert.
type EntryOut struct {
	Level         BlockLevel
	PrefixHash    string
	TokenCount    int64
	TTL           BlockTTL
	State         EntryState
	CreatedAt     time.Time
	LastRefreshAt time.Time
	ExpiresAt     time.Time
}

// EventOut describes one cache_events row to insert. The
// AttributeOutcome shape (Kind, Cause, DivergedSeq, DivergedLevel)
// drives diagnostic columns; tokens come from the usage envelope.
//
// Mispredicted carries the engine's REAL ReconcilePrediction-side
// bucket-mismatch signal (bucket(predicted) != bucket(observed)
// with the skipped-side exclusion). Surfaced here so
// (a) the §15.3 (c) phase-1 baseline goldens can pin the engine's
// own value rather than re-deriving the bucket logic in a parallel
// helper that silently drifts, and
// (b) downstream sinks can persist or roll it up without
// re-computing.
// NOT currently persisted to cache_events (the persisted predicted_kind
// + kind columns let cache-health re-compute via BucketMismatch — same
// answer, no migration required).
type EventOut struct {
	Outcome         AttributeOutcome
	Timestamp       time.Time
	TokensRead      int64
	TokensWritten   int64
	TokensWritten1h int64
	PredictedKind   Kind
	Mispredicted    bool
}

// ObserveTurn is THE single seam every caller uses. Walks the
// per-turn observation through chain accumulation, attribution
// (§7), and entry state transitions (§6); returns the row set the
// caller persists.
//
// §15.3 dispatch: when in.Caps.ImplicitCache is true, routes to
// [Engine.observeImplicit] (reduced attribution for OpenAI /
// OpenAI-compatible providers — see implicit.go) instead of the
// Anthropic decision tree. The two paths share the per-session
// state struct but write to disjoint fields; the engine NEVER
// branches on provider/tier identity, only on the capability.
//
// Concurrency: takes the per-session lock; safe to call from many
// goroutines targeting different (session, model, scope) tuples
// in parallel. Same-key calls serialize.
func (e *Engine) ObserveTurn(in ObserveInput) ObserveResult {
	if in.Now.IsZero() {
		in.Now = e.Clock()
	}
	if in.Tier != TierUnknown && in.Caps == (Capabilities{}) {
		in.Caps = CapabilitiesFor(in.Tier)
	}

	sess := e.getOrCreateSession(in.SessionID, in.Model, in.Scope, in.Now)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	m := sess.model

	// §15.3 implicit-cache dispatch — load-bearing §5 guardrail.
	// Routed BEFORE chain/attribute/reconcile so implicit-cache
	// events never touch any of the Anthropic state machinery
	// (mispredict counters, EMA update, entry creation). Returns
	// its own ObserveResult; sess.lastTouch is updated inside.
	if in.Caps.ImplicitCache {
		return e.observeImplicit(in, sess, m)
	}

	// Apply compaction reset BEFORE chain advances. CompactionSeen
	// is a §7 row 6 trigger AND a chain reset.
	if in.CompactionSeen {
		_ = m.CompactionReset()
	}

	// Sweep expired entries before the attribution prediction so
	// the matched-entry lookup sees state=expired where appropriate.
	_ = m.SweepExpired(in.Now)

	// §15.3 (c)-phase-2: snapshot the prior-turn end-of-chain hash
	// BEFORE pushing this turn's blocks. The exact-match
	// FindByPrefix below uses this snapshot so a continuation turn
	// (whose end-of-turn chain has grown past the prior-turn
	// entry's hash) still locates the matched entry. Without the
	// snapshot the post-push hash never matches an entry created
	// at end-of-T_{n-1}, lookup misses, predictKind falls to the
	// "no matched entry" branch and silently mispredicts every
	// continuation turn — feeding spurious EMA samples + demoting
	// entries via TriggerMispredict. See
	// docs/plans/cachetrack-15.3c-assumedbreakpoints-lookup-plan-2026-06-09.md.
	priorTurnEndHash := m.Chain.PrefixHashHex()

	// Push blocks into the chain in input order; record segment
	// rows at breakpoint positions and at level boundaries; AND
	// compute per-turn SECTION hashes (tools-only, system-only)
	// so §7 rows 4 + 5 can compare turn-over-turn. Section hashes
	// must be a FRESH sha256 over just the level's blocks — the
	// cumulative chain hash accumulates across turns and would
	// always differ even on identical tools/system content
	// (caught the hard way by TestEngine_LevelHash_*).
	out := ObserveResult{}
	toolsHasher := sha256.New()
	systemHasher := sha256.New()
	var sawTools, sawSystem bool
	bpIndex := buildBreakpointIndex(in.Breakpoints)
	for i, b := range in.Blocks {
		hash := m.Chain.Push(Block{
			Level:          b.Level,
			Kind:           b.Kind,
			CanonicalBytes: b.CanonicalBytes,
		})
		switch b.Level {
		case LevelTools:
			toolsHasher.Write(b.CanonicalBytes)
			sawTools = true
		case LevelSystem:
			systemHasher.Write(b.CanonicalBytes)
			sawSystem = true
		}
		bp, isBP := bpIndex.get(i)
		isBoundary := i == len(in.Blocks)-1 || (i+1 < len(in.Blocks) && in.Blocks[i+1].Level != b.Level)
		if isBP || isBoundary {
			seg := SegmentOut{
				Seq:           i,
				Level:         b.Level,
				Kind:          b.Kind,
				PrefixHash:    hexEncode(hash),
				TokenEstimate: EstimateTokens(b.Kind, b.CanonicalBytes),
				IsBreakpoint:  isBP,
			}
			if isBP {
				seg.TTL = bp.TTL
			}
			out.Segments = append(out.Segments, seg)
		}
		e.maybeEmitCalibrateEntry(in, i, b)
	}
	var toolsLevelHash, systemLevelHash string
	if sawTools {
		toolsLevelHash = hex.EncodeToString(toolsHasher.Sum(nil))
	}
	if sawSystem {
		systemLevelHash = hex.EncodeToString(systemHasher.Sum(nil))
	}

	// Build attribution input + the engine's PREDICTION about
	// what the provider will report. Reconciliation (§10)
	// compares the prediction's bucket against the observed
	// outcome's bucket; mispredicts score against the §10
	// health-metric denominator.
	prefixHashHex := m.Chain.PrefixHashHex()
	// Lookup uses the SNAPSHOT (prior-turn end), NOT the post-
	// push hash — the post-push hash names the entry THIS turn
	// would create, not a prior-turn entry to match against.
	matched := m.FindByPrefix(priorTurnEndHash)
	prior := buildPriorSignals(m)
	predictedTokens := estimateNewSuffixTokens(in.Blocks, in.Caps, matched)
	predicted := predictKind(matched, in.Now, prior, predictedTokens, in.Model)
	attrIn := AttributeInput{
		Caps:                  in.Caps,
		Model:                 in.Model,
		Fast:                  in.Fast,
		Now:                   in.Now,
		PrefixHash:            prefixHashHex,
		PrefixTokens:          0, // C9 calibrates; for now leave 0 so row 10 doesn't fire.
		CacheReadTokens:       in.Usage.CacheReadTokens,
		CacheCreationTokens:   in.Usage.CacheCreationTokens,
		CacheCreation1hTokens: in.Usage.CacheCreation1hTokens,
		Compaction:            in.CompactionSeen,
		ToolsLevelHash:        toolsLevelHash,
		SystemLevelHash:       systemLevelHash,
		DivergedSeq:           -1, // Tier-1 detection in §10 reconciliation; placeholder for now.
		BlocksSinceBreakpoint: m.BlocksSinceLastBreakpoint,
		Prior:                 prior,
		MatchedEntry:          matched,
		HandoffMarker:         in.HandoffMarker,
	}
	outcome := Attribute(attrIn)

	// Choose the TTL for entries created/refreshed this turn.
	// Precedence (per ObservedTTL's contract): the request's explicit
	// cache_control marker TTL wins; absent a marker the observed
	// ephemeral_1h usage signal decides; absent both we fall back to the
	// tier default. NOTE: do NOT pass defaultTTLForTier as ObservedTTL's
	// markerTTL — a concrete 5m/1h default short-circuits the usage check
	// and silently pins every proxy entry to one tier (the bug where a
	// 1h-tier Claude Code cache was recorded — and warned about — as 5m).
	markerTTL := breakpointMarkerTTL(in.Breakpoints)
	chosenTTL := ObservedTTL(in.Usage.CacheCreation1hTokens, markerTTL)
	if markerTTL == TTLUnset && in.Usage.CacheCreation1hTokens == 0 {
		chosenTTL = defaultTTLForTier(in.Tier)
	}

	// Apply outcome: create or refresh entry per attribution.
	switch outcome.Kind {
	case KindHit:
		if matched != nil {
			matched.Apply(TriggerRead, in.Now)
			out.Entries = append(out.Entries, entryRowFromState(matched))
		}
	case KindReanchor, KindWrite, KindExpiryRewrite, KindInvalidationRewrite, KindModelSwitchRewrite, KindCompactionReset:
		// Write — create or replace the entry at the current
		// prefix hash. Reanchor is included: the first turn for
		// a (session, model, scope) tuple lands the initial
		// entry alongside the diagnostic event. Compaction-reset
		// likewise: the post-compaction write creates a fresh
		// entry against the new (shorter) chain prefix.
		if prefixHashHex != "" && in.Usage.CacheCreationTokens > 0 {
			ent := &Entry{
				Key: EntryKey{
					Model:      in.Model,
					Scope:      in.Scope,
					PrefixHash: prefixHashHex,
				},
				Level:         finalLevel(in.Blocks),
				SessionID:     in.SessionID,
				TokenCount:    in.Usage.CacheCreationTokens,
				TTL:           chosenTTL,
				Tier:          in.Tier,
				CreatedAt:     in.Now,
				LastRefreshAt: in.Now,
				ExpiresAt:     in.Now.Add(TTLDuration(chosenTTL)),
				State:         StateLive,
				// §15.3 (c)-phase-2 slice anchor: record
				// len(in.Blocks) at creation so the NEXT turn's
				// estimateNewSuffixTokens can slice this turn's
				// in.Blocks down to the new tail (Tier-1
				// cumulative case). Tier-2 delta callers record
				// but never consult — capability gate handles it.
				BlockCount: len(in.Blocks),
			}
			m.AddEntry(ent)
			out.Entries = append(out.Entries, entryRowFromState(ent))
		}
	}

	// Reconcile prediction vs observation (§10). Updates the
	// per-session EMA, surfaces the mispredict signal on the
	// event row, and feeds the matched entry's state machine.
	rec := ReconcilePrediction(
		PredictedShape{Kind: predicted, EstimatedWrittenTokens: predictedTokens},
		ObservedShape{
			Kind:                outcome.Kind,
			ObservedReadTokens:  in.Usage.CacheReadTokens,
			ObservedWriteTokens: in.Usage.CacheCreationTokens,
		},
	)
	if rec.Mispredicted {
		// G2 counter — engine-wide rate-blind regression surface.
		e.bucketMispredictTotal.Add(1)
	}
	if rec.Mispredicted && matched != nil {
		// G3 counter — strictly tighter subset (mispredict +
		// matched != nil = actual entry-state demotion).
		e.triggerMispredictCalls.Add(1)
		// Demote the matched entry to unverified so the next
		// turn either confirms (back to live) or re-classifies it.
		matched.Apply(TriggerMispredict, in.Now)
	}
	if rec.EstimateScale > 0 {
		m.EstimateEMA = UpdateEMA(m.EstimateEMA, rec.EstimateScale)
	}

	// Build the event row. predicted_kind carries the engine's
	// pre-observation guess so reconcile.MispredictRate over
	// persisted events scores §10 honestly. Mispredicted carries
	// the engine's REAL ReconcileResult.Mispredicted for §15.3 (c)
	// phase-1 G2 anchor — read by baseline tests + downstream
	// sinks instead of an external bucket-mismatch helper that
	// would silently drift from bucketOf.
	event := EventOut{
		Outcome:         outcome,
		Timestamp:       in.Now,
		TokensRead:      in.Usage.CacheReadTokens,
		TokensWritten:   in.Usage.CacheCreationTokens,
		TokensWritten1h: in.Usage.CacheCreation1hTokens,
		PredictedKind:   predicted,
		Mispredicted:    rec.Mispredicted,
	}
	out.Events = append(out.Events, event)

	// Update per-session cross-turn signals for the next call.
	// LastToolsLevelHash / LastSystemLevelHash drive §7 rows 4-5
	// on the next observation; empty values are fine (the
	// attribution rule guards against empty hashes).
	m.LastModel = in.Model
	m.LastFast = in.Fast
	m.LastMessageID = in.MessageID
	m.LastTurnAt = in.Now
	m.LastToolsLevelHash = toolsLevelHash
	m.LastSystemLevelHash = systemLevelHash
	sess.lastTouch = in.Now

	return out
}

// getOrCreateSession returns the per-session state, creating it
// if needed and evicting the oldest session when the cap is hit.
func (e *Engine) getOrCreateSession(sessionID, model, scope string, now time.Time) *sessionState {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := engineSessionKey{SessionID: sessionID, Model: model, Scope: scope}
	if s, ok := e.sessions[key]; ok {
		s.lastTouch = now
		return s
	}
	if e.maxSessions > 0 && len(e.sessions) >= e.maxSessions {
		// Evict oldest.
		var oldestKey engineSessionKey
		var oldestTouch time.Time
		first := true
		for k, s := range e.sessions {
			if first || s.lastTouch.Before(oldestTouch) {
				oldestKey = k
				oldestTouch = s.lastTouch
				first = false
			}
		}
		delete(e.sessions, oldestKey)
	}
	s := &sessionState{
		model:     NewCacheModel(),
		lastTouch: now,
	}
	e.sessions[key] = s
	return s
}

// predictKind generates the engine's pre-observation guess about
// the upcoming turn's Kind, used by [ReconcilePrediction] to
// score §10 mispredicts. The §15.3 (c)-phase-2 fix adds the
// CacheableTokens-gated branch between "matched live" and the
// no-prior-match fallthrough:
//
//   - No prior → KindReanchor (denominator-excluded; first turn
//     for a session has nothing to predict against).
//   - Matched live entry + the new tail is cacheable-sized for
//     this model → KindWrite (growth case — provider will write
//     a new cache_creation past the marker).
//   - Matched live entry + new tail below min-cacheable → KindHit
//     (continuation case — no new cache write expected, provider
//     reads the matched prefix).
//   - Otherwise → KindWrite (no matched entry; something will
//     land as a new entry).
//
// The split between the two matched-live branches is what closes
// §15.3 (c) the right way. Pre-fix the predict was Hit for every
// matched-live turn, which is correct for continuation but wrong
// for growth — and on real Tier-1 Sonnet most matched-live turns
// are growth. The CacheableTokens gate uses predictedNewTokens
// (estimateNewSuffixTokens output) as a proxy for "did the new
// tail cross a cache_control marker placement threshold?" That
// proxy is approximate — see the boundary residual call-out
// below — but it correctly separates growth-shape from
// continuation-shape on representative content sizes.
//
// BOUNDARY RESIDUAL (acknowledged trade-off): predictedNewTokens
// uses estimateNewSuffixTokens's v1 byte→token heuristic.
// Turns whose actual new-tail tokens sit NEAR the
// MinCacheableTokens(model) threshold may estimate on the wrong
// side and produce a spurious bucket-level mispredict
// (rec.Mispredicted = true with no observable §10-rate impact,
// since outcome.Kind stays Write/Hit). SessionEMA scaling refines
// the estimate over time; full closure is §15.3 (c)-phase-2
// (walkback / rolling-entry refresh for consecutive-Hit
// sequences). A future debugger investigating "why did this
// boundary turn mispredict?" — this is the residual, not a
// phantom bug.
func predictKind(matched *Entry, now time.Time, prior *PriorSignals, predictedNewTokens int64, model string) Kind {
	if prior == nil {
		return KindReanchor
	}
	if matched != nil && matched.State == StateLive && now.Before(matched.ExpiresAt) {
		if CacheableTokens(model, int(predictedNewTokens)) {
			return KindWrite
		}
		return KindHit
	}
	return KindWrite
}

// estimateNewSuffixTokens approximates the per-byte token count
// the provider will charge for cache_creation on the NEW tail of
// this turn — the suffix past the matched entry's prefix.
//
// Slice anchor: the matched entry's BlockCount records
// len(in.Blocks) AT ITS CREATION TURN. Because Tier-1 (proxy)
// always passes the full Anthropic request body (cumulative
// conversation), the next turn's in.Blocks at the same scope
// grows monotonically and the new tail is in.Blocks[BlockCount:].
//
// Why not m.Chain.Count() instead of matched.BlockCount: the
// Chain accumulates across EVERY Push regardless of cumulative
// vs delta semantics (chain.go::Push increments c.n monotonically
// and Reset only fires on compaction). For Tier-1 by turn-3 the
// Chain.Count() snapshot before push diverges from the new turn's
// len(in.Blocks): a guard like `priorChainCount < len(blocks)`
// silently falls back to `start=0` and sums the entire cumulative
// in.Blocks → CacheableTokens(model, ~thousands) always true →
// always predict Write → no-op fix. BlockCount-on-matched-entry
// is the correct anchor because it's measured in the same units
// as the slice (in.Blocks block indices, not chain pushes).
//
// Capability gate: only consult BlockCount when the caller passes
// cumulative blocks (Tier-1 proxy via the API request body).
// Tier-2 delta callers (the transcript adapters) already pass the
// per-turn tail in in.Blocks — slicing would produce the wrong
// answer (out-of-range start when delta is shorter than matched
// BlockCount). The capability is set at the engine boundary via
// CapabilitiesFor(Tier) and consumed here as in.Caps.
func estimateNewSuffixTokens(blocks []ObserveBlock, caps Capabilities, matched *Entry) int64 {
	start := 0
	if caps.BlocksAreCumulative && matched != nil && matched.BlockCount > 0 && matched.BlockCount < len(blocks) {
		start = matched.BlockCount
	}
	var total int64
	for _, b := range blocks[start:] {
		total += int64(EstimateTokens(b.Kind, b.CanonicalBytes))
	}
	return total
}

// buildPriorSignals captures cross-turn signals for §7 attribution.
// Returns nil when no prior turn has been observed for this session.
func buildPriorSignals(m *CacheModel) *PriorSignals {
	if m.LastTurnAt.IsZero() {
		return nil
	}
	return &PriorSignals{
		Model:           m.LastModel,
		Fast:            m.LastFast,
		ToolsLevelHash:  m.LastToolsLevelHash,
		SystemLevelHash: m.LastSystemLevelHash,
	}
}

// entryRowFromState produces an EntryOut from an Entry. Caller
// translates to store.CacheEntryRow at the boundary.
func entryRowFromState(e *Entry) EntryOut {
	return EntryOut{
		Level:         e.Level,
		PrefixHash:    e.Key.PrefixHash,
		TokenCount:    e.TokenCount,
		TTL:           e.TTL,
		State:         e.State,
		CreatedAt:     e.CreatedAt,
		LastRefreshAt: e.LastRefreshAt,
		ExpiresAt:     e.ExpiresAt,
	}
}

// finalLevel returns the level of the last block in the input.
// Used to stamp the entry created when a write outcome fires.
func finalLevel(blocks []ObserveBlock) BlockLevel {
	if len(blocks) == 0 {
		return LevelUnknown
	}
	return blocks[len(blocks)-1].Level
}

// defaultTTLForTier returns the engine's default TTL when no
// usage signal arrives. Per R1(a): Claude Code is 1h-by-default;
// other clients fall through to the provider's 5m default until
// they have their own measured equivalent.
//
// Tier is the dispatcher: Tier 2 (transcript) without a
// CacheCreation1h signal still defaults to 1h IF the
// traffic-tool-of-record is Claude Code (the engine doesn't know
// the tool name directly; the caller's choice of Tier already
// encodes it). For now: any Tier-2 transcript → 1h default,
// matching the only Tier-2-emitting adapter (claudecode) in P0.
// Codex/OpenCode Tier-2 rollout in P2 will widen this if their
// R1(a)-equivalent measurements differ.
func defaultTTLForTier(t Tier) BlockTTL {
	switch t {
	case TierTranscript:
		return TTL1h
	default:
		return TTL5m
	}
}

// breakpointMarkerTTL resolves the dominant explicit cache_control
// marker TTL from a turn's breakpoints, returning TTLUnset when no
// breakpoint carried an explicit ttl. A request's markers share a tier
// in practice (Claude Code stamps a uniform ttl across its breakpoints),
// but if they ever diverge the longer-lived 1h tier dominates — it is
// the TTL of the prefix we most want to keep warm. This is the request
// signal ("what we asked for") that ObservedTTL prefers over the usage
// signal ("what landed").
func breakpointMarkerTTL(bps []ObserveBreakpoint) BlockTTL {
	out := TTLUnset
	for _, bp := range bps {
		switch bp.TTL {
		case TTL1h:
			return TTL1h
		case TTL5m:
			out = TTL5m
		}
	}
	return out
}

// breakpointIndex is a small helper map: block-index → Breakpoint.
type breakpointIndex map[int]ObserveBreakpoint

func buildBreakpointIndex(bps []ObserveBreakpoint) breakpointIndex {
	if len(bps) == 0 {
		return nil
	}
	out := make(breakpointIndex, len(bps))
	for _, bp := range bps {
		out[bp.BlockIndex] = bp
	}
	return out
}

func (b breakpointIndex) get(i int) (ObserveBreakpoint, bool) {
	bp, ok := b[i]
	return bp, ok
}

// breakpointIndex's bool lookup is via map presence: ranging over
// b[i] returns the value AND ok. The `_ = ok` shape is used at
// call sites where we only care about presence.
//
//revive:disable-next-line:unused-receiver
var _ = breakpointIndex(nil).get

// maybeEmitCalibrateEntry writes one JSON-Lines entry to the
// calibrate sidecar when wired and the auto-stop counter still
// has budget. Tools+system blocks carry a bounded canonical-bytes
// prefix (first CalibrateTextPrefix chars) so the operator can
// SEE what differs in one pass; message-level blocks emit
// hash-only (CLAUDE.md "no content in the DB / logs"). RawBytes
// are hashed when present to distinguish "source drift" from
// "canonicalize drift" — when sha_raw differs across turns at
// the same seq, the upstream is the culprit; when sha_raw matches
// but sha_canon differs, canonicalize is the regression.
//
// All write errors are swallowed: the sidecar is a diagnostic
// surface, not a correctness path; a closed file or full disk
// must NEVER fail the hot path.
func (e *Engine) maybeEmitCalibrateEntry(in ObserveInput, i int, b ObserveBlock) {
	if e.CalibrateSink == nil {
		return
	}
	if e.calibrateRemaining.Add(-1) < 0 {
		return
	}
	entry := CalibrateEntry{
		Timestamp: in.Now.UTC().Format(time.RFC3339Nano),
		SessionID: in.SessionID,
		APITurnID: in.APITurnID,
		Seq:       i,
		Level:     b.Level.String(),
		Kind:      b.Kind,
		LenRaw:    len(b.RawBytes),
		LenCanon:  len(b.CanonicalBytes),
	}
	if len(b.RawBytes) > 0 {
		sum := sha256.Sum256(b.RawBytes)
		entry.ShaRaw = hex.EncodeToString(sum[:])
	}
	if len(b.CanonicalBytes) > 0 {
		sum := sha256.Sum256(b.CanonicalBytes)
		entry.ShaCanon = hex.EncodeToString(sum[:])
	}
	if b.Level == LevelTools || b.Level == LevelSystem {
		entry.CanonPrefix = truncatePrefix(b.CanonicalBytes, CalibrateTextPrefix)
	}
	enc := json.NewEncoder(e.CalibrateSink)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(entry)
}

// truncatePrefix returns up to n bytes of b as a string. Stops
// at the first invalid UTF-8 byte to avoid corrupting JSON output.
// Tools+system canonical bytes are JSON text — always valid UTF-8
// — so this is a defensive guard, not a hot-path constraint.
func truncatePrefix(b []byte, n int) string {
	if n <= 0 || len(b) == 0 {
		return ""
	}
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n])
}

// observeImplicit is the §15.3 implicit-cache dispatch path —
// reduced attribution for OpenAI / OpenAI-compatible providers
// that emit only a scalar cached_tokens count, no markers, no
// TTL signal, no separate write count.
//
// Disjoint from the Anthropic path: does NOT touch the chain,
// does NOT consult predictKind / estimateNewSuffixTokens, does
// NOT update m.EstimateEMA, does NOT increment the §10 G2/G3
// mispredict counters, does NOT create any [Entry] (the implicit
// cache has no marker-level identity to anchor entries against).
//
// What it DOES:
//   - Read m.ImplicitPrefixTokens + m.ImplicitObserved as the
//     per-session prior state.
//   - Compute an estimated current-prefix-tokens from the input
//     (proxy passes Usage.NetInputTokens; codex Tier-2 passes the
//     scalar via in.Usage.CacheReadTokens — the band-check still
//     runs but lower fidelity).
//   - Drive [attributeImplicit] → AttributeOutcome.
//   - Drive [predictImplicitKind] → predicted Kind.
//   - Emit one [EventOut] with the result.
//   - Update m.ImplicitPrefixTokens to the post-turn estimate
//     (granule-quantized) + m.ImplicitObserved = true.
//
// The emitted Kind is in {KindImplicitHit, KindImplicitMiss,
// KindImplicitWrite, KindBelowMin}; all are routed to bucketSkipped
// by [bucketOf] + isRateSkipped by [isRateSkipped], so the §10
// Anthropic gate is PROVABLY UNMOVED by these events.
//
// Concurrency: caller already holds sess.mu.
func (e *Engine) observeImplicit(in ObserveInput, sess *sessionState, m *CacheModel) ObserveResult {
	obs := ImplicitObservation{
		Model:                in.Model,
		PriorObserved:        m.ImplicitObserved,
		PriorPrefixTokens:    m.ImplicitPrefixTokens,
		ObservedCachedTokens: in.Usage.CacheReadTokens,
		// HandoffMarker threads the boundary's raw-body / block scan
		// through so a handoff TARGET's bootstrap turn attributes as
		// cause=handoff_rehydration instead of plain reanchor
		// (ruleImplicitHandoffRehydration self-gates on !PriorObserved,
		// so a marker persisting into later turns is inert). Mirrors
		// the Anthropic lane's AttributeInput.HandoffMarker.
		HandoffMarker: in.HandoffMarker,
		// PromptCacheKeyOverflow is wired-but-inert today; the proxy
		// doesn't yet detect prompt_cache_key rolls. Future-proofed.
		PromptCacheKeyOverflow: false,
	}
	outcome := attributeImplicit(obs)
	predicted := predictImplicitKind(obs)

	event := EventOut{
		Outcome:    outcome,
		Timestamp:  in.Now,
		TokensRead: in.Usage.CacheReadTokens,
		// OpenAI implicit caching classically reports no separate write
		// count, so this stayed 0. The GPT-5.6 metered API-key lane DOES
		// surface cache_write_tokens (parsed at internal/proxy into
		// CacheCreationTokens), so thread it through here when present:
		// it is 0 on the ChatGPT-plan lane (unchanged behaviour) and the
		// real count on a metered turn, so the persisted cache_events row
		// (and every downstream write consumer — dashboard efficiency,
		// advisor, cachewarm value-at-risk) stops underreporting writes.
		// TokensWritten1h stays 0: OpenAI writes are untiered, no 1h subset.
		TokensWritten:   in.Usage.CacheCreationTokens,
		TokensWritten1h: 0,
		PredictedKind:   predicted,
		// Mispredicted: the §10 g2/g3 surface is Anthropic-only.
		// Implicit-cache predicted vs observed mismatches surface
		// on the SEPARATE ImplicitCacheConsistency metric, NOT here.
		// Leaving Mispredicted=false keeps the G2 counter clean.
		Mispredicted: false,
	}

	// Update per-session implicit state.
	// Estimated current-prefix-tokens = observed cached_tokens
	// quantized to 128-token granules. On bootstrap (no observed
	// cache yet) we seed from NetInputTokens as a best-effort
	// floor — the next turn refines.
	newPrefix := QuantizeToGranule(in.Usage.CacheReadTokens, OpenAIPrefixGranule)
	if newPrefix == 0 && in.Usage.NetInputTokens > 0 {
		// Seed from observed input on the bootstrap turn so the
		// next turn's prior-prefix estimate isn't zero. Still
		// granule-quantized.
		newPrefix = QuantizeToGranule(in.Usage.NetInputTokens, OpenAIPrefixGranule)
	}
	m.ImplicitPrefixTokens = newPrefix
	m.ImplicitObserved = true
	m.LastModel = in.Model
	m.LastFast = in.Fast
	m.LastMessageID = in.MessageID
	m.LastTurnAt = in.Now
	sess.lastTouch = in.Now

	return ObserveResult{
		Events: []EventOut{event},
		// No Segments, no Entries — implicit cache has no marker-
		// level identity to anchor either against. cache_segments
		// + cache_entries stay Anthropic-only; the persisted
		// cache_events row carries kind/cause/tokens_read (+
		// tokens_written when the GPT-5.6 metered lane reports it)
		// for the implicit-cache surface.
	}
}

// hexEncode is a small local helper so engine.go doesn't have to
// import encoding/hex twice. Inlines the chain's PrefixHashHex
// path's output.
func hexEncode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hexChars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexChars[v>>4]
		out[i*2+1] = hexChars[v&0x0f]
	}
	return string(out)
}
