package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/processobs"
)

// Sink is the write side of the proxy — the store layer implements this so
// the proxy package doesn't depend on *sql.DB. In production this is
// (*store.Store).InsertAPITurn.
type Sink interface {
	InsertAPITurn(ctx context.Context, t models.APITurn) (int64, error)
}

// CacheSink, when non-nil on [Options], receives one
// PersistCacheObservation call per turn for which the proxy ran
// cache observation (cacheEngine != nil + Anthropic provider).
// The store implements it as a wrapper around its
// InsertCacheSegments / UpsertCacheEntries / InsertCacheEvents
// helpers; tests can pass nil to compute-but-not-persist. Per
// §24.2 only cachetrack ObserveInput/ObserveResult appear in
// this signature — the proxy never holds row-shaped types.
//
// Exactly one of apiTurnID / tokenUsageID is non-zero. The
// proxy passes (apiTurnID, 0); the store-side Tier-2 backfill
// path (which also implements this interface via the same Store
// method) passes (0, tokenUsageID). A zero apiTurnID on the
// proxy path means the upstream insert failed and the caller
// should drop the cache rows (WARN, do not retry).
type CacheSink interface {
	PersistCacheObservation(ctx context.Context, in cachetrack.ObserveInput, result cachetrack.ObserveResult, apiTurnID, tokenUsageID int64) error
}

// LimitSink, when non-nil on [Options], receives one InsertLimitSnapshot
// call per upstream response that carried at least one rate-limit /
// subscription-window header (the Next-Message Cost & Limit Predictor's
// limit half). The store implements it as (*store.Store).
// InsertLimitSnapshot. Optional — nil disables limit capture entirely,
// leaving the predictor's cost half unaffected. The snapshot is a plain
// models row (same shape contract as [Sink].InsertAPITurn).
type LimitSink interface {
	InsertLimitSnapshot(ctx context.Context, snap models.LimitSnapshot) error
}

// SessionResolver maps an incoming TCP connection's remote address
// ("127.0.0.1:54321") onto a host-tool session_id. The proxy calls it
// only when the request did not carry an X-Session-Id header — useful
// for Claude Code and Codex which don't set one. A clean miss
// (`ok=false`, nil error) is not an error; the proxy just stores a NULL
// session_id the way it always has. In production this is
// (*pidbridge.ProcResolver).Resolve.
type SessionResolver interface {
	Resolve(ctx context.Context, remoteAddr string) (sessionID string, ok bool, err error)
}

// ToolResolver is the optional [SessionResolver] extension reporting
// which AI tool owns the connection (the pidbridge Entry's Tool field,
// written by the SessionStart hook). Consumed ONLY as routing input
// for the compression profile router's per-tool assignments (Track R,
// R2) — proxy behavior never branches on the tool string itself
// (capability rule). A clean miss ("", ok=false, nil error) degrades
// resolution to the per-provider assignment tier. In production this
// is (*pidbridge.ProcResolver).ResolveTool, which shares Resolve's
// per-addr cache so calling both costs one /proc walk.
type ToolResolver interface {
	ResolveTool(ctx context.Context, remoteAddr string) (tool string, ok bool, err error)
}

// CWDResolver is the optional [SessionResolver] extension reporting
// the working directory the owning tool's session started in (the
// pidbridge Entry's CWD). Routing input for per-project compression
// overrides (Track R, R3) — same capability rules and miss semantics
// as [ToolResolver]; shares the same resolver cache in production.
type CWDResolver interface {
	ResolveCWD(ctx context.Context, remoteAddr string) (cwd string, ok bool, err error)
}

// Compressor is the optional pre-forward hook the proxy runs on a request
// body (spec §10 Layer 3). Implementations MUST return a body that's safe
// to forward upstream — scrubbed, provider-shape-preserving, and no larger
// than the input. The stats land on models.APITurn and observer_log.
//
// In production the implementation is
// (*conversation.Pipeline).Compress (wrapped to adapt the method set).
// Interface-typed so proxy tests can stub compression without importing
// the conversation package.
type Compressor interface {
	Compress(ctx context.Context, provider string, body []byte) CompressionResult
}

// SessionAwareCompressor is the v1.4.42 extension: when the proxy has
// already extracted the request's session_id (Anthropic Pro/Max OAuth
// path) it passes it through so session-scoped features can fire
// (D20 rolling summaries, C16 read-cache auto-substitution). The base
// Compressor interface stays for backward compat with simpler callers
// and tests.
type SessionAwareCompressor interface {
	Compressor
	CompressInSession(ctx context.Context, provider string, body []byte, sessionID string) CompressionResult
}

// RequestClass carries the routing inputs the compression profile
// router resolves a parameter set from (Track R): the provider class
// (R1, from the URL path), the connection's owning tool (R2,
// pidbridge), and that tool's session working directory (R3, project
// overrides). Tool and CWD are best-effort — "" skips their
// resolution tiers.
type RequestClass struct {
	Provider string
	Tool     string
	CWD      string
}

// ClassAwareCompressor is the Track-R extension of
// [SessionAwareCompressor]: the proxy passes the full [RequestClass]
// so the profile router can honor per-tool assignments and
// per-project overrides ahead of per-provider ones. The class fields
// are advisory routing input only — implementations must not vary
// content on them beyond selecting the resolved parameter set.
type ClassAwareCompressor interface {
	SessionAwareCompressor
	CompressInSessionClass(ctx context.Context, class RequestClass, body []byte, sessionID string) CompressionResult
}

// CompressionResult is the output of [Compressor.Compress].
type CompressionResult struct {
	// Body is the body to forward. When Skipped, callers MUST forward the
	// original body — a nil/empty Body with Skipped=false is treated as
	// "compression failed; fall back to original".
	Body []byte
	// Skipped is true when the compressor did not modify the input.
	Skipped bool
	// MessagePrefixHash is the cache-aligned prefix identifier landed on
	// [models.APITurn.MessagePrefixHash].
	MessagePrefixHash string
	// OriginalBytes / CompressedBytes are the before/after sizes used by
	// observer_log and the dashboard.
	OriginalBytes   int
	CompressedBytes int
	// CompressedCount / DroppedCount / MarkerCount expose per-turn
	// counters for Step 11 savings metrics.
	CompressedCount int
	DroppedCount    int
	MarkerCount     int
	// Events is the per-decision compression detail (one record per
	// compress or drop). Persisted alongside the api_turn into the
	// compression_events table by the store layer; empty when the
	// pipeline skipped.
	Events []CompressionEvent
}

// CompressionEvent is one mechanism-tagged compression decision.
// Mirrors conversation.Event but defined here so the proxy contract
// stays import-cycle-free.
type CompressionEvent struct {
	Mechanism       string // 'json' | 'code' | 'logs' | 'text' | 'diff' | 'html' | 'drop'
	OriginalBytes   int
	CompressedBytes int
	MsgIndex        int
	ImportanceScore float64 // set only for 'drop'
	BodyHash        string  // sha256-hex of pre-compression body (V7-9)
}

// CostComputer turns a (model, token-bundle) pair into a USD cost for
// the api_turns.cost_usd column. Optional — nil means the proxy
// records turns without a cost (downstream readers compute it on the
// fly via the cost engine). When set, the proxy populates cost_usd at
// insert time so `observer cost` and CLI scripts that sum the column
// directly (scripts/ab-claude-report.sh, etc.) see real numbers
// without re-implementing pricing in shell. In production this is a
// thin adapter over (*cost.Engine).ComputeAt.
type CostComputer interface {
	Compute(model string, tokens CostTokens) (usd float64, ok bool)
}

// CostTokens mirrors cost.TokenBundle but is duplicated here so the
// proxy contract stays free of an import cycle into the intelligence
// package. Field names and meaning match TokenBundle exactly.
type CostTokens struct {
	Input           int64
	Output          int64
	CacheRead       int64
	CacheCreation   int64
	CacheCreation1h int64
	// Fast carries the turn's fast-tier flag so the cost computer can
	// apply the FastMultiplier premium (Anthropic Opus 4.8 speed:"fast"
	// = 2×). Without this the proxy would store the standard cost on a
	// fast turn and the dashboard's recorded cost would understate the
	// real spend by 2×.
	Fast bool
	// At is the turn's wall-clock timestamp, used by the cost computer
	// to resolve time-of-day-dependent rates such as peak/off-peak.
	// Zero means resolve at current/flat rates.
	At time.Time
}

// VirtualKeySource supplies the org-issued AI Gateway virtual key
// (sbo-vk-…) used for Sol S2 auth-substitution when Gateway Mode is
// active (docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md
// §2.3). In production this is a thin adapter over the node's
// orgclient.BearerStore third slot (SaveVirtualKey/LoadVirtualKey) — bound
// at the orgclient wiring point in cmd/observer so internal/proxy never
// imports internal/orgclient, the same seam pattern as CostComputer for
// internal/intelligence and Admitter/EgressReporter for internal/obs.
type VirtualKeySource interface {
	// LoadVirtualKey returns the currently stored virtual key and the
	// routing generation it was minted under. An error (typically
	// orgclient.ErrNoSecret when Gateway Mode has not been provisioned
	// locally yet) means the proxy has no usable credential for the
	// gateway leg — the caller MUST fail closed rather than forward the
	// developer's own provider credential or silently fall back to a
	// direct-provider destination.
	LoadVirtualKey() (key string, generation uint64, err error)
}

// Options configures a Proxy.
type Options struct {
	// AnthropicUpstream is the base URL for Anthropic requests. Must be an
	// absolute URL with a scheme. Typical: https://api.anthropic.com.
	AnthropicUpstream string
	// OpenAIUpstream is the base URL for OpenAI-compatible requests. Typical:
	// https://api.openai.com.
	OpenAIUpstream string
	// ChatGPTUpstream is the base URL for ChatGPT-plan Codex backend requests.
	// Typical: https://chatgpt.com.
	ChatGPTUpstream string
	// GeminiUpstream is the base URL for Google Gemini generateContent
	// requests. Typical: https://generativelanguage.googleapis.com.
	GeminiUpstream string
	// Upstreams maps a routing id to an upstream base URL, selected
	// per-request via a `/up/<id>/` path prefix (Phase C). Lets a routed
	// tool whose traffic must reach a non-default host (e.g. hermes →
	// OpenRouter) point its base URL at http://127.0.0.1:<port>/up/<id>/v1.
	// Each value is the host root WITHOUT a version suffix (mirrors the
	// fixed upstreams). Empty/unset → only the fixed three upstreams exist
	// (fail-open). LOCAL-ONLY config; never distributed.
	Upstreams map[string]string
	// AutoDefaultLane names the [proxy.upstreams] lane id the virtual
	// "auto" /up/auto/<path> lane (Phase 2, gateway config plane spec)
	// forwards to when the request's top-level model carries no matching
	// lane-id prefix (no "/", no match, or an empty/unparseable model —
	// e.g. a GET). Config: [proxy].auto_default_lane, validated to name a
	// configured upstream when set. Empty means no default: an
	// unresolvable auto-lane request falls through exactly like an
	// unknown /up/<id> id (fixed upstream, warn-once). See resolveAutoLane.
	AutoDefaultLane string
	// ForceChatGPTHTTP rejects ChatGPT backend websocket upgrades so Codex falls
	// back to HTTPS POST, which is the path Observer can currently compress.
	ForceChatGPTHTTP bool
	// Sink receives one APITurn per request. Required.
	Sink Sink
	// Compressor is optional. When non-nil, it runs before the request
	// body is forwarded upstream. Must preserve the request's JSON
	// envelope. See [Compressor].
	Compressor Compressor

	// Admitter is the optional pre-forward input-admission gate
	// (admission spec §6.2). nil ⇒ disabled. Bound at the obs wiring
	// point so internal/proxy never imports internal/obs. See [Admitter].
	Admitter Admitter
	// EgressReporter is the optional proxy→obs realized-outcome callback for
	// Plane-A egress routes (G22 wave 2). nil ⇒ no callback. Bound at the obs
	// wiring point so internal/proxy never imports internal/obs. See
	// [EgressReporter].
	EgressReporter EgressReporter
	// VirtualKeySource supplies the AI Gateway virtual key for Sol S2
	// auth-substitution. nil ⇒ Gateway Mode requests fail closed (a local
	// 502 error, never a forwarded developer credential). Only consulted
	// when the installed org-route (SetOrgGatewayRoute) is in
	// orgModeGateway; a build with no org-route installed never touches
	// this field. Bound at the orgclient wiring point so internal/proxy
	// never imports internal/orgclient. See [VirtualKeySource].
	VirtualKeySource VirtualKeySource
	// GatewayFleetAlerter, when non-nil, receives one GatewayLadderAlert each
	// time the Gateway-Mode fallback ladder exhausts every configured endpoint
	// and applies its terminal policy (queue-and-hold, break-glass-unavailable,
	// or custody-downgrading direct fallback — Luna L16). It is the "raise a
	// fleet alert" signal from the design's terminal-policy contract. nil (the
	// default) leaves the ladder behavior byte-identical except for a nil
	// check; the executor always also logs at Warn. Bound at the daemon
	// composition point (dashboard / org-client), never imported by
	// internal/proxy directly. See [GatewayFleetAlerter].
	GatewayFleetAlerter GatewayFleetAlerter
	// AdmissionUserHeader names the request header the admission gate reads
	// the end-user identity from (org-hosted-app model). Empty ⇒ no per-end-
	// user identity is threaded from the proxy path.
	AdmissionUserHeader string
	// CostComputer is optional. When non-nil, the proxy populates
	// APITurn.CostUSD before insertion using this computer. See
	// [CostComputer].
	CostComputer CostComputer
	// ObserverLog, when non-nil, receives one entry per compressed
	// request describing the savings. Optional. In production this is
	// adapted from (*store.Store).InsertObserverLog.
	ObserverLog ObserverLogSink
	// SessionResolver, when non-nil, is consulted to fill in session_id
	// on requests that don't send an X-Session-Id header. Optional.
	SessionResolver SessionResolver
	// Logger receives operational messages. Defaults to a discard logger.
	Logger *slog.Logger
	// Client overrides the upstream HTTP client. Defaults to a client with
	// no response timeout (SSE streams can run for minutes) but a short dial
	// timeout so `proxy start` fails fast when the network is down.
	Client *http.Client
	// Clock overrides time.Now for tests. Defaults to time.Now.
	Clock func() time.Time
	// PostCompactInjector, when non-nil, gates the v1.4.43+ / Tier 3 /
	// D23 compaction-survival feature: on Anthropic requests whose
	// session_id has a recent compaction event in the observer DB, the
	// proxy prepends a synthetic system block carrying recovery context
	// (last reads, last edits, recent failures, learned rules) so the
	// model can re-orient without paying for a re-Read of every file.
	// Cross-turn invariance: the injected content is byte-stable per
	// compaction event, so Anthropic's prefix cache hits hold across
	// every turn of the post-compact conversation.
	PostCompactInjector PostCompactInjector
	// AuthCache, when non-nil, captures the Authorization /
	// x-api-key headers of every Anthropic request before the
	// compressor runs (D20 / Tier 2 — live API wire-up). The
	// rolling-summ summariser pulls credentials from this cache so
	// the per-session summary call rides the same auth as the user's
	// regular request. Optional — without it, rolling summarisation
	// no-ops (the framework's safety contract).
	AuthCache AuthCache
	// PrewarmTargets are URLs the proxy fires a no-op GET against at
	// startup to populate the http.Transport connection pool with
	// warm TLS sessions. V6-3 mitigation: the first real proxy
	// request reuses the pooled connection, saving the 500ms-1.5s
	// TLS handshake delay that pushed codex's inner-pipe TTFB past
	// its ~15s timeout. Empty list disables pre-warm. Defaults are
	// set by cmd/observer/start.go from [proxy].prewarm_targets in
	// config.toml. See docs/observer-platform-issues-v6.md §V6-3.
	PrewarmTargets []string
	// CompressTypes mirrors `[compression.conversation] compress_types`.
	// Used by the V7-2 codex-variant warning: when the proxy sees an
	// OpenAI request whose model matches the codex-variant family
	// (anything matching the `(?i)(?:^codex-|-codex(?:-|$))` regex)
	// AND CompressTypes is non-empty, observer emits one stderr
	// warning per session pointing the operator at
	// `docs/codex-compression-recipe.md`. Empty / nil disables the
	// warning. Optional — leaving it unset is the test-only path.
	CompressTypes []string
	// CacheEngine, when non-nil, drives Tier-1 cache observation
	// per spec §8 (C8). The proxy calls CacheEngine.ObserveTurn
	// after upstream usage is known for every Anthropic turn that
	// has cache_control markers in its request body. Result rows
	// flow to CacheSink when both are set. Owned by the store
	// layer per R-engine Option A (spec §0 Findings + §24.4); a
	// single Engine instance is shared with watcher-path Tier-2
	// ingest. Optional.
	CacheEngine *cachetrack.Engine
	// CacheSink, when non-nil, receives ObserveTurn results from
	// CacheEngine. The store implements PersistCacheObservation
	// to write cache_segments + cache_events + cache_entries;
	// tests can pass nil to compute-but-not-persist. Optional.
	CacheSink CacheSink
	// LimitSink, when non-nil, receives one models.LimitSnapshot per
	// upstream response that carried rate-limit headers (predictor
	// limit half; migration 049). Optional — nil disables limit
	// capture, leaving the cost estimate unaffected.
	LimitSink LimitSink
	// NetworkSink, when non-nil and NetworkCapture.Enabled is true, receives a
	// node-local process network event for each proxied upstream call. This is
	// the plaintext capture source for process observability network bodies;
	// nil leaves proxy behavior byte-identical except for a nil check.
	NetworkSink processobs.EventSink
	// NetworkCapture controls optional process-network metadata/body capture
	// from the proxy path. Default zero value disables capture.
	NetworkCapture NetworkCaptureOptions
	// ModelRouter is the Channel-B routing seam (model-routing spec
	// §R5/§R11): called once per parsed request pre-forward; in
	// enforce mode the proxy rewrites the body's top-level model
	// field (and effort fields per §R6.5) with §R11.2 integrity —
	// every non-model byte preserved. Nil (the default) is the
	// byte-identical pass-through path: no routing code runs at all.
	// See router.go for the seam contract and its fail-open guards.
	ModelRouter ModelRouter
	// Reliability configures §R12.2 same-target retries. The zero
	// value changes nothing (doWithRetry's single transport retry is
	// pre-existing behavior). See reliability.go.
	Reliability ReliabilityOptions
	// LocalUpstreams maps model ids to local OpenAI-shape endpoint
	// base URLs (§R11.7 — Ollama / LM Studio / vLLM). A request whose
	// (possibly routed) model matches forwards to that endpoint
	// instead of the cloud upstream. Empty = no local routing.
	LocalUpstreams map[string]string
	// KeyPools maps a provider name to its §R12.4 rotating key ring
	// ([routing.key_pool] — local-only config, never synced/pushed).
	// On 429s the reliability layer retries with the next key, under
	// the credential-form guard in keypool.go.
	KeyPools map[string][]string
	// Guard, when non-nil, wires the guard layer's proxy seams
	// (guard spec §8): one ScanRequest call per request on the final
	// outbound body (post-compression — the same position cachetrack
	// hashes) and one InspectResponse call on the parsed response
	// surface. The cmd composition adapts the daemon's shared
	// guard.Guard + store behind this interface; nil leaves the
	// proxy's behavior byte-identical to the pre-guard baseline.
	// Optional.
	Guard GuardScanner
	// ObsSink, when non-nil, receives one ChatTurnFacts per successfully
	// inserted api_turn (the "gateway rail" — docs/observability.md "proxy
	// turn (automatic)") so it can synthesize a Plane-A obs_traces/obs_spans
	// pair without the proxying app emitting any OTLP itself. nil (the
	// default) leaves proxy behavior byte-identical except for a nil check.
	// See ObsSink's doc comment for the reverse-import-boundary rationale.
	ObsSink ObsSink
	// ObsContentExtractor, when non-nil, closes the gateway-rail content-
	// truncation class (Lane B, trajectory-ui-rollup-and-spandetail-fixes
	// spec): synthesizeObsTrace calls it synchronously over the FULL
	// request/response bodies (before any clipping) and carries the result
	// on ChatTurnFacts.PromptText/ResponseText instead of the clipped
	// Request/ResponseBody. nil (the default) leaves synthesizeObsTrace's
	// behavior byte-identical to before this seam existed. See
	// ObsContentExtractor's doc comment.
	ObsContentExtractor ObsContentExtractor
	// DrainGate, when non-nil, is the bounded-drain seam an in-place binary
	// update needs (enterprise-update-management plan §3.7 step 4a, rulings
	// R9/R13). While the gate is closed the proxy stops ADMITTING and
	// answers a retryable 503 with Retry-After; requests already admitted
	// run to completion, which is what "wait for in-flight to reach zero"
	// means. nil (the default) leaves proxy behavior byte-identical except
	// for a nil check.
	//
	// It is an INTERFACE, like Sink / Admitter / CostComputer, so the
	// concrete counter (internal/quiesce.Gate) stays on the other side of
	// the seam and internal/proxy never learns what an update is.
	DrainGate DrainGate
}

// DrainGate is the proxy's half of the node's quiescence contract.
//
// The rule it implements is a DRAIN, not a sample. A point-in-time "is
// anything in flight?" check races the request that arrives during the
// restart window, which is precisely the failure CLAUDE.md's
// "don't stop/restart the daemon while the proxy route is active" rule
// exists to prevent: the node cannot flip its client's base URL, so the
// closest honest equivalent of "route OFF" is a retryable refusal.
type DrainGate interface {
	// Enter admits one request, reporting whether it was admitted. A
	// refusal is answered 503 + Retry-After, never dropped and never held.
	Enter() bool
	// Leave releases one admitted request. Called from a defer, so every
	// exit path of the handler — including a panic — is covered.
	Leave()
	// RetryAfterSeconds is the hint sent with a refusal. It is the drain's
	// own budget rather than a constant, so a client that obeys it never
	// returns before the gate could have reopened.
	RetryAfterSeconds() int
}

// NetworkCaptureOptions controls optional proxy→process-network capture.
// Bodies are only stored when CaptureBodies is "proxied" or "available".
type NetworkCaptureOptions struct {
	Enabled          bool
	CaptureBodies    string
	MaxRequestBytes  int
	MaxResponseBytes int
	CaptureHeaders   bool
	ScrubBodies      bool
	StoreBinary      bool
}

// AuthCache is the proxy-side write interface for
// (messagesummary.AuthCache). The interface lets proxy_test.go stub
// it without importing the messagesummary package.
type AuthCache interface {
	Set(sessionID string, creds AuthCredentials)
}

// AuthCredentials mirrors messagesummary.AuthCredentials so the proxy
// contract stays import-cycle-free. Field names match exactly.
type AuthCredentials struct {
	Authorization string
	APIKey        string
}

// Proxy is the API reverse proxy. Safe for concurrent use.
type Proxy struct {
	anthropicURL *url.URL
	openaiURL    *url.URL
	chatgptURL   *url.URL
	geminiURL    *url.URL
	// lanes holds the routing id → upstream URL map (from a /up/<id>/ path
	// prefix, Phase C per-provider selection AND the virtual "auto" lane,
	// Phase 2) TOGETHER WITH the "auto" lane's default lane id, published
	// as one atomically-swapped snapshot (Phase 3, gateway config plane
	// spec — see docs/plans/gateway-config-plane-spec-2026-08-15.md).
	// Bundling them into a single laneTable behind one atomic.Pointer is
	// deliberate: the map and the default id used to be two independently
	// mutable fields (a map behind its own atomic.Pointer plus a plain
	// string), so a request that resolved the auto lane could Load() the
	// upstream map from one generation and read the default lane id from
	// a LATER (or earlier) generation of a concurrent SetLaneTable/
	// SetUpstreams swap — a torn read across two writers of what is really
	// one piece of state. Every reader Load()s laneSnapshot() at most once
	// per request; the snapshot value is never mutated after publish
	// (copy-on-write), so a swap never races an in-flight request that
	// already read the old snapshot. nil/empty upstreams map when no
	// [proxy.upstreams] are configured (fail-open to the fixed three).
	lanes atomic.Pointer[laneTable]
	// laneGen is the monotonically increasing source of laneTable.generation
	// ids (Sol S7). Every setter that publishes a new laneTable (New,
	// SetUpstreams, SetLaneTable, SetOrgGatewayRoute) calls nextGeneration()
	// exactly once and stamps the result into the snapshot it Stores — so
	// "the ACKed generation is exactly what was installed" is a plain
	// integer equality check, with no ambiguity from partial/torn state.
	laneGen atomic.Uint64
	// virtualKeySource supplies the AI Gateway virtual key for Sol S2
	// auth-substitution when Gateway Mode is active. nil ⇒ Gateway Mode
	// can never succeed (fails closed — see the gateway auth-substitution
	// block in serve()); a byte-identical-to-pre-P5a build simply never
	// sets an org-route, so this only matters once Gateway Mode is
	// actually installed. Bound at the orgclient wiring point so
	// internal/proxy never imports internal/orgclient (same pattern as
	// Admitter/EgressReporter for internal/obs).
	virtualKeySource VirtualKeySource
	// gatewayAlerter mirrors Options.GatewayFleetAlerter — the fleet-alert
	// sink the Gateway-Mode fallback executor fires on terminal-policy
	// application. nil ⇒ no sink (the executor still logs). See
	// gatewayfallback.go.
	gatewayAlerter      GatewayFleetAlerter
	forceChatGPTHTTP    bool
	sink                Sink
	compressor          Compressor
	admitter            Admitter
	egressReporter      EgressReporter
	egressBreaker       *egressBreaker
	admissionUserHeader string
	cost                CostComputer
	obsLog              ObserverLogSink
	sessions            SessionResolver
	logger              *slog.Logger
	client              *http.Client
	now                 func() time.Time
	postCompact         PostCompactInjector
	authCache           AuthCache
	prewarmTargets      []string
	// cacheEngine, when non-nil, drives Tier-1 cache observation
	// per spec §8 (C8). buildTurn / buildStreamTurn call
	// cacheEngine.ObserveTurn after upstream usage is known and
	// feed the result to cacheSink. Both are optional — when
	// either is nil the proxy continues unchanged.
	cacheEngine *cachetrack.Engine
	cacheSink   CacheSink
	// limitSink, when non-nil, receives a models.LimitSnapshot for each
	// upstream response carrying rate-limit headers (predictor limit half).
	limitSink LimitSink
	// networkSink receives optional proxy-observed process network events.
	networkSink    processobs.EventSink
	networkCapture NetworkCaptureOptions
	// guard, when non-nil, is the guard layer's proxy seam (spec §8).
	// See Options.Guard.
	guard GuardScanner
	// compressTypes holds the configured `compress_types` slice so the
	// per-request V7-2 codex-variant warning can decide whether to
	// fire. See Options.CompressTypes.
	compressTypes []string
	// router is the Channel-B seam (Options.ModelRouter). Nil = no
	// routing code on the request path at all.
	router ModelRouter
	// reliability is the §R12.2 same-target retry config.
	reliability ReliabilityOptions
	// localUpstreams maps model ids to parsed §R11.7 local endpoints.
	localUpstreams map[string]*url.URL
	// keyPools holds the §R12.4 per-provider rotating key rings.
	keyPools map[string]*keyPool
	// codexVariantWarned is the per-session dedup map for the V7-2
	// warning. Keyed by session_id (codex's prompt_cache_key); value
	// is unused. Bounded via codexVariantWarnedCap to prevent memory
	// growth on long-running daemons; eviction is simple oldest-first
	// (any-key delete) when the cap is hit. The map's read/write
	// contention is low — one Load + one Store per session, lifetime
	// of the daemon.
	codexVariantWarned sync.Map
	// unknownUpstreamWarned dedups the stripUpstreamPrefix warning for an
	// unknown `/up/<id>/` routing id. Keyed by the id (a small, config-shaped
	// vocabulary — an operator's typo set, not user input at scale), value
	// unused: one Warn per distinct id for the daemon's lifetime.
	unknownUpstreamWarned sync.Map
	// obsSink is the optional gateway-rail seam (Options.ObsSink).
	obsSink ObsSink
	// obsContentExtractor is the optional Lane B extract-before-clip seam
	// (Options.ObsContentExtractor). nil ⇒ synthesizeObsTrace's legacy
	// clipped-bodies path, unchanged.
	obsContentExtractor ObsContentExtractor
	// obsSem bounds gateway-rail trace-synthesis concurrency (Finding F3 —
	// see obsGatewayMaxConcurrentSynthesis's doc comment). Always
	// allocated (cheap, fixed-size); only ever touched when obsSink != nil.
	obsSem chan struct{}
	// drainGate is the optional bounded-drain seam (Options.DrainGate). nil
	// ⇒ admission is unconditional, byte-identical to the pre-update-arc
	// behaviour.
	drainGate DrainGate
}

// codexVariantRe matches OpenAI-shape model identifiers that belong to
// the codex-variant family — i.e. names where `codex` appears as a
// dash-delimited token. Verified against the v4 batch's observed
// model strings: gpt-5.3-codex, gpt-5.3-codex-low, gpt-5.3-codex-high,
// gpt-5.3-codex-xhigh, gpt-5-codex-agent, codex-internal. Does NOT
// match gpt-5.4-mini, gpt-5.5, claude-* etc. Case-insensitive — codex
// emits lowercase in practice but the model field is operator-supplied
// on some paths.
//
// The empirical v4-codex-compression session (2026-05-29) showed that
// this family treats compressed tool_result bodies as missing data and
// re-derives via shell tools, inflating cost ~2-3×. V7-2 mitigation
// emits a one-line warning per session pointing the operator at the
// codex-variant recipe.
var codexVariantRe = regexp.MustCompile(`(?i)(?:^codex-|-codex(?:-|$))`)

// codexVariantWarnedCap caps the per-daemon dedup map so a long-running
// observer with thousands of distinct sessions doesn't grow unbounded.
// 10k is plenty for realistic operator deployments — well past the
// session count of any single workday.
const codexVariantWarnedCap = 10_000

// maxRequestBodyBytes caps a proxied client request body. It is a DoS ceiling
// (the daemon buffers the whole body for forward + inspection and also serves
// the dashboard/watcher in the same process), not a functional limit — 512 MiB
// is far above any real prompt/image/conversation payload.
const maxRequestBodyBytes = 512 << 20

// maybeWarnCodexVariantModel emits at most one stderr warning per
// session_id when an OpenAI-shape request's model matches a
// codex-variant identifier AND the proxy was configured with non-empty
// `compress_types`. See Options.CompressTypes for the contract.
// Pure no-op when sid is empty, compressTypes is empty, or the model
// is not a codex variant. Safe for concurrent use.
func (p *Proxy) maybeWarnCodexVariantModel(sid, model string) {
	if sid == "" || model == "" || len(p.compressTypes) == 0 {
		return
	}
	if !codexVariantRe.MatchString(model) {
		return
	}
	if _, loaded := p.codexVariantWarned.LoadOrStore(sid, struct{}{}); loaded {
		return
	}
	// Bound the map. Drop one arbitrary entry — eviction order is best-
	// effort, not strictly oldest-first. The cap prevents pathological
	// growth, not warning re-emission for the previously-evicted key
	// (a re-emission for an old session that just happens to send a
	// request after eviction is acceptable, given how rare it is).
	if mapLen(&p.codexVariantWarned) > codexVariantWarnedCap {
		p.codexVariantWarned.Range(func(k, _ any) bool {
			p.codexVariantWarned.Delete(k)
			return false // delete one and stop
		})
	}
	p.logger.Warn(
		"proxy: codex-variant model paired with non-empty compress_types — "+
			"the codex-variant family re-derives data on compressed tool_results, "+
			"inflating cost; recommend `[compression.conversation] compress_types = []` "+
			"or `observer start --recipe codex-variant`; see docs/codex-compression-recipe.md",
		"model", model,
		"session_id", sid,
		"compress_types", strings.Join(p.compressTypes, ","),
	)
}

// mapLen returns the number of entries in m. sync.Map has no Len
// method; we walk the map once. Called only on the warning-emit path
// (rare), so the cost is amortized away.
func mapLen(m *sync.Map) int {
	n := 0
	m.Range(func(_, _ any) bool { n++; return true })
	return n
}

// ObserverLogSink is the write side of the observer_log telemetry
// channel — same pattern as [Sink]. The zero value is a no-op when
// assigned as nil.
type ObserverLogSink interface {
	InsertObserverLog(ctx context.Context, level, component, message, details string) error
}

// New validates opts and constructs a Proxy.
func New(opts Options) (*Proxy, error) {
	if opts.Sink == nil {
		return nil, errors.New("proxy.New: Sink is required")
	}
	anthropicURL, err := parseUpstream("anthropic_upstream", opts.AnthropicUpstream, "https://api.anthropic.com")
	if err != nil {
		return nil, err
	}
	openaiURL, err := parseUpstream("openai_upstream", opts.OpenAIUpstream, "https://api.openai.com")
	if err != nil {
		return nil, err
	}
	chatgptURL, err := parseUpstream("chatgpt_upstream", opts.ChatGPTUpstream, "https://chatgpt.com")
	if err != nil {
		return nil, err
	}
	geminiURL, err := parseUpstream("gemini_upstream", opts.GeminiUpstream, "https://generativelanguage.googleapis.com")
	if err != nil {
		return nil, err
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{
			Transport: &http.Transport{
				DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 16,
				// Idle connections are held for at most 30s before
				// recycling. Pre-v1.4.24 this was 90s — too long for
				// environments where a NAT layer (WSL2, corporate
				// firewalls, mobile hotspots) closes idle TCP streams
				// faster than that. The user-visible symptom was
				// "write tcp ...: connection reset by peer" on a
				// reused dead connection. 30s is short enough to evict
				// stale entries before typical NAT idle-kill, long
				// enough to amortize TLS for back-to-back requests in
				// the same conversation.
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				// Disable response buffering so SSE events flow through
				// immediately.
				DisableCompression: true,
			},
			// No Timeout — SSE streams can run for minutes.
		}
	}
	now := opts.Clock
	if now == nil {
		now = time.Now
	}
	var localUpstreams map[string]*url.URL
	for model, raw := range opts.LocalUpstreams {
		u, err := parseUpstream("local_upstream:"+model, raw, "")
		if err != nil {
			return nil, err
		}
		if localUpstreams == nil {
			localUpstreams = map[string]*url.URL{}
		}
		localUpstreams[model] = u
	}
	// Phase C: explicit per-provider upstreams selected by a /up/<id>/ path
	// prefix. Parsed like localUpstreams; an empty map leaves the fixed
	// three upstreams as the only targets (fail-open).
	var explicitUpstreams map[string]*url.URL
	for id, raw := range opts.Upstreams {
		u, err := parseUpstream("upstream:"+id, raw, "")
		if err != nil {
			return nil, err
		}
		if explicitUpstreams == nil {
			explicitUpstreams = map[string]*url.URL{}
		}
		explicitUpstreams[id] = u
	}
	prewarm := opts.PrewarmTargets
	if prewarm == nil {
		// nil → use defaults. Empty slice (non-nil) → operator explicitly
		// disabled pre-warm (don't fire any).
		prewarm = []string{"https://chatgpt.com/", "https://api.openai.com/"}
	}
	p := &Proxy{
		anthropicURL:        anthropicURL,
		openaiURL:           openaiURL,
		chatgptURL:          chatgptURL,
		geminiURL:           geminiURL,
		forceChatGPTHTTP:    opts.ForceChatGPTHTTP,
		sink:                opts.Sink,
		compressor:          opts.Compressor,
		admitter:            opts.Admitter,
		egressReporter:      opts.EgressReporter,
		virtualKeySource:    opts.VirtualKeySource,
		gatewayAlerter:      opts.GatewayFleetAlerter,
		egressBreaker:       newEgressBreaker(),
		admissionUserHeader: opts.AdmissionUserHeader,
		cost:                opts.CostComputer,
		obsLog:              opts.ObserverLog,
		sessions:            opts.SessionResolver,
		logger:              logger,
		client:              client,
		now:                 now,
		postCompact:         opts.PostCompactInjector,
		authCache:           opts.AuthCache,
		prewarmTargets:      prewarm,
		compressTypes:       opts.CompressTypes,
		cacheEngine:         opts.CacheEngine,
		cacheSink:           opts.CacheSink,
		limitSink:           opts.LimitSink,
		networkSink:         opts.NetworkSink,
		networkCapture:      opts.NetworkCapture,
		router:              opts.ModelRouter,
		reliability:         opts.Reliability,
		localUpstreams:      localUpstreams,
		keyPools:            buildKeyPools(opts.KeyPools),
		guard:               opts.Guard,
		obsSink:             opts.ObsSink,
		obsContentExtractor: opts.ObsContentExtractor,
		obsSem:              make(chan struct{}, obsGatewayMaxConcurrentSynthesis),
		drainGate:           opts.DrainGate,
	}
	// atomic.Pointer has no struct-literal form (unexported internal
	// state) — publish the initial lane table via Store, same call path
	// SetUpstreams/SetLaneTable/SetOrgGatewayRoute use for a later hot
	// swap. orgRoute starts at its zero value (orgModeNode — inert).
	p.lanes.Store(&laneTable{upstreams: explicitUpstreams, autoDefault: opts.AutoDefaultLane, generation: p.nextGeneration()})
	return p, nil
}

// nextGeneration returns the next monotonically increasing routing-
// generation id (Sol S7). Safe for concurrent use; every laneTable setter
// calls this exactly once per publish.
func (p *Proxy) nextGeneration() uint64 {
	return p.laneGen.Add(1)
}

// SetUpstreams parses and validates every entry in upstreams, then
// atomically swaps the live routing-id → upstream-URL map used by
// /up/<id> lane selection and the virtual "auto" lane (Phase 1, gateway
// config plane spec), PRESERVING the currently live auto-default lane id
// AND org-gateway route (Sol S7 — see SetOrgGatewayRoute) unchanged.
// All-or-nothing: if ANY entry fails to parse, the PREVIOUSLY
// live table keeps serving unchanged and the first parse error is
// returned — there is no partial swap. "auto" is a reserved lane id
// (Phase 2) and is always rejected, mirroring the config-time check in
// internal/config.
//
// The swapped laneTable value is never mutated after publish
// (copy-on-write); concurrent requests each Load() it at most once per
// request via laneSnapshot, so a swap never races an in-flight request
// that already read the old table. Callers that also need to change the
// default lane id atomically with the upstream map should use
// SetLaneTable instead.
func (p *Proxy) SetUpstreams(upstreams map[string]string) error {
	var next map[string]*url.URL
	for id, raw := range upstreams {
		if id == autoLaneID {
			return fmt.Errorf("proxy.SetUpstreams: %q is a reserved lane id", autoLaneID)
		}
		u, err := parseUpstream("upstream:"+id, raw, "")
		if err != nil {
			return fmt.Errorf("proxy.SetUpstreams: %w", err)
		}
		if next == nil {
			next = map[string]*url.URL{}
		}
		next[id] = u
	}
	prev := p.laneSnapshot()
	p.lanes.Store(&laneTable{upstreams: next, autoDefault: prev.autoDefault, orgRoute: prev.orgRoute, generation: p.nextGeneration()})
	return nil
}

// SetLaneTable atomically swaps BOTH the explicit /up/<id> upstream map and
// the virtual "auto" lane's default lane id in a single publish (Phase 3,
// gateway config plane spec — the install seam for a dashboard-managed
// gateway.providers policy resource). Unlike SetUpstreams, which preserves
// whatever default is currently live, this replaces it outright: passing
// an empty autoDefaultLane clears the default. The org-gateway route
// (Sol S7 — see SetOrgGatewayRoute) is PRESERVED unchanged, same as
// SetUpstreams.
//
// All-or-nothing: if ANY upstream entry fails to parse, or autoDefaultLane
// is non-empty and doesn't name a key of upstreams (including "auto",
// which is never a valid lane id), the PREVIOUSLY live table keeps serving
// unchanged and an error is returned — there is no partial swap.
//
// The swapped laneTable value is never mutated after publish
// (copy-on-write); concurrent requests each Load() it at most once per
// request via laneSnapshot, so this races neither an in-flight request
// nor a concurrent SetUpstreams/SetLaneTable call (last Store wins, and
// each call's validation runs against ITS OWN candidate table, never a
// partially-applied one).
func (p *Proxy) SetLaneTable(upstreams map[string]string, autoDefaultLane string) error {
	var next map[string]*url.URL
	for id, raw := range upstreams {
		if id == autoLaneID {
			return fmt.Errorf("proxy.SetLaneTable: %q is a reserved lane id", autoLaneID)
		}
		u, err := parseUpstream("upstream:"+id, raw, "")
		if err != nil {
			return fmt.Errorf("proxy.SetLaneTable: %w", err)
		}
		if next == nil {
			next = map[string]*url.URL{}
		}
		next[id] = u
	}
	if autoDefaultLane == autoLaneID {
		return fmt.Errorf("proxy.SetLaneTable: auto_default_lane %q is a reserved lane id", autoLaneID)
	}
	if autoDefaultLane != "" {
		if _, ok := next[autoDefaultLane]; !ok {
			return fmt.Errorf("proxy.SetLaneTable: auto_default_lane %q does not name a configured upstream", autoDefaultLane)
		}
	}
	p.lanes.Store(&laneTable{upstreams: next, autoDefault: autoDefaultLane, orgRoute: p.laneSnapshot().orgRoute, generation: p.nextGeneration()})
	return nil
}

// LaneTable returns a copy of the currently live lane table as plain
// strings: lane id -> upstream base URL, plus the auto-default lane id.
// Both halves come from ONE laneSnapshot() load, so a caller can never
// observe a mixed generation across a concurrent SetLaneTable swap.
//
// This is the READ counterpart of SetLaneTable, added for the P0-6
// effective-policy-state reporter (docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md
// §2.2): the gateway.providers point reports a content hash of the table
// that is ACTUALLY live, rather than a mirror of what the install seam
// believes it applied. The returned map is a fresh copy the caller owns.
//
// The URLs are re-serialized from their parsed form, so a base URL may be
// normalized relative to the configured string (a trailing slash, a
// default port). Callers must treat the result as a stable identity of the
// live table, never as the operator's config text.
func (p *Proxy) LaneTable() (upstreams map[string]string, autoDefaultLane string) {
	t := p.laneSnapshot()
	out := make(map[string]string, len(t.upstreams))
	for id, u := range t.upstreams {
		if u == nil {
			continue
		}
		out[id] = u.String()
	}
	return out, t.autoDefault
}

// SetOrgGatewayRoute atomically installs (or clears) the org-wide AI
// Gateway routing mode, destination, and fallback ladder as part of the
// SAME immutable routing-generation snapshot as the /up/<id> lane table
// (Sol S7, docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md
// §2 Gateway Mode). This is the ONLY way org-route state changes — there
// is no second atomic.Pointer for it (Sol S7's "no second setter/pointer"
// constraint). PRESERVES the currently live upstream map and auto-default
// lane id unchanged, mirroring SetUpstreams' RMW pattern for the other
// half of the snapshot.
//
// mode must be orgModeNode ("" — clears any installed route; default-lane
// traffic goes directly to the fixed upstreams, byte-identical to every
// pre-P5a build) or orgModeGateway ("gateway" — default-lane traffic with
// no explicit /up/<id> lane is redirected to primary via upstreamForPath,
// Sol S8, and Gateway Mode auth-substitution activates for it, Sol S2).
// Any other mode string is rejected. In gateway mode, primary is required
// and must parse as a valid upstream URL (scheme + host); every entry in
// fallbacks must too. The fallback ladder's runtime state machine (try
// each entry, apply a terminal policy) is Sol S10 / P5b — this call only
// stores the data so a later phase can walk it.
//
// All-or-nothing: on any validation error the previously live snapshot
// keeps serving unchanged and the error is returned — there is no partial
// install. A nil error means the generation this call just published
// (see RoutingGeneration) is now exactly what's live: no torn state for a
// caller (e.g. the org policy-state ACK path) to worry about.
func (p *Proxy) SetOrgGatewayRoute(mode, primary string, fallbacks []string) error {
	return p.SetOrgGatewayRouteWithFallback(mode, primary, fallbacks, "", false)
}

// SetOrgGatewayRouteWithFallback is SetOrgGatewayRoute plus the compiled
// fallback-ladder terminal policy (Sol S10 / Luna L16). The runtime ladder
// executor (gatewayfallback.go) reads the stored terminal rung + custody-ack
// when primary and every fallback endpoint is exhausted. terminal is one of
// terminalHold / terminalBreakGlass / terminalDirect (empty ⇒ hold);
// custodyAck is only honored for terminalDirect. The three-arg
// SetOrgGatewayRoute is the terminal="hold" default form.
func (p *Proxy) SetOrgGatewayRouteWithFallback(mode, primary string, fallbacks []string, terminal string, custodyAck bool) error {
	org, err := newOrgRouteState(mode, primary, fallbacks, terminal, custodyAck)
	if err != nil {
		return fmt.Errorf("proxy.SetOrgGatewayRoute: %w", err)
	}
	prev := p.laneSnapshot()
	p.lanes.Store(&laneTable{
		upstreams:   prev.upstreams,
		autoDefault: prev.autoDefault,
		orgRoute:    org,
		generation:  p.nextGeneration(),
	})
	return nil
}

// SetRoutingSnapshot atomically installs BOTH the /up/<id> lane table
// (upstreams + auto-default) AND the org-gateway route (mode + primary +
// fallbacks) as ONE routing-generation snapshot — the true realization of
// Sol S7's "one immutable routing-generation snapshot, published in one
// swap, ACKed as one generation." It is the combined form of SetLaneTable +
// SetOrgGatewayRoute for the gateway.providers MODE-body accept path, which
// must publish lanes and mode together so a reader can never observe new
// lanes with an old mode (or vice versa) across the accept.
//
// mode is orgModeNode ("") or orgModeGateway ("gateway"); in gateway mode
// primary is required and every URL must parse. Validation is all-or-nothing:
// on any error the previously live snapshot keeps serving unchanged. The
// autoLaneID lane id is reserved for both the lane map and auto_default_lane.
//
// For a lane-only body that carries no mode block, the accept path reads the
// live OrgRoute() and passes it straight through here, so "preserve the
// current org-route" is expressed as "set it to what it already is" — still
// one atomic swap, never a torn generation.
func (p *Proxy) SetRoutingSnapshot(upstreams map[string]string, autoDefaultLane, mode, primary string, fallbacks []string) error {
	return p.SetRoutingSnapshotWithFallback(upstreams, autoDefaultLane, mode, primary, fallbacks, "", false)
}

// SetRoutingSnapshotWithFallback is SetRoutingSnapshot plus the compiled
// fallback-ladder terminal policy (Sol S10 / Luna L16). The mode-body accept
// path (cmd/observer's gatewayProvidersHandle.ApplyWithMode) calls this so a
// Gateway-Mode body installs its lanes, destination, ordered fallback ladder,
// AND terminal rung in ONE routing generation — the runtime executor
// (gatewayfallback.go) then reads the terminal rung + custody-ack from the
// same snapshot it reads the endpoints from, never straddling two
// generations. The six-arg SetRoutingSnapshot is the terminal="hold" default
// form. All validation stays all-or-nothing.
func (p *Proxy) SetRoutingSnapshotWithFallback(upstreams map[string]string, autoDefaultLane, mode, primary string, fallbacks []string, terminal string, custodyAck bool) error {
	// Validate the lane half (mirrors SetLaneTable).
	var next map[string]*url.URL
	for id, raw := range upstreams {
		if id == autoLaneID {
			return fmt.Errorf("proxy.SetRoutingSnapshot: %q is a reserved lane id", autoLaneID)
		}
		u, err := parseUpstream("upstream:"+id, raw, "")
		if err != nil {
			return fmt.Errorf("proxy.SetRoutingSnapshot: %w", err)
		}
		if next == nil {
			next = map[string]*url.URL{}
		}
		next[id] = u
	}
	if autoDefaultLane == autoLaneID {
		return fmt.Errorf("proxy.SetRoutingSnapshot: auto_default_lane %q is a reserved lane id", autoLaneID)
	}
	if autoDefaultLane != "" {
		if _, ok := next[autoDefaultLane]; !ok {
			return fmt.Errorf("proxy.SetRoutingSnapshot: auto_default_lane %q does not name a configured upstream", autoDefaultLane)
		}
	}
	// Validate the org-route half (mirrors SetOrgGatewayRoute).
	org, err := newOrgRouteState(mode, primary, fallbacks, terminal, custodyAck)
	if err != nil {
		return fmt.Errorf("proxy.SetRoutingSnapshot: %w", err)
	}
	// One swap, one generation — lanes and org-route together.
	p.lanes.Store(&laneTable{upstreams: next, autoDefault: autoDefaultLane, orgRoute: org, generation: p.nextGeneration()})
	return nil
}

// OrgRoute returns the currently live org-gateway route: the mode
// (orgModeNode or orgModeGateway), the primary destination and fallback
// ladder as plain strings, and the routing-generation id of the snapshot
// they came from. All four come from ONE laneSnapshot() load, so a caller
// can never observe a mixed generation across a concurrent
// SetOrgGatewayRoute swap. mode == orgModeNode means primary/fallbacks are
// always "" / nil (no route installed).
func (p *Proxy) OrgRoute() (mode, primary string, fallbacks []string, generation uint64) {
	t := p.laneSnapshot()
	if t.orgRoute.primary != nil {
		primary = t.orgRoute.primary.String()
	}
	for _, u := range t.orgRoute.fallbacks {
		if u == nil {
			continue
		}
		fallbacks = append(fallbacks, u.String())
	}
	return t.orgRoute.mode, primary, fallbacks, t.generation
}

// RoutingGeneration returns the generation id of the currently live
// routing snapshot (Sol S7). Exposed for tests and diagnostics that need
// to confirm an install landed without inspecting the rest of the state.
func (p *Proxy) RoutingGeneration() uint64 {
	return p.laneSnapshot().generation
}

// laneSnapshot returns the currently live laneTable (a Load() of the
// atomic.Pointer set by New/SetUpstreams/SetLaneTable). The returned value
// is never mutated after publish, so callers read it directly without
// copying. Never nil — New always publishes an initial table, even when
// empty.
func (p *Proxy) laneSnapshot() *laneTable {
	if t := p.lanes.Load(); t != nil {
		return t
	}
	return &laneTable{}
}

// upstreamsSnapshot returns the upstreams map half of the currently live
// laneTable. Retained as a thin accessor for call sites that only need the
// map (stripUpstreamPrefix, warnUnknownUpstreamOnce's configuredCount);
// call sites that also need the auto-default lane id call laneSnapshot
// directly so both halves come from the SAME Load (see laneTable's doc
// comment on why that matters). The returned map is never mutated after
// publish, so callers read it directly without copying. nil when no
// [proxy.upstreams] are configured.
func (p *Proxy) upstreamsSnapshot() map[string]*url.URL {
	return p.laneSnapshot().upstreams
}

// Prewarm fires a no-op HEAD against each target URL using the
// proxy's upstream http.Client. The goal is to populate the
// http.Transport's connection pool with warm TLS sessions so the
// first real proxy request reuses a pooled connection instead of
// paying a cold-handshake. V6-3 mitigation (see
// docs/observer-platform-issues-v6.md).
//
// Cheap: HEAD against a public endpoint, 5s timeout, non-fatal on
// any error (connectivity, DNS, 4xx/5xx — all logged at info, never
// returned). Safe to call multiple times; each call refreshes the
// pool.
//
// Exported so cmd/observer can fire it at start (current callsite:
// ListenAndServe) and so the test suite can drive it directly.
func (p *Proxy) Prewarm(ctx context.Context, targets []string) {
	if len(targets) == 0 {
		return
	}
	for _, raw := range targets {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, raw, nil)
		if err != nil {
			cancel()
			p.logger.Info("proxy: prewarm skipped (bad URL)", "target", raw, "err", err)
			continue
		}
		resp, err := p.client.Do(req)
		if err != nil {
			cancel()
			p.logger.Info("proxy: prewarm failed", "target", raw, "err", err)
			continue
		}
		_ = resp.Body.Close()
		cancel()
		p.logger.Info("proxy: prewarm ok", "target", raw, "status", resp.StatusCode)
	}
}

func parseUpstream(name, raw, fallback string) (*url.URL, error) {
	if raw == "" {
		raw = fallback
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy.New: %s: %w", name, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("proxy.New: %s %q must include scheme and host", name, raw)
	}
	return u, nil
}

// Handler returns the proxy's http.Handler. Mount it on a net/http server
// or use ListenAndServe.
func (p *Proxy) Handler() http.Handler { return http.HandlerFunc(p.serve) }

// CacheEngine returns the per-process cachetrack.Engine the proxy was
// built with, or nil when cache tracking is disabled. The daemon hands
// this same instance to the watcher's store (via Watcher.SetCacheEngine)
// so Tier-2 (transcript) observations advance the SAME CacheModel state
// the proxy's Tier-1 path advances — the "single engine, multiple feed
// paths" model (spec §24.4). Without this, the watcher-side ingest seam
// sees a nil engine and silently drops every transcript cache
// observation, so non-proxied sessions get no cache_entries at all.
func (p *Proxy) CacheEngine() *cachetrack.Engine { return p.cacheEngine }

// ListenAndServe runs the proxy on addr until ctx is cancelled, then shuts
// down with a 5s grace period.
// hostnameOnly strips the port (and IPv6 brackets) from a host[:port] value.
func hostnameOnly(hostport string) string {
	if hostport == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// hostIsLoopback reports whether host is a loopback name or IP.
func hostIsLoopback(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func (p *Proxy) ListenAndServe(ctx context.Context, addr string) error {
	if host := hostnameOnly(addr); host != "" && !hostIsLoopback(host) {
		p.logger.Warn("proxy bound to a non-loopback address — the listener has no client auth and, when a routing key_pool is configured, will substitute the operator's own API keys on a 429; anything that can reach it can drive requests upstream", "addr", addr)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           p.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	// V6-3 mitigation: pre-warm the http.Transport connection pool
	// against configured upstream targets so the first real request
	// doesn't pay the 500ms-1.5s TLS handshake cost that pushed
	// codex's inner-pipe TTFB past its ~15s timeout. Non-blocking;
	// failures are logged but never abort startup.
	go p.Prewarm(ctx, p.prewarmTargets)
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("proxy shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

// healthzPath is the proxy's unauthenticated liveness endpoint (W1.2,
// gateway config plane spec). It lives under a "/-/" prefix — a segment no
// provider API path (Anthropic, OpenAI, Gemini, ChatGPT backend, or any
// configured /up/<id> lane, including the literal id "-") can ever produce,
// since every one of those begins with a provider-specific /v1/,
// /backend-api/, or /up/ segment — so an exact match here can never shadow
// forwarded traffic. The convention mirrors well-known non-resource path
// prefixes (cf. Kubernetes' own /-/ready, /-/healthy admin paths).
const healthzPath = "/-/healthz"

// serveHealthz answers the liveness probe: 200 + a tiny JSON body for GET,
// 200 with no body for HEAD (net/http's Header-write path already suppresses
// the body for HEAD, but the explicit early return keeps the intent obvious
// and avoids writing bytes that would otherwise be silently dropped), and
// 405 for anything else. Deliberately does not touch p.client, p.sink, or
// any upstream — a probe must answer even when every upstream is down, and
// must never record an api_turn.
func serveHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// serve is the top-level request handler.
func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	// Unauthenticated liveness probe (W1.2) — intercepted before ANY other
	// routing (including stripUpstreamPrefix) so it never collides with a
	// /up/<id> lane and never depends on upstream/admission/compression
	// state. Exact match only: a lane-prefixed variant is not a thing this
	// path supports (see healthzPath's doc comment on why it can't collide).
	if r.URL.Path == healthzPath {
		serveHealthz(w, r)
		return
	}

	// Bounded drain (enterprise-update-management plan §3.7 step 4a, R9/R13).
	// Placed here, immediately AFTER the liveness probe and BEFORE any
	// routing, body read, admission or compression, for two reasons: the
	// probe must keep answering while the node quiesces (a supervisor that
	// reads it would otherwise restart the daemon in the middle of its own
	// update), and a refusal must cost nothing — no upstream dial, no body
	// buffered, no lane resolved.
	//
	// The defer covers every one of serve's many exit paths, including the
	// websocket-upgrade branch. That branch is a KNOWN under-report: a
	// hijacked connection outlives serve, so a long-lived upgrade stops
	// counting once serve returns. Upgrades are not the API-turn traffic the
	// drain exists to protect, and the alternative — counting inside
	// serveUpgradePassthrough's copy loops — would make a single idle
	// websocket block every update indefinitely.
	if p.drainGate != nil {
		if !p.drainGate.Enter() {
			writeDrainRefusal(w, providerForPath(r.URL.Path), p.drainGate.RetryAfterSeconds())
			return
		}
		defer p.drainGate.Leave()
	}

	// Phase C: explicit per-provider upstream selection. A routed tool whose
	// traffic must reach a non-default host (e.g. hermes → OpenRouter) points
	// its base URL at .../up/<id>/v1; stripUpstreamPrefix rewrites r.URL.Path
	// to drop the /up/<id> segment (so all downstream path/provider logic
	// sees the canonical path) and returns the mapped upstream. Returns nil
	// when there's no prefix or the id is unknown → the fixed-upstream path
	// below runs unchanged (fail-open).
	explicitUpstream, upstreamLaneID := p.stripUpstreamPrefix(r)
	if upstreamLaneID != "" {
		// Stamp the lane id on the request context: the gateway rail's
		// Plane-A/Plane-B discriminator (obsLaneCtxKey doc). Reassigned
		// here, before any closure captures r, so every downstream
		// synthesizeObsTrace call site (including serveGuardDeny) sees it.
		r = r.WithContext(context.WithValue(r.Context(), obsLaneCtxKey{}, upstreamLaneID))
	}

	provider := providerForPath(r.URL.Path)
	// Codex 0.128.0+ with `requires_openai_auth = true` on a custom
	// model_provider hits canonical /v1/responses paths with a ChatGPT
	// JWT — the proxy can't differentiate by path alone, so detect via
	// the Authorization header. When detected, route the request to
	// chatgpt.com and rewrite the path to the codex backend equivalent.
	// An explicit upstream short-circuits this: that traffic carries the
	// routed tool's own key, not a ChatGPT JWT. This must also exclude
	// EVERY /up/ lane, named or virtual "auto" alike (upstreamLaneID != ""):
	// stripUpstreamPrefix returns a nil explicitUpstream for the "auto"
	// lane (its target isn't known until the body is read below), so
	// explicitUpstream == nil alone can't tell a lane request apart from
	// a genuine fixed-upstream one. Routed lane traffic always carries the
	// routed tool's own key, never a ChatGPT JWT, so it must never trip
	// this detection — without the upstreamLaneID guard, a ChatGPT-JWT-
	// bearing GET to /up/auto/v1/models was wrongly short-circuited into
	// the synthetic {"models":[]} response below instead of reaching the
	// auto lane's own resolution (bug W1.3a).
	chatgptAuth := explicitUpstream == nil && upstreamLaneID == "" && provider == models.ProviderOpenAI && isChatGPTAuthRequest(r)
	upstream := explicitUpstream
	// gatewayRouted reports whether this request resolved to the org's AI
	// Gateway (Sol S8) rather than a fixed provider upstream or an
	// explicit /up/<id> lane. It gates Sol S2 auth-substitution below —
	// deliberately false for the explicitUpstream (named-lane) case, since
	// a named lane never falls through to org-route by construction.
	gatewayRouted := false
	// routeGeneration is the routing-snapshot generation this turn was
	// served under (Sol S7 / Luna L15). It is stamped onto every api_turns
	// row via stampRoute below so a mixed-mode fleet's org rollup can
	// attribute each turn to the exact routing generation that produced it.
	routeSnap := p.laneSnapshot()
	routeGeneration := routeSnap.generation
	if upstream == nil {
		// Sol S8: this laneSnapshot() load is self-contained and NOT shared
		// with the independent laneSnapshot() calls further down (the
		// websocket-upgrade branch and the post-body auto-lane resolution)
		// — each resolves against its own read of the live snapshot, so a
		// concurrent SetOrgGatewayRoute/SetLaneTable install between them
		// can only ever advance a caller to a newer generation, never mix
		// halves of two different ones within a single call.
		upstream, gatewayRouted = p.upstreamForPath(r.URL.Path, provider, chatgptAuth, routeSnap, upstreamLaneID)
	}
	upstreamPath := r.URL.Path
	if chatgptAuth {
		upstreamPath = translateChatGPTPath(r.URL.Path)
	}

	// Short-circuit /v1/models for ChatGPT-auth: chatgpt.com doesn't
	// expose a /backend-api/codex/models endpoint, so codex's model-
	// list refresher hammers it and logs 401s on every interactive
	// turn. Codex tolerates an empty model list, so return a synthetic
	// 200 and skip the upstream trip entirely. No api_turn is recorded
	// — this isn't an LLM call. Codex 0.128.0+ expects the chatgpt-
	// shaped `{"models":[]}` body, not OpenAI's
	// `{"object":"list","data":[]}` — the latter trips its decoder with
	// "missing field `models`".
	if chatgptAuth && r.Method == http.MethodGet && isModelsPath(r.URL.Path) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"models":[]}`))
		return
	}

	if isWebSocketUpgrade(r) {
		if p.forceChatGPTHTTP && (isChatGPTBackendPath(r.URL.Path) || chatgptAuth) {
			http.Error(w, "observer: ChatGPT websocket disabled; use HTTP fallback", http.StatusUpgradeRequired)
			return
		}
		// G1 (custody blocker on the WS path): when this upgrade resolved to the
		// org AI Gateway, it MUST NOT reach serveUpgradePassthrough — that path
		// forwards the client's original Authorization / X-Api-Key /
		// X-Goog-Api-Key / Api-Key untouched (it strips only hosted-identity
		// query params, never the gateway-credential set, and never attaches the
		// virtual key), which is the exact F1 developer-credential leak, on the
		// WS path. The gateway data plane is HTTP request/response only
		// (internal/aigateway/gwhttp/handler.go has no Upgrade/Hijack shape), so
		// a WS upgrade to it is not a supported request: fail closed. The
		// upstream is never dialed and no developer credential leaves the node.
		if gatewayRouted {
			p.logger.Warn("proxy: refusing websocket upgrade routed to the org AI gateway (HTTP-only data plane)", "path", r.URL.Path)
			http.Error(w, "observer: websocket upgrade is not supported on the org AI gateway", http.StatusBadGateway)
			return
		}
		// The auto lane's target normally depends on the request body's
		// top-level model (resolveAutoLane, below), but this branch exits
		// before the body is ever read — a websocket upgrade request has
		// no JSON body to inspect anyway. Resolve here with an empty
		// model so an unmatched-prefix / no-body request falls straight
		// to the configured default lane, exactly like the body path's
		// "GET without a body" case (bug W1.3b: previously this branch
		// forwarded /up/auto/... upgrades to the placeholder fixed
		// upstream computed above, never reaching the auto lane at all).
		if upstreamLaneID == autoLaneID {
			lanes := p.laneSnapshot()
			resolved, resolvedLane, _, _ := p.resolveAutoLane(lanes, "", nil)
			upstreamLaneID = resolvedLane
			if resolved != nil {
				upstream = resolved
			} else {
				p.warnUnknownUpstreamOnce(autoLaneID, r.URL.Path, len(lanes.upstreams))
			}
			r = r.WithContext(context.WithValue(r.Context(), obsLaneCtxKey{}, upstreamLaneID))
		}
		p.serveUpgradePassthrough(w, r, upstream)
		return
	}

	// Read client request body so we can both forward it and inspect it.
	// Bodies are typically < 100KB (prompts); the MaxBytesReader is a DoS
	// ceiling, not a functional limit — a single client POSTing a multi-GB
	// body would otherwise OOM the daemon (which also serves the dashboard
	// and watcher). 512 MiB is far above any real conversation/image payload.
	reqBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBodyBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			p.logger.Warn("proxy: request body exceeds cap", "max_bytes", maxRequestBodyBytes)
			http.Error(w, "proxy: request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		p.logger.Warn("proxy: read request body", "err", err)
		http.Error(w, "proxy: read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	// Decode a zstd-encoded body ONCE so compression, the guard
	// egress scan, and request-shape parsing all see plain JSON;
	// when anything mutates the body, one re-encode happens below
	// before forwarding. (Pre-G9 the decode lived inside the
	// compressor block; hoisting it means reqShapeBody is plain JSON
	// for zstd traffic even without a compressor configured, so
	// session extraction and cache tracking work on that path too.)
	reqShapeBody := reqBody
	needsReencode := false
	if isZstdEncoded(r.Header.Get("Content-Encoding")) {
		if decoded, derr := decodeZstd(reqBody); derr != nil {
			p.logger.Debug("proxy: skip compressed request body", "encoding", r.Header.Get("Content-Encoding"), "err", derr)
		} else {
			reqShapeBody = decoded
			needsReencode = true
		}
	} else if isGzipEncoded(r.Header.Get("Content-Encoding")) {
		// §3.5 posture: gzip request bodies are NOT decoded before
		// admission/egress — reqShapeBody stays compressed, so admission
		// and egress both no-op (fail-open). Enforce-mode deployments that
		// must classify gzip traffic need a bounded gzip parity path first
		// (docs §9 deferred); until then the app must not gzip requests to
		// the proxy.
		p.logger.Debug("proxy: gzip request body not decoded — admission/egress skip this request (§3.5)")
	}
	// bodyMutated tracks whether reqShapeBody diverged from the bytes
	// the client sent (compression, post-compact injection, or guard
	// masking) and therefore must replace reqBody before forwarding.
	bodyMutated := false

	// Stable per-request correlation id, established BEFORE admit() so the
	// admission/egress audit rows soft-join to the api_turns row (design P0
	// finding: admit() previously omitted the request id, so the join was
	// dead). It is stamped onto the api_turn as the request_id fallback below
	// (the upstream provider's own id still wins when present).
	proxyRequestID := newRequestID()

	// Resolve the pre-mutation top-level model cheaply (design §3.4), so the
	// egress layer matches the model the request carried — before any
	// Channel-B rewrite. gzip-encoded bodies are not decoded (§3.5), so this
	// returns "" for them and egress model matchers simply do not fire.
	topModel := topLevelModel(reqShapeBody)

	// Phase 2 (gateway config plane spec): the virtual "auto" lane routes
	// by the top-level model's prefix (OpenRouter-style), which needs the
	// request body — not available yet when stripUpstreamPrefix ran.
	// Resolve it now, reusing reqShapeBody/topModel (no double-read of the
	// body). topModel itself is left untouched (admission below still sees
	// the pre-rewrite model, matching the Channel-B router's precedent);
	// only reqShapeBody/upstream/upstreamLaneID change. Re-stamp the
	// context so admission/egress/the gateway rail see the RESOLVED lane,
	// never the literal "auto" (obsLaneCtxKey contract).
	if upstreamLaneID == autoLaneID {
		// One Load() for the whole decision (Phase 3): the upstream map
		// and the auto-default lane id must come from the SAME laneTable
		// generation, or a concurrent SetLaneTable/SetUpstreams swap
		// between two independent Loads could resolve a lane id against
		// an upstream map that no longer (or doesn't yet) contain it.
		lanes := p.laneSnapshot()
		resolved, resolvedLane, rewrittenBody, rewrote := p.resolveAutoLane(lanes, topModel, reqShapeBody)
		upstreamLaneID = resolvedLane
		if resolved != nil {
			upstream = resolved
			if rewrote {
				reqShapeBody = rewrittenBody
				bodyMutated = true
			}
		} else {
			// Unresolvable (no prefix match and no usable default lane):
			// fall through exactly like an unknown /up/<id> today — the
			// placeholder `upstream` computed above (p.upstreamForPath)
			// keeps serving, body untouched, warn-once.
			p.warnUnknownUpstreamOnce(autoLaneID, r.URL.Path, len(lanes.upstreams))
		}
		r = r.WithContext(context.WithValue(r.Context(), obsLaneCtxKey{}, upstreamLaneID))
	}

	// Optional pre-forward input-admission (admission spec §6.2 — the
	// secondary seam; the SDK admit() front-door is primary). Runs on the
	// plain-JSON body before any mutation. In enforce mode a blocked
	// request short-circuits with a provider-shaped refusal and is never
	// forwarded; observe mode records the shadow verdict and forwards.
	// nil admitter ⇒ no-op (zero overhead).
	//
	// PLANE BOUNDARY: admission is Plane A — it judges a HOSTED APP's
	// end-user input, so this seam gates only /up/<id> lane traffic. The
	// default provider lanes carry Plane-B coding agents, whose policy
	// layer is internal/guard; running the Plane-A admitter on them both
	// mixed the planes AND — with a remote judge configured — egressed
	// coding-session prompt text to the judge endpoint (operator-reported
	// class, 2026-08-13). Same discriminator as the gateway rail
	// (obsLaneCtxKey).
	//
	// TWO-PHASE persist (admission-trace-linkage spec §1): an allowed verdict
	// keeps its audit row unwritten until the turn's request id resolves, so
	// the row can carry the SAME trace id the synthesized gateway trace uses
	// (the provider-echoed id wins over proxyRequestID, and the row is
	// hash-chained at insert — it can never be corrected afterwards).
	// resolvedRequestID tracks the best id known at any instant; the defer
	// below finalizes exactly once on every exit path, including a panic
	// unwinding through the handler.
	resolvedRequestID := proxyRequestID
	resolveRequestID := func(id string) string {
		resolvedRequestID = orRequestID(id, proxyRequestID)
		return resolvedRequestID
	}
	var admitRes AdmitResult
	if obsUpstreamLane(r) != "" {
		var admitBlock bool
		admitRes, admitBlock = p.admit(r.Context(), provider, reqShapeBody, p.admissionUser(r), proxyRequestID, topModel)
		defer func() { p.finalizeAdmission(admitRes.Finalize, resolvedRequestID) }()
		if admitBlock {
			writeAdmissionRefusal(w, provider, admitRes.Reason)
			p.logger.Info("proxy: admission blocked request",
				"provider", provider, "criterion", admitRes.Criterion)
			return
		}
	}
	// The enforce-mode Plane-A egress directive (nil in advise/off), applied
	// after the Channel-B router block per the §3.6 precedence merge.
	egressRoute := admitRes.Route

	// Optional pre-forward compression (spec §10 Layer 3). Must preserve
	// the request's JSON envelope and scrub any values inside before
	// returning a body to forward. When the compressor returns Skipped or
	// an empty Body, we keep the original request untouched.
	// Prompt-submit intervention PROXY LANE, phase 1 (LIVE CORRECTION
	// 2026-09-07): scan the developer's latest turn on the ORIGINAL
	// body, BEFORE conversation compression. The pipeline forward-scrubs
	// the outbound body (scrub.ScrubForward), so the single
	// post-compression scan below used to see [REDACTED] where the
	// secret was and could never ask-once/block -- two live Codex Desktop
	// turns were silently redacted with no event and no message. Only a
	// PromptPhaseScanner takes this path; the post-compression scan then
	// runs ScanRequestAfterPrompt so the prompt lane is never evaluated
	// twice for one submission.
	promptPhase, twoPhase := p.guard.(PromptPhaseScanner)
	promptSID := ""
	promptAPISessionID := ""
	if twoPhase {
		// Keep the real identity separate from the guard-only scope. The
		// latter may be a local fallback for session-less clients, but it
		// must never land in api_turns, traces, or cost attribution.
		promptAPISessionID = p.resolveAPITurnSessionID(r, provider, reqShapeBody)
		promptSID = resolvePromptGuardScopeID(r, promptAPISessionID,
			promptGuardUpstreamID(upstreamLaneID, provider), provider)
		pr := promptPhase.ScanPrompt(r.Context(), provider, reqShapeBody, promptSID)
		switch pr.Action {
		case "prompt_deny":
			p.serveGuardPromptDeny(w, r, provider, pr, reqShapeBody, promptAPISessionID)
			return
		case "deny":
			p.serveGuardDeny(w, r, provider, pr, reqShapeBody, promptAPISessionID)
			return
		case "mask":
			// Same json.Valid backstop as the post-compression mask
			// branch: a structurally invalid masked body is dropped in
			// favour of the original rather than forwarded.
			if len(pr.Body) > 0 && json.Valid(pr.Body) {
				reqShapeBody = pr.Body
				bodyMutated = true
			}
		}
	}

	var compression CompressionResult
	if p.compressor != nil {
		compressionInput := reqShapeBody
		// v1.4.43+ / Tier 3 / D23: pre-compression post-compact context
		// injection. When the session has a recent compaction event in
		// the observer DB, prepend a synthetic system block carrying
		// recovery context (last reads, last edits, recent failures,
		// learned rules) so the model can re-orient without re-Reading
		// every file. Runs after zstd-decode so injectAnthropicSystemBlock
		// sees plain JSON; runs before compression so the compressor
		// sees the injected body. The injector caches per compaction
		// event — the prepended bytes are stable turn-over-turn and
		// Anthropic's prefix cache hits hold across the post-compact
		// conversation.
		injected := false
		if p.postCompact != nil && provider == models.ProviderAnthropic {
			sid := extractAnthropicSessionID(compressionInput)
			if sid != "" {
				if content, err := p.postCompact.Get(r.Context(), sid); err == nil && content != "" {
					if mutated, ierr := injectAnthropicSystemBlock(compressionInput, content); ierr == nil && len(mutated) > 0 {
						compressionInput = mutated
						reqShapeBody = mutated
						injected = true
					} else if ierr != nil {
						p.logger.Debug("proxy: post-compact inject failed", "session_id", sid, "err", ierr)
					}
				}
			}
		}
		// v1.4.42+: when the compressor implements SessionAwareCompressor
		// and the body carries a session_id (Claude Code SDK's metadata
		// blob, or codex's prompt_cache_key), thread it through so
		// session-scoped features (rolling-summ, read-cache) can fire on
		// the right session. Falls back to the base Compress() path when
		// neither side supports it OR when the provider has no extractor.
		//
		// Codex parity: extractOpenAISessionID reads prompt_cache_key
		// from the Responses API body. Header fallback reads `session_id`
		// HTTP header (same value in observed traffic). Auth-cache
		// stores Bearer tokens for both API-key (sk-...) and ChatGPT-Plus
		// JWT (eyJ...) shapes — the OpenAI summariser picks the right
		// one when calling the Responses API.
		if sac, ok := p.compressor.(SessionAwareCompressor); ok && (provider == models.ProviderAnthropic || provider == models.ProviderOpenAI) {
			var sid string
			switch provider {
			case models.ProviderAnthropic:
				sid = extractAnthropicSessionID(compressionInput)
			case models.ProviderOpenAI:
				sid = extractOpenAISessionID(compressionInput)
				if sid == "" {
					// Header fallback: codex puts the same UUID on
					// `session_id` / `thread_id` / `x-client-request-id`.
					// Body extract should normally hit; this catches edge
					// cases where the body lost the prompt_cache_key
					// (older codex builds, custom upstreams, or a turn
					// where the SDK omits it).
					sid = r.Header.Get("session_id")
				}
			}
			// D20: capture per-session Authorization / x-api-key so the
			// rolling-summ Summarizer can call upstream with the same
			// auth the proxy is forwarding. Done before invoking the
			// compressor so an in-flight summary call sees fresh
			// credentials. No-op when AuthCache is unset.
			if p.authCache != nil && sid != "" {
				p.authCache.Set(sid, AuthCredentials{
					Authorization: r.Header.Get("Authorization"),
					APIKey:        r.Header.Get("x-api-key"),
				})
			}
			// V7-2: once-per-session warning when an OpenAI-shape request
			// targets a codex-variant model (gpt-5.3-codex family) while
			// `compress_types` is non-empty. Logs are pinned at
			// docs/codex-compression-recipe.md; no-op for Anthropic
			// requests (no codex-variant Anthropic models) and for
			// requests that don't carry a session_id.
			if provider == models.ProviderOpenAI {
				p.maybeWarnCodexVariantModel(sid, extractOpenAIModel(compressionInput))
			}
			// Track R: when the compressor routes per profile, pass the
			// full request class — provider plus the pidbridge-resolved
			// owning tool (R2) and its session CWD (R3 project
			// overrides). Best-effort — empty fields degrade tier by
			// tier down to per-provider resolution.
			if cac, ok := p.compressor.(ClassAwareCompressor); ok {
				compression = cac.CompressInSessionClass(r.Context(), p.requestClass(r, provider), compressionInput, sid)
			} else {
				compression = sac.CompressInSession(r.Context(), provider, compressionInput, sid)
			}
		} else {
			compression = p.compressor.Compress(r.Context(), provider, compressionInput)
		}
		switch {
		case !compression.Skipped && len(compression.Body) > 0 && json.Valid(compression.Body):
			reqShapeBody = compression.Body
			bodyMutated = true
			p.recordCompression(r.Context(), provider, compression)
		case !compression.Skipped && len(compression.Body) > 0:
			// HARD GUARD (correctness over savings): the compressor returned
			// a non-empty body that is NOT valid JSON. Forwarding it makes
			// the upstream reject the whole request (400 "unexpected
			// character"), which silently breaks and cascades the live
			// session as its context grows past the size where the
			// compressor mangles the body. Never forward an unparseable
			// body — drop compression for this request and fall back to the
			// pre-compression bytes (the post-compact-injected form when
			// injected, else the untouched original). A config that turns
			// conversation compression on can no longer corrupt requests.
			p.logger.Warn("proxy: compressor emitted invalid JSON — forwarding pre-compression body (compression skipped for this request)",
				"provider", provider,
				"input_bytes", len(compressionInput),
				"output_bytes", len(compression.Body))
			if injected {
				// reqShapeBody already carries the injected (valid) form.
				bodyMutated = true
			}
		case injected:
			// Compression skipped (zero events fired) but we did mutate
			// the body via post-compact injection. Forward the injected
			// bytes upstream rather than the pre-injection original.
			// reqShapeBody already carries the injected form.
			bodyMutated = true
		}
	}

	// Resolve the session_id that lands on the api_turn row (and feeds
	// the guard's session-scoped state). Lookup order:
	//   - Anthropic: extractAnthropicSessionID (metadata.user_id from
	//     Claude Code SDK) → X-Session-Id header → SessionResolver.
	//   - OpenAI: extractOpenAISessionID (prompt_cache_key) →
	//     `session_id` / `thread_id` / `x-client-request-id` header
	//     fallback (codex emits the same UUID on each) → X-Session-Id
	//     header → SessionResolver. Pre-V4-4, OpenAI requests skipped
	//     the body+header fallback at this insert site entirely, so
	//     ChatGPT-Plus auth turns (which drop prompt_cache_key from
	//     the body) always landed with `session_id = ""` and collapsed
	//     to `<unattributed>` in `observer cost --group-by session`.
	// Hoisted above the forward (G9) so the guard scan sees it; the
	// inputs are identical to the old post-response call site.
	// Two-phase scanners already resolved the id on the ORIGINAL body
	// in phase 1; reuse it rather than re-parsing the (now possibly
	// compressed) body — both serializers preserve the envelope fields
	// this reads (prompt_cache_key / metadata.user_id), so the ids agree,
	// and the reconsider-once fingerprint stays on one session id.
	sessionID := promptAPISessionID
	if !twoPhase {
		sessionID = p.resolveAPITurnSessionID(r, provider, reqShapeBody)
	}
	guardSessionID := sessionID
	// Phase 2 is the egress/injection/MCP guard path, not the prompt
	// reconsider path. Keep its identity on the real API session (empty
	// when unresolved); a prompt-only fallback must not affect its
	// deduplication, taint, budget, or approval semantics.

	// Guard egress scan + injection heuristics (guard spec §8.1/§8.2/
	// §8.4): ONE call on the final outbound body — after compression,
	// the same bytes cachetrack hashes — for both providers. Proxy-
	// only, zero effect on other paths (the compression precedent).
	if p.guard != nil {
		var gr GuardRequestResult
		if twoPhase {
			gr = promptPhase.ScanRequestAfterPrompt(r.Context(), provider, reqShapeBody, guardSessionID)
		} else {
			gr = p.guard.ScanRequest(r.Context(), provider, reqShapeBody, sessionID)
		}
		switch gr.Action {
		case "deny":
			// §8.5: synthetic 403 with a provider-shaped error body
			// carrying the rule ID — never a connection drop.
			p.serveGuardDeny(w, r, provider, gr, reqShapeBody, sessionID)
			return
		case "prompt_deny":
			// Prompt-submit intervention PROXY LANE (contract §3): a
			// provider-shaped error body written for the DEVELOPER, at
			// gr.Status (400 for a fresh ask-once interrupt, 403 for an
			// unconditional block — never 429, never a 5xx).
			p.serveGuardPromptDeny(w, r, provider, gr, reqShapeBody, sessionID)
			return
		case "mask":
			// Adopt the masked body only when it is still valid JSON — the
			// same backstop the compression path uses (proxy.go json.Valid
			// guard). A mask rule that emitted structurally-invalid JSON would
			// otherwise be forwarded, drawing an upstream 400 and silently
			// cascading the live session (the ~214KB invalid-JSON class).
			if len(gr.Body) > 0 && json.Valid(gr.Body) {
				reqShapeBody = gr.Body
				bodyMutated = true
			} else if len(gr.Body) > 0 {
				p.logger.Warn("proxy: guard mask produced invalid JSON; forwarding original body",
					"session_id", sessionID)
			}
		}
	}

	// include-usage injection (aider capture gap, 2026-08-21): OpenAI Chat
	// Completions streams carry NO usage unless the caller sets
	// stream_options.include_usage — aider/LiteLLM counts tokens client-side
	// instead, so proxied turns landed api_turns rows with 0/0 tokens even
	// though the tool displayed real counts. Inject the option into
	// streaming chat-completions bodies on the DEFAULT api.openai.com lane
	// when absent (never on /up/<id> custom upstreams — third-party
	// OpenAI-compatible servers may reject the field; never on the Responses
	// API, which reports usage natively). Fail-open: any parse surprise
	// forwards the original body.
	if provider == models.ProviderOpenAI && explicitUpstream == nil && upstreamLaneID == "" &&
		strings.Contains(r.URL.Path, "/chat/completions") {
		if mutated, ok := injectOpenAIIncludeUsage(reqShapeBody); ok {
			reqShapeBody = mutated
			bodyMutated = true
			p.logger.Debug("proxy: injected stream_options.include_usage for accurate token capture")
		}
	}

	// Request shape, pre-forward. The single parseRequest pass also
	// feeds cache-tracking enumeration and the post-response turn
	// build; hoisting it here (it previously ran after the upstream
	// round-trip, on the same bytes) lets the routing seam see the
	// shape without a second parse. Parsed AFTER the guard scan so a
	// guard mask is reflected in the shape the router sees.
	reqShape := parseRequest(reqShapeBody)
	if isChatGPTBackendPath(r.URL.Path) {
		if items := summarizeResponsesInput(reqShapeBody); len(items) > 0 {
			p.logger.Debug("proxy: chatgpt responses input", "items", items)
		}
	}

	// Channel B routing seam (model-routing spec §R5/§R11). Decide
	// runs pre-forward on the parsed shape; in enforce mode the body's
	// top-level model field is spliced with §R11.2 integrity (every
	// non-model byte preserved). EVERY failure path here — nil router,
	// unparsed model, panic (safeDecide), splice failure, zstd
	// re-encode failure — forwards the ORIGINAL request untouched (G7).
	var routerToken int64
	var fallbackChain []string
	if p.router != nil && reqShape.Model != "" {
		verdict := p.safeDecide(RouterShape{
			Model:                reqShape.Model,
			MessageCount:         reqShape.MessageCount,
			ToolUseCount:         reqShape.ToolUseCount,
			SystemPromptHash:     reqShape.SystemPromptHash,
			Stream:               reqShape.Stream,
			Speed:                reqShape.Speed,
			ServiceTier:          reqShape.ServiceTier,
			PromptTokensEstimate: int64(len(reqShapeBody)) / 4,
		}, RouterSession{
			Provider:    provider,
			SessionID:   sessionID,
			Entitlement: resolveEntitlement(r),
		})
		routerToken = verdict.Token
		fallbackChain = verdict.FallbackModels
		if verdict.Apply {
			mutated := reqShapeBody
			servedModel := reqShape.Model
			changed := false
			if verdict.SelectedModel != "" && verdict.SelectedModel != reqShape.Model {
				if out, ok := rewriteTopLevelModel(mutated, verdict.SelectedModel); ok {
					mutated, servedModel, changed = out, verdict.SelectedModel, true
				} else {
					p.logger.Warn("proxy: model rewrite splice failed; forwarding original", "model", reqShape.Model)
				}
			}
			// Effort routing (§R6.5): replace-only, downshift-only —
			// see effort.go for the G7 contract.
			if verdict.SetEffort != "" {
				if out, effortChanged := rewriteEffortFields(mutated, verdict.SetEffort, provider); effortChanged {
					mutated, changed = out, true
				}
			}
			if changed && p.applyRoutedBody(r, mutated, &reqBody) {
				reqShapeBody = mutated
				// api_turns.model records the SERVED model (§R11.1):
				// error paths build their turn from reqShape, so the
				// shape carries the rewrite from here on. The decision
				// row (router side) holds the original.
				reqShape.Model = servedModel
			}
		}
	}

	// §R11.7 local upstreams: a (possibly routed) model served by a
	// declared local endpoint forwards there instead of the cloud
	// upstream. Health observation is unchanged — the turn lands in
	// api_turns like any other and feeds the same passive breakers.
	if lu, ok := p.localUpstreams[reqShape.Model]; ok {
		upstream = lu
	}

	// Plane-A egress governance (G22 §3.6): applied AFTER the Channel-B router
	// block AND after the localUpstreams lookup, so egress is the last word — a
	// local-upstream entry for a Plane-A-chosen model cannot overwrite a
	// Plane-A upstream. egressRoute is non-nil ONLY in enforce mode (advise
	// evaluates + logs + records, never emits a route). Every splice failure
	// forwards the original (G7); a pinned locality target that cannot be
	// resolved fails CLOSED.
	// Egress realized-outcome tracking (G22 wave 2). egressApplied = the route
	// was put on the wire (body spliced or upstream switched); egressTargetKey =
	// the breaker key of a chosen route_upstream target; egressPinned marks a
	// MustUseTarget locality route the proxy must fail CLOSED on at runtime;
	// preEgressUpstream is the upstream a fail-open route reverts to.
	var (
		egressApplied   bool
		egressTargetKey string
		egressPinned    bool
	)
	preEgressUpstream := upstream
	if egressRoute != nil {
		switch egressRoute.Action {
		case "route_model":
			if egressRoute.Model != "" && egressRoute.Model != reqShape.Model {
				if out, ok := rewriteTopLevelModel(reqShapeBody, egressRoute.Model); ok {
					reqShapeBody, reqShape.Model, bodyMutated = out, egressRoute.Model, true
					egressApplied = true
					// Plane-A model wins: discard any Channel-B fallback chain —
					// it was built off the now-stale model (§3.6 row 1).
					fallbackChain = nil
				} else {
					p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, false, false, egressOutcomeSpliceFail)
					p.logger.Warn("proxy: egress model splice failed; forwarding original", "model", egressRoute.Model)
				}
			}
		case "set_effort":
			if egressRoute.Effort != "" {
				if out, changed := rewriteEffortFields(reqShapeBody, egressRoute.Effort, provider); changed {
					reqShapeBody, bodyMutated, egressApplied = out, true, true
				}
			}
		case "route_upstream":
			if u := p.resolveEgressTarget(egressRoute); u != nil {
				key := u.Host
				switch {
				case p.egressBreaker.Allow(key):
					upstream = u
					egressApplied = true
					egressTargetKey = key
					egressPinned = egressRoute.MustUseTarget
					if egressRoute.MustUseTarget {
						// Pin the target: no fallback-model substitution off it
						// (§3.6 row 4). Same-target retry may still re-dial it.
						fallbackChain = nil
					}
				case egressRoute.MustUseTarget || egressRoute.OnUnavailable == "deny":
					// Breaker OPEN on a pinned locality/sensitive target: fail
					// CLOSED immediately — never dial (never hang), never leak
					// to the default upstream (§3.6 / finding 1).
					p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, false, true, egressOutcomeBreakerOpen)
					p.logger.Warn("proxy: egress target breaker open; failing closed", "upstream", egressRoute.UpstreamID)
					writeAdmissionRefusal(w, provider, "Request must be served by a resource that is unavailable.")
					return
				default:
					// Breaker OPEN on a fail-open convenience route: fall back to
					// the default upstream immediately (never dial the dead
					// target; §3.6 row 5).
					p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, false, false, egressOutcomeBreakerOpen)
					p.logger.Info("proxy: egress target breaker open; failing open to default", "upstream", egressRoute.UpstreamID)
				}
			} else if egressRoute.MustUseTarget || egressRoute.OnUnavailable == "deny" {
				// Pinned locality/sensitive route to an unresolvable target:
				// fail CLOSED (§3.6) — never leak to the default upstream.
				p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, false, true, egressOutcomeFailClosed)
				writeAdmissionRefusal(w, provider, "Request must be served by a resource that is unavailable.")
				return
			}
			// MustUseTarget=false + unresolvable → fall through: fail-open to
			// the current upstream (§3.6 row 5, cost/cohort convenience).
		}
		p.logger.Debug("proxy: egress route applied", "action", egressRoute.Action,
			"rule", egressRoute.RuleName, "upstream", egressRoute.UpstreamID, "model", egressRoute.Model)
	}

	// One re-encode for whatever mutated the plain body. On the
	// (practically impossible) in-memory encode failure the ORIGINAL
	// client bytes forward — a wrong-encoding body would hard-fail
	// upstream, which is worse than losing the mutation; WARN so a
	// dropped guard mask is at least loud.
	if bodyMutated {
		if needsReencode {
			if encoded, eerr := encodeZstd(reqShapeBody); eerr != nil {
				p.logger.Warn("proxy: zstd re-encode mutated request body failed; forwarding original", "err", eerr)
			} else {
				reqBody = encoded
			}
		} else {
			reqBody = reqShapeBody
		}
	}

	// Sol S2 fail-closed gate: when this request resolved via the org AI
	// Gateway (gatewayRouted, Sol S8), a usable virtual key MUST exist
	// before any upstream request is built. Checked here — before outURL/
	// outReq are constructed — so a missing key can never result in the
	// developer's own provider credential being copied onto a gateway-
	// bound request, and never silently falls back to a direct-provider
	// destination (the fallback ladder is separate, explicit config that
	// only a later phase, Sol S10, walks; this is a hard failure, not a
	// fallback trigger).
	var gatewayVirtualKey string
	if gatewayRouted {
		if p.virtualKeySource == nil {
			p.logger.Warn("proxy: gateway mode active but no virtual key source configured")
			http.Error(w, "proxy: AI Gateway auth not provisioned on this node", http.StatusBadGateway)
			return
		}
		key, _, vkErr := p.virtualKeySource.LoadVirtualKey()
		if vkErr != nil || key == "" {
			p.logger.Warn("proxy: gateway mode active but no virtual key available", "err", vkErr)
			http.Error(w, "proxy: AI Gateway auth not provisioned on this node", http.StatusBadGateway)
			return
		}
		gatewayVirtualKey = key
	}

	// Build the upstream request.
	outURL := *upstream
	outURL.Path = joinPath(upstream.Path, upstreamPath)
	outURL.RawQuery = stripHostedIdentityQueryParams(r.URL.RawQuery)

	// Capture the developer's ORIGINAL provider credentials BEFORE any Gateway
	// Mode auth-substitution strips them, so a custody-acked direct fallback can
	// restore whichever shape the direct provider expects (F1). Google carries
	// its key in a header AND/OR the ?key= query param; both are captured.
	origGoogAPIKey := r.Header.Get("X-Goog-Api-Key")
	origAzureAPIKey := r.Header.Get("Api-Key")
	origKeyQuery := credentialQueryParam(r.URL.RawQuery)
	if gatewayRouted {
		// A provider credential also travels in the Gemini ?key= query param —
		// strip it from the gateway-bound URL so the developer's Google
		// credential never reaches the org gateway (F1 custody blocker).
		outURL.RawQuery = stripGatewayCredentialQueryParams(outURL.RawQuery)
	}

	upstreamURL := outURL.String()
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, bytes.NewReader(reqBody))
	if err != nil {
		p.logger.Warn("proxy: build upstream request", "err", err)
		http.Error(w, "proxy: build upstream request", http.StatusBadGateway)
		return
	}
	p.copyRequestHeaders(outReq.Header, r.Header)
	if gatewayRouted {
		// Sol S2 auth-substitution: the developer's own provider credential
		// (however copyRequestHeaders just carried it) must never reach the
		// gateway. Strip EVERY provider-credential header shape — not just
		// Authorization / X-Api-Key but also the Gemini X-Goog-Api-Key and the
		// Azure Api-Key (F1 custody blocker) — then attach the org-issued
		// virtual key. The gateway's own extractKey checks X-Api-Key first
		// (internal/aigateway/gwhttp/handler.go), so that's the header the
		// virtual key rides in on.
		for _, h := range gatewayCredentialHeaders {
			outReq.Header.Del(h)
		}
		outReq.Header.Set("X-Api-Key", gatewayVirtualKey)
	}
	// Force identity response encoding on upstream so we can parse the
	// SSE stream and the non-streaming JSON body. Without this, claude
	// (and most modern HTTP clients) send Accept-Encoding: gzip, br —
	// api.anthropic.com responds with Content-Encoding: gzip — and the
	// streaming parser tees gzip-encoded bytes through `data:`-line
	// pattern matching, finding zero usage fields. The bug is invisible
	// for API-key-auth requests when ANTHROPIC_BASE_URL is hit by
	// scripts/curl that don't request compression, but surfaces hard on
	// the OAuth path where claude's own request always negotiates gzip.
	// Identity-forcing trades a small bandwidth cost (the proxy runs on
	// loopback so it's effectively free) for accurate usage capture.
	outReq.Header.Set("Accept-Encoding", "identity")
	outReq.Host = upstream.Host
	outReq.ContentLength = int64(len(reqBody))

	start := p.now()
	captureNetwork := func(statusCode int, respBody []byte, stream bool, apiTurnID int64, requestID, unavailable string, captureErr error, respHeader http.Header) {
		errText := ""
		if captureErr != nil {
			errText = captureErr.Error()
		}
		p.captureProcessNetwork(r.Context(), networkCaptureInput{
			Provider:     provider,
			SessionID:    sessionID,
			RequestID:    orRequestID(requestID, proxyRequestID),
			APITurnID:    apiTurnID,
			Method:       r.Method,
			URL:          upstreamURL,
			Host:         targetHost(upstreamURL),
			StatusCode:   statusCode,
			Duration:     p.now().Sub(start),
			RequestBody:  reqShapeBody,
			ResponseBody: respBody,
			RequestHead:  outReq.Header,
			ResponseHead: respHeader,
			RequestType:  outReq.Header.Get("Content-Type"),
			ContentType:  contentTypeFrom(respHeader),
			Stream:       stream,
			Error:        errText,
			Unavailable:  unavailable,
		})
	}
	// §R12 reliability wraps the forward: same-target retries +
	// fallback chains, all strictly BEFORE the first client write —
	// the never-retry-after-streamed-bytes rule is structural. A
	// Gateway-Mode request (Sol S8) instead walks the org fallback ladder
	// (primary → fallbacks → terminal policy, Luna L16) — which itself uses
	// forwardReliable per endpoint, so the §R12 semantics are preserved on
	// each rung. A non-gateway request takes the byte-identical single-forward
	// path.
	var resp *http.Response
	if gatewayRouted {
		resp, err = p.walkGatewayLadder(r, outReq, reqBody, reqShapeBody, fallbackChain, provider, &reqShape, gatewayLadderCtx{
			endpoints:         gatewayLadderEndpoints(routeSnap),
			upstreamPath:      upstreamPath,
			rawQuery:          outURL.RawQuery,
			terminal:          routeSnap.orgRoute.terminal,
			custodyAck:        routeSnap.orgRoute.custodyAck,
			generation:        routeSnap.generation,
			provider:          provider,
			origAuthorization: r.Header.Get("Authorization"),
			origAPIKey:        r.Header.Get("X-Api-Key"),
			origGoogAPIKey:    origGoogAPIKey,
			origAzureAPIKey:   origAzureAPIKey,
			origKeyQuery:      origKeyQuery,
		})
	} else {
		resp, err = p.forwardReliable(r, outReq, reqBody, reqShapeBody, fallbackChain, provider, &reqShape)
	}

	// Egress realized-outcome + breaker feedback (G22 wave 2, design §3.6/§6).
	// A route_upstream target's dial outcome trains its breaker so a repeatedly-
	// dead target is short-circuited on the next request. A pinned locality
	// target that failed at runtime fails CLOSED (a provider-shaped refusal, not
	// a raw 502 — data-locality intent). A fail-open convenience target that
	// erred at the transport reverts to the default upstream once (never a byte
	// streamed yet), honoring the "leak to default is acceptable" posture.
	if egressTargetKey != "" {
		p.egressBreaker.Record(egressTargetKey, err == nil && resp.StatusCode < 500)
	}
	egressRealizedReported := false
	if err != nil {
		if egressPinned {
			// A pinned locality/sensitive target that failed at runtime: fail
			// CLOSED with a provider-shaped refusal (not a raw 502) — never leak
			// to the default upstream (§3.6 row 4).
			p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, false, true, egressOutcomeUpstreamErr)
			p.logger.Warn("proxy: egress pinned target failed at runtime; failing closed", "upstream", egressRoute.UpstreamID, "err", err)
			captureNetwork(0, nil, false, 0, "", "upstream_transport_error", err, nil)
			writeAdmissionRefusal(w, provider, "Request must be served by a resource that is unavailable.")
			return
		}
		if egressTargetKey != "" {
			// A fail-open convenience target that erred at the transport: re-
			// forward to the default upstream once (never a byte streamed yet),
			// honoring the "leak to default is acceptable" posture (§3.6 row 5).
			if fo, foErr := p.forwardEgressFailOpen(r, preEgressUpstream, upstreamPath, reqBody); foErr == nil {
				p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, false, false, egressOutcomeFallbackOpen)
				egressRealizedReported = true
				p.logger.Info("proxy: egress target failed; failed open to default upstream", "upstream", egressRoute.UpstreamID)
				resp, err = fo, nil
			}
		}
	}
	if err != nil {
		// Spec §17: proxy upstream failure — forward an error. Don't swallow.
		p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, false, false, egressOutcomeUpstreamErr)
		p.logger.Warn("proxy: upstream error", "provider", provider, "err", err)
		captureNetwork(0, nil, false, 0, "", "upstream_transport_error", err, nil)
		http.Error(w, fmt.Sprintf("proxy: upstream: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Successful forward: report the realized egress outcome. Applied is true
	// only when the route was put on the wire AND the target returned a
	// non-error response (design §7 "did the rewritten request actually go to
	// the directed target and succeed"). Suppressed when a fail-open re-forward
	// already recorded the fallback (that request did NOT reach the target).
	if egressApplied && !egressRealizedReported {
		p.reportEgressRealized(r.Context(), egressRoute, proxyRequestID, resp.StatusCode < 400, false, egressOutcomeApplied)
	}

	// Copy upstream headers and status to the client.
	copyResponseHeaders(w.Header(), resp.Header)
	// Limit-snapshot capture (predictor limit half). resp.Header is live
	// here for EVERY response shape — streaming, non-streaming, error/429 —
	// so one graft covers all four R2 cases uniformly. Additive: not
	// threaded through the turn builders.
	p.captureLimitSnapshot(resp.Header, provider, sessionID)
	w.WriteHeader(resp.StatusCode)

	contentType := resp.Header.Get("Content-Type")
	// chatgpt.com/backend-api/codex/responses returns SSE bodies with an
	// empty/missing Content-Type header (verified against codex 0.129.0+;
	// fixture: testdata/chatgpt_codex_responses_sse.bin). The looksLikeSSE
	// fallback below recovers the api_turn metadata after-the-fact, but
	// without forcing the streaming path here, the response is buffered
	// in io.ReadAll → codex's app-server inner-pipe "wait for first byte"
	// timeout (~15 s) trips, codex emits `Reconnecting... N/5 (timeout
	// waiting for child process to exit)`, and each turn takes ~2 min
	// wall instead of ~10 s. See docs/observer-platform-issues-v4.md V4-1.
	isStream := strings.HasPrefix(contentType, "text/event-stream") || chatgptAuth
	// V6-3 defense-in-depth: on the streaming path only, flush
	// upstream status+headers immediately so codex's inner pipe has
	// SOMETHING to consume before the first SSE event arrives. Gated
	// on isStream because flushing in the non-stream path would let
	// the client read the response before the synchronous
	// insertTurnDetached completes — racing tests that check sink
	// state immediately after http.Post returns.
	if isStream {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	if isStream {
		captured := p.teeStream(r.Context(), w, resp.Body)
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Upstream returned an error status. The captured body might
			// be either a plain JSON error (when the upstream returned
			// non-200 immediately, before any SSE preamble) or an SSE
			// `event: error` envelope. Try the SSE shape first; fall
			// back to direct parse.
			errBody := extractStreamErrorBody(captured)
			if errBody == nil {
				errBody = captured
			}
			turn := buildErrorTurn(provider, reqShape, errBody, resp.Header, resp.StatusCode, start, sessionID)
			turn.RequestID = resolveRequestID(turn.RequestID)
			stampRoute(&turn, gatewayRouted, routeGeneration)
			p.applyCost(&turn)
			errTurnID := p.insertTurnDetached(turn, routerToken, "proxy: insert error api_turn (stream)")
			p.synthesizeObsTrace(turn, errTurnID, r, reqShapeBody, errBody)
			captureNetwork(resp.StatusCode, captured, true, 0, turn.RequestID, "", nil, resp.Header)
			return
		}
		turn := p.buildStreamTurn(provider, reqShape, captured, resp.Header, start, sessionID)
		turn.RequestID = resolveRequestID(turn.RequestID)
		stampRoute(&turn, gatewayRouted, routeGeneration)
		var apiTurnID int64
		switch {
		case turn.Model == "":
			// Model never resolved — no turn to record.
		case isEmptyUsage(turn) && !hasCompressionEvidence(compression) && !chatgptAuth:
			// Stream delivered headers + message_start (model is set) but
			// never produced a usage-bearing delta — likely a cancelled
			// request or short-circuited upstream. Recording a zero-token
			// turn pollutes averages and inflates turn counts. See audit
			// item B2. Exceptions: (1) when Observer itself compressed the
			// request, keep the turn so compression telemetry remains
			// visible even if the upstream omitted usage; (2) when the
			// request transited the ChatGPT-auth path, keep the turn
			// regardless — chatgpt.com's SSE usage shape can differ from
			// api.openai.com's and we'd rather log a partial turn than
			// silently drop the A/B baseline.
			p.logger.Debug("proxy: dropping zero-usage stream turn", "model", turn.Model)
		default:
			applyCompressionMeta(&turn, compression)
			p.applyCost(&turn)
			apiTurnID = p.insertTurnAndCacheDetached(turn, reqShape, provider, routerToken, "proxy: insert api_turn (stream)")
			p.synthesizeObsTrace(turn, apiTurnID, r, reqShapeBody, captured)
		}
		captureNetwork(resp.StatusCode, captured, true, apiTurnID, turn.RequestID, "", nil, resp.Header)
		// Guard response inspection (§8.3): the captured SSE carries
		// the model's intended next actions; the client already has
		// its bytes (teeStream forwarded them), so this is off the
		// latency path. Run AFTER the insert so the verdict anchors to
		// the api_turn (apiTurnID 0 when the turn was dropped).
		p.inspectResponseGuard(provider, sessionID, captured, true, apiTurnID)
		return
	}

	// Non-streaming: buffer the full body so we can inspect + forward.
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		p.logger.Warn("proxy: read upstream body", "err", err)
		captureNetwork(resp.StatusCode, nil, false, 0, "", "response_read_error", err, resp.Header)
		return
	}
	if _, err := w.Write(respBody); err != nil {
		p.logger.Warn("proxy: write client body", "err", err)
		captureNetwork(resp.StatusCode, respBody, false, 0, "", "", err, resp.Header)
		return
	}
	// SSE content-sniffing: chatgpt.com/backend-api/codex/responses
	// (observed 2026-05-08 against codex 0.129.0) returns SSE bodies
	// with an empty/missing Content-Type header, which means the
	// `Content-Type: text/event-stream` check above mis-classified the
	// stream as non-streaming. Sniff the body prefix as a fallback so
	// the SSE parser actually runs — without this, parseOpenAIResponse
	// fails to JSON-unmarshal the SSE body, returns Model="", and the
	// proxy silently drops the turn with no api_turns row.
	if !isStream && looksLikeSSE(respBody) {
		// Non-2xx error already handled above; skip to the success path.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			turn := p.buildStreamTurn(provider, reqShape, respBody, resp.Header, start, sessionID)
			turn.RequestID = resolveRequestID(turn.RequestID)
			stampRoute(&turn, gatewayRouted, routeGeneration)
			var apiTurnID int64
			switch {
			case turn.Model == "":
				// Model never resolved — no turn to record.
			case isEmptyUsage(turn) && !hasCompressionEvidence(compression) && !chatgptAuth:
				p.logger.Debug("proxy: dropping zero-usage sniffed-SSE turn", "model", turn.Model)
			default:
				applyCompressionMeta(&turn, compression)
				p.applyCost(&turn)
				apiTurnID = p.insertTurnAndCacheDetached(turn, reqShape, provider, routerToken, "proxy: insert api_turn (sniffed SSE)")
				p.synthesizeObsTrace(turn, apiTurnID, r, reqShapeBody, respBody)
			}
			captureNetwork(resp.StatusCode, respBody, true, apiTurnID, turn.RequestID, "", nil, resp.Header)
			p.inspectResponseGuard(provider, sessionID, respBody, true, apiTurnID)
			return
		}
	}

	// Non-2xx — record a zero-token error turn so the failure is
	// visible. Pre-v1.4.20 the proxy returned early here, silently
	// dropping rate-limit / overloaded / invalid-request errors. Now
	// the parsed error envelope (Anthropic / OpenAI standard shape)
	// lands on api_turns.{http_status, error_class, error_message}.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		turn := buildErrorTurn(provider, reqShape, respBody, resp.Header, resp.StatusCode, start, sessionID)
		turn.RequestID = resolveRequestID(turn.RequestID)
		stampRoute(&turn, gatewayRouted, routeGeneration)
		p.applyCost(&turn)
		errTurnID := p.insertTurnDetached(turn, routerToken, "proxy: insert error api_turn")
		p.synthesizeObsTrace(turn, errTurnID, r, reqShapeBody, respBody)
		captureNetwork(resp.StatusCode, respBody, false, 0, turn.RequestID, "", nil, resp.Header)
		return
	}

	turn := p.buildTurn(provider, reqShape, respBody, resp.Header, start, sessionID)
	turn.RequestID = resolveRequestID(turn.RequestID)
	stampRoute(&turn, gatewayRouted, routeGeneration)
	var apiTurnID int64
	switch {
	case turn.Model == "":
		// Model never resolved — no turn to record.
	case isEmptyUsage(turn) && !hasCompressionEvidence(compression) && !chatgptAuth:
		p.logger.Debug("proxy: dropping zero-usage turn", "model", turn.Model)
	default:
		applyCompressionMeta(&turn, compression)
		p.applyCost(&turn)
		apiTurnID = p.insertTurnAndCacheDetached(turn, reqShape, provider, routerToken, "proxy: insert api_turn")
		p.synthesizeObsTrace(turn, apiTurnID, r, reqShapeBody, respBody)
	}
	captureNetwork(resp.StatusCode, respBody, false, apiTurnID, turn.RequestID, "", nil, resp.Header)
	p.inspectResponseGuard(provider, sessionID, respBody, false, apiTurnID)
}

// serveGuardDeny writes the §8.5 synthetic 403 (provider-shaped error
// body carrying the rule ID) and records a zero-token error api_turn
// so the denial is visible on the cost/timeline surfaces like any
// other failed request.
func (p *Proxy) serveGuardDeny(w http.ResponseWriter, r *http.Request, provider string, gr GuardRequestResult, reqShapeBody []byte, sessionID string) {
	status := gr.Status
	if status == 0 {
		status = http.StatusForbidden
	}
	body := guardDenyBody(provider, gr.RuleID, gr.Reason, gr.HumanLine, status)
	p.writeGuardErrorTurn(w, r, provider, body, status, reqShapeBody, sessionID, "proxy: write guard-deny body", "proxy: insert guard-denied api_turn")
}

// serveGuardPromptDeny writes the prompt-submit intervention PROXY
// LANE's own deny (contract §3): a provider-shaped error body written
// for the DEVELOPER (guardPromptDenyBody, not guardDenyBody's
// agent-facing egress framing), at gr.Status (400 for a fresh
// ask-once interrupt, 403 for an unconditional block — an unset
// Status defaults to 403, the same conservative default serveGuardDeny
// uses).
//
// F8 (phase-3b review): gr.Status is a value the guard scanner sets
// (guard.promptDenyStatus), not an HTTP status this package trusts
// blindly from another package's arithmetic — contract §3.3 is
// explicit that only {400, 403} are ever safe here (never 429, which
// every major SDK retries by default and would silently "confirm" an
// interrupt the developer never read; never a 5xx). Any OTHER value —
// a future guard-side bug, or an already-caught regression — is
// clamped to the conservative 403 default, with a warn log so the
// underlying bug is visible rather than silently shipping an unsafe
// status to a live client.
func (p *Proxy) serveGuardPromptDeny(w http.ResponseWriter, r *http.Request, provider string, gr GuardRequestResult, reqShapeBody []byte, sessionID string) {
	status := gr.Status
	switch status {
	case http.StatusBadRequest, http.StatusForbidden:
		// contract §3.3's exact two safe values — pass through as-is.
	default:
		if status != 0 {
			p.logger.Warn("proxy: guard prompt-deny Status outside the contract's {400,403} set; clamping to 403",
				"status", status, "session_id", sessionID)
		}
		status = http.StatusForbidden
	}
	body := guardPromptDenyBody(provider, gr.Reason, status)
	p.writeGuardErrorTurn(w, r, provider, body, status, reqShapeBody, sessionID, "proxy: write guard-prompt-deny body", "proxy: insert guard-prompt-denied api_turn")
}

// writeGuardErrorTurn is the shared write-response + record-error-turn
// tail both serveGuardDeny and serveGuardPromptDeny use — the only
// difference between the two callers is which body-builder produced
// body and which status code applies.
func (p *Proxy) writeGuardErrorTurn(w http.ResponseWriter, r *http.Request, provider string, body []byte, status int, reqShapeBody []byte, sessionID, writeErrLog, insertErrLog string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		p.logger.Warn(writeErrLog, "err", err)
	}
	turn := buildErrorTurn(provider, parseRequest(reqShapeBody), body, http.Header{}, status, p.now(), sessionID)
	p.applyCost(&turn)
	// routerToken 0: a guard-denied request is refused before the
	// routing seam runs, so there is no decision row to anchor.
	denyTurnID := p.insertTurnDetached(turn, 0, insertErrLog)
	p.synthesizeObsTrace(turn, denyTurnID, r, reqShapeBody, body)
}

// inspectResponseGuard extracts the response's tool_use blocks and
// hands them to the guard scanner (§8.3). Called only on success
// paths AFTER the client has its bytes — added latency lands on the
// persistence tail, not the request. Detached context: the client may
// close its connection the instant the stream ends (the
// insertTurnDetached precedent).
//
// apiTurnID is the api_turn this response was captured as (0 when the turn
// was dropped — e.g. zero-usage — or no turn was inserted). It anchors the
// persisted guard verdict to the turn so the obs trajectory enrichment can
// surface the verdict on that span (P6 GuardVerdict follow-up). Called AFTER
// the turn insert so the id is known; still off the latency path since both
// run after the client has its bytes.
func (p *Proxy) inspectResponseGuard(provider, sessionID string, body []byte, isStream bool, apiTurnID int64) {
	if p.guard == nil {
		return
	}
	tools := extractToolUses(provider, body, isStream)
	if len(tools) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p.guard.InspectResponse(ctx, sessionID, apiTurnID, tools)
}

// insertTurnDetached writes turn to the sink on a context derived from
// context.Background() with a 10 s timeout, so a client that closes
// its read side promptly after the stream ends doesn't cancel the SQL
// insert mid-flight. Mirrors the proxy.go shutdownCtx idiom — when
// persistence MUST complete even though the request-scoped context
// has died, the call has to ride a detached context.
//
// The race the detached context closes: serve() finishes teeStream
// once the upstream body is fully consumed, then constructs the
// api_turn and calls the sink. SQLite's BeginTx + write under WAL
// contention takes a handful of ms — long enough for a fast client
// (codex 0.130+ closes its connection the instant the final SSE event
// lands) to win the race and cancel r.Context(). Before this helper,
// every codex turn dropped silently with `proxy: insert api_turn
// (stream): store.InsertAPITurn: context canceled`.
//
// Errors are logged at WARN under the supplied label and never
// propagate — the upstream response is already delivered; the
// api_turn is a best-effort persistence side effect.
//
// Returns the inserted api_turn id (0 on failure) so a caller can anchor
// downstream records (e.g. the response-inspection guard verdict) to it.
func (p *Proxy) insertTurnDetached(turn models.APITurn, routerToken int64, label string) int64 {
	insertCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := p.sink.InsertAPITurn(insertCtx, turn)
	if err != nil {
		p.logger.Warn(label, "err", err)
		return 0
	}
	p.recordServedSafe(routerToken, id, turn.Model)
	return id
}

// insertTurnAndCacheDetached writes turn to the sink AND — when
// the cache engine is wired — runs cache observation per spec §8
// (C8) on the same detached context. The api_turn insert is the
// authoritative source of the api_turn_id used to anchor
// cache_segments + cache_events; when the upstream insert fails
// the cache rows are dropped (WARN, do not retry — per spec §8:
// "Failure to write cache rows must NOT fail the turn insert").
//
// Provider routing — the OBSERVE-INPUT BUILDER picks the shape
// per CLAUDE.md rule 3 (branch on capability, never on source
// identity downstream). Anthropic + request CacheBlocks →
// marker-aware ObserveInput; OpenAI / OpenAI-compatible →
// implicit-cache ObserveInput with Capabilities.ImplicitCache
// overlaid (§15.3, see [buildOpenAIImplicitObserveInput]). The
// engine never sees the provider string — it dispatches on the
// capability alone.
//
// Behaviour is identical to insertTurnDetached when the engine
// isn't wired or the builder returns ok=false.
//
// Returns the inserted api_turn id (0 on failure), so the success path can
// anchor the response-inspection guard verdict to the same turn.
func (p *Proxy) insertTurnAndCacheDetached(turn models.APITurn, reqShape requestShape, provider string, routerToken int64, label string) int64 {
	insertCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	apiTurnID, err := p.sink.InsertAPITurn(insertCtx, turn)
	if err != nil {
		p.logger.Warn(label, "err", err)
		return 0
	}
	p.recordServedSafe(routerToken, apiTurnID, turn.Model)
	if p.cacheEngine == nil {
		return apiTurnID
	}
	in, ok := p.buildCacheObserveInput(turn, reqShape, provider, apiTurnID)
	if !ok {
		return apiTurnID
	}
	result := p.cacheEngine.ObserveTurn(in)
	if p.cacheSink == nil {
		return apiTurnID
	}
	if err := p.cacheSink.PersistCacheObservation(insertCtx, in, result, apiTurnID, 0); err != nil {
		// Per spec §8: WARN only, never fail the turn.
		p.logger.Warn("proxy: cache observation persist failed", "err", err, "label", label)
	}
	return apiTurnID
}

// synthesizeObsTrace is the gateway-rail seam call site (Options.ObsSink):
// fire-and-forget hand-off of one already-inserted api_turn so the sink can
// synthesize a Plane-A chat.turn/chat.completions trace pair. Called from
// every insertTurnDetached / insertTurnAndCacheDetached call site AFTER the
// insert has returned.
//
// No-op when ObsSink is nil (the default) or apiTurnID is 0 (the insert
// itself failed — nothing durable to anchor the trace to). Otherwise the
// facts are projected synchronously (cheap: struct fields + one header read)
// and the actual sink call — the part that touches the obs store — is
// spawned on its own goroutine with its own detached 10s context (the
// captureProcessNetwork precedent), so a slow or hung sink can NEVER add
// latency to the response path, only to how promptly its trace appears.
// Fail-open two ways: a panic inside the goroutine is recovered (never
// crashes the proxy) and a returned error is logged at DEBUG (unlike the
// WARN-level cache/network sinks — a missing trace is a lower-severity miss
// than a missing cache/network row); neither ever affects the turn, which is
// already durably recorded.
//
// reqBody/respBody are the raw HTTP bodies for this call (whichever the
// caller already has in hand — see each call site), threaded through
// unparsed (but bounded — see obsGatewayMaxBodyBytes) for the sink's own
// content extraction (docs/observability.md "proxy turn (automatic)");
// either may be nil.
//
// Bounded, fail-open two ways (Finding F3, round-2 adversarial review):
// bodies are clipped to obsGatewayMaxBodyBytes BEFORE they're handed to the
// goroutine (bounds per-in-flight memory), and in-flight synthesis
// concurrency is capped at obsGatewayMaxConcurrentSynthesis via obsSem — when
// saturated, this call's trace is simply DROPPED (logged at DEBUG) rather
// than queued or blocking; the underlying api_turns row this trace would
// have anchored to is already durably recorded regardless.
//
// Lane B (trajectory-ui-rollup-and-spandetail-fixes spec): when
// Options.ObsContentExtractor is wired, the clip-then-hand-off scheme above
// is bypassed entirely for content purposes — the extractor runs
// SYNCHRONOUSLY over the FULL, unclipped bodies before the goroutine even
// spawns, and only its own bounded text output is retained on ChatTurnFacts
// (Request/ResponseBody go nil). Memory is bounded at the SOURCE in that
// mode — by the extractor's own output bound, not by obsGatewayMaxBodyBytes
// — which is what fixes the truncation class obsGatewayMaxBodyBytes'
// blind head/tail clip could not: it discarded real content whenever the
// interesting bytes fell outside the kept 64 KiB. The concurrency bound
// (obsSem) is unchanged either way — it gates only the goroutine below, and
// the (now-synchronous) extractor call happens before that gate is even
// reached.
func (p *Proxy) synthesizeObsTrace(turn models.APITurn, apiTurnID int64, r *http.Request, reqBody, respBody []byte) {
	if p.obsSink == nil || apiTurnID == 0 {
		return
	}
	// PLANE BOUNDARY: Plane-A trace synthesis is for HOSTED-APP traffic
	// only — requests that arrived on an explicit /up/<id> upstream lane.
	// The default provider lanes carry Plane-B coding agents (Claude Code,
	// codex, gemini, …), whose observability rail is api_turns → sessions →
	// the coding-agent org rollups; synthesizing them here put coding-agent
	// turns (and their content) into the Hosted Apps Trajectory explorer,
	// mixing the two planes (operator-reported defect, 2026-08-13).
	if obsUpstreamLane(r) == "" {
		return
	}
	// Session identity: EXPLICIT headers only. turn.SessionID deliberately
	// does NOT feed the trace — resolveAPITurnSessionID's SessionResolver
	// fallback attributes otherwise-unattributed proxy turns to a recent
	// CODING-AGENT session (correct for Plane-B cost rollups, actively
	// wrong as a hosted-app conversation id: live WebUI turns were observed
	// grouped under a codex session). Accepted, in order: X-Session-Id,
	// then the hosted-app conversation headers (X-Superbased-Session /
	// X-OpenWebUI-Chat-Id — the same list resolveAPITurnSessionID lifts on
	// /up lanes; without them here the api_turns row groups by conversation
	// while the synthesized trace stays ungrouped, the harness/OWUI blank
	// session_id class, 2026-08-14). No header ⇒ no session — the honest
	// empty value; end-user identity still arrives via User below.
	facts := ChatTurnFacts{
		APITurnID:           apiTurnID,
		RequestID:           turn.RequestID,
		SessionID:           explicitHostedSessionID(r),
		User:                p.admissionUser(r),
		Provider:            turn.Provider,
		Model:               turn.Model,
		Timestamp:           turn.Timestamp,
		TotalResponseMS:     turn.TotalResponseMS,
		TimeToFirstTokenMS:  turn.TimeToFirstTokenMS,
		InputTokens:         turn.InputTokens,
		OutputTokens:        turn.OutputTokens,
		CacheReadTokens:     turn.CacheReadTokens,
		CacheCreationTokens: turn.CacheCreationTokens,
		CostUSD:             turn.CostUSD,
		StopReason:          turn.StopReason,
		HTTPStatus:          turn.HTTPStatus,
		ErrorClass:          turn.ErrorClass,
		ErrorMessage:        turn.ErrorMessage,
	}
	// Lane B (extract-before-clip): when an extractor is wired, run it
	// SYNCHRONOUSLY, here, over the FULL uncopied bodies — before any
	// clipping and before the fire-and-forget goroutine spawns below. This
	// closes the truncation class the clip-then-extract order created (a
	// tail-clipped SSE stream losing its head; a head-clipped >64 KiB
	// request losing its prompt entirely): the extractor sees everything.
	// Request/ResponseBody are left nil in this mode — the extractor's
	// output is already bounded (its own content-clip bound) and
	// authoritative, so there is no reason to also retain the raw bytes.
	if p.obsContentExtractor != nil {
		facts.PromptText, facts.ResponseText = p.obsContentExtractor(reqBody, respBody)
		facts.ContentExtracted = true
	} else {
		facts.RequestBody = obsClipBody(reqBody)
		facts.ResponseBody = obsClipResponseBody(respBody)
	}
	select {
	case p.obsSem <- struct{}{}:
	default:
		p.logger.Debug("proxy: obs gateway-rail trace synthesis dropped (concurrency bound saturated)",
			"api_turn_id", apiTurnID, "bound", obsGatewayMaxConcurrentSynthesis)
		return
	}
	go func() {
		defer func() { <-p.obsSem }()
		defer func() {
			if rec := recover(); rec != nil {
				p.logger.Debug("proxy: obs gateway-rail trace synthesis panicked", "recovered", rec)
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.obsSink.SynthesizeChatTurn(ctx, facts); err != nil {
			p.logger.Debug("proxy: obs gateway-rail trace synthesis failed", "err", err)
		}
	}()
}

// obsGatewayMaxConcurrentSynthesis bounds how many gateway-rail trace
// syntheses (Options.ObsSink.SynthesizeChatTurn calls) can be in flight at
// once (Finding F3, round-2 adversarial review). Without a bound,
// synthesizeObsTrace spawns one goroutine per proxied turn — under
// sustained high QPS (or a sink that's gone slow/hung) that's unbounded
// goroutine growth, each one retaining a copy of the turn's request/response
// bodies, with no backpressure on the proxy at all. obsSem (a buffered
// channel sized to this const, allocated once per Proxy) caps in-flight
// synthesis; see synthesizeObsTrace for the drop-not-block policy once it's
// saturated.
const obsGatewayMaxConcurrentSynthesis = 8

// obsGatewayMaxBodyBytes caps how much of a request/response body
// synthesizeObsTrace retains for the gateway-rail sink (Finding F3): the
// proxy's own network capture can hand across an arbitrarily large body, but
// the sink only ever needs a bounded prefix for its own content extraction
// (which itself clips further, to ~8000 runes — see
// cmd/observer/obs_wire.go's obsGatewayContentClipChars). Clipping HERE,
// before the copy crosses onto the synthesis goroutine, bounds the
// per-in-flight-synthesis memory footprint at the source rather than relying
// on the sink to clip after already retaining the whole body.
//
// This bound — and obsClipBody/obsClipResponseBody below — is now the
// NO-EXTRACTOR FALLBACK PATH ONLY (Lane B, trajectory-ui-rollup-and-
// spandetail-fixes spec): when Options.ObsContentExtractor is wired,
// synthesizeObsTrace skips this clip altogether and runs the extractor over
// the full bodies instead, which is what actually fixes the truncation
// class this const's blind byte-offset clip could introduce (real content
// living outside the kept window). Semantics here are unchanged for the
// fallback case — this const still means exactly what it always meant when
// no extractor is configured.
const obsGatewayMaxBodyBytes = 64 << 10 // 64 KiB

// obsClipBody truncates body to obsGatewayMaxBodyBytes from the HEAD, or
// returns it unchanged when already within bound. Used for request bodies
// (always a single plain-JSON document — the interesting fields
// (model/messages) are at the front, so a head clip is safe) and for
// non-streaming response bodies. A byte-level clip — body is opaque JSON
// bytes at this point, not yet parsed, so a byte cut is fine: a truncated
// tail simply fails the sink's JSON unmarshal and yields "", the same
// tolerant-to-zero-content outcome as any other unparseable/truncated body.
//
// Only reached on the no-extractor fallback path (synthesizeObsTrace calls
// this exclusively when Options.ObsContentExtractor is nil) — semantics
// unchanged by Lane B; when an extractor IS wired this function is never
// called and the extractor sees the full, unclipped body instead.
func obsClipBody(body []byte) []byte {
	if len(body) <= obsGatewayMaxBodyBytes {
		return body
	}
	return body[:obsGatewayMaxBodyBytes]
}

// obsClipResponseBody is the response-body counterpart to obsClipBody. It
// head-clips a plain-JSON response body exactly like obsClipBody, but
// TAIL-clips a streaming (SSE) response body instead (Finding F6 follow-up:
// live verification against a real OpenRouter stream from a reasoning model
// — nvidia/nemotron-3.5-lightning:free — showed a synthesized trace with a
// prompt content row but NO response content row). A reasoning model's SSE
// stream emits its `reasoning` deltas FIRST and its assistant `content`
// deltas LAST, often after many kilobytes of reasoning text; obsClipBody's
// unconditional head clip discarded exactly the tail where the content
// deltas lived, so obsExtractResponseTextSSE (cmd/observer/obs_wire.go) had
// nothing to reassemble. Keeping the LAST obsGatewayMaxBodyBytes of an SSE
// body instead keeps the deltas that matter for content extraction; a
// partial `data:` line left dangling at the very start of the kept tail
// simply fails that one line's JSON unmarshal (the same
// tolerant-to-zero-content behaviour every other extraction helper in this
// package/cmd/observer/obs_wire.go already relies on) without affecting the
// complete lines after it.
//
// Like obsClipBody, only reached on the no-extractor fallback path — Lane B
// (Options.ObsContentExtractor) bypasses this clip entirely and hands the
// full response body straight to the extractor, which is the actual fix for
// the class of loss this function's tail-clip only partially covers (a long
// enough stream can still push real content outside even the kept tail).
func obsClipResponseBody(body []byte) []byte {
	if len(body) <= obsGatewayMaxBodyBytes {
		return body
	}
	if obsLooksLikeStreamBody(body) {
		return body[len(body)-obsGatewayMaxBodyBytes:]
	}
	return body[:obsGatewayMaxBodyBytes]
}

// obsLooksLikeStreamBody is the internal/proxy-side twin of
// cmd/observer/obs_wire.go's obsLooksLikeSSE: the SAME discriminator (a
// plain JSON document always starts, after leading whitespace, with '{' or
// '['; an SSE capture never does and contains a "data:" line somewhere),
// deliberately duplicated rather than imported — internal/proxy must never
// import internal/obs or any cmd/observer wiring (the reverse-import
// boundary CLAUDE.md documents), and this discriminator is small enough
// that duplicating it is cheaper than inventing a shared seam for one
// six-line heuristic. Returns false for an empty body.
func obsLooksLikeStreamBody(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return false
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		return false
	}
	return bytes.Contains(body, []byte("data:"))
}

// buildCacheObserveInput is the §15.3 boundary that resolves
// provider differences into a capability-tagged ObserveInput.
// Returns ok=false when the observation should be dropped (no
// signal to record).
//
// Anthropic path: requires request CacheBlocks (the marker-aware
// chain). Same shape as the pre-§15.3 code.
//
// OpenAI / OpenAI-compatible path: builds an implicit-cache
// ObserveInput with Capabilities.ImplicitCache=true. No Blocks /
// Breakpoints (the implicit-cache engine path doesn't push the
// chain). The cached_tokens scalar is already on
// turn.CacheReadTokens (the proxy's parseOpenAIResponse +
// parseOpenAIStream paths net it out of input_tokens upstream —
// see internal/proxy/provider.go:357 and
// internal/proxy/streaming.go:317). The bootstrap-turn estimate
// seeds from turn.InputTokens (NET non-cached); the engine's
// per-session ImplicitPrefixTokens carries forward turn-over-turn.
func (p *Proxy) buildCacheObserveInput(turn models.APITurn, reqShape requestShape, provider string, apiTurnID int64) (cachetrack.ObserveInput, bool) {
	now := p.now()
	switch provider {
	case models.ProviderAnthropic:
		if len(reqShape.CacheBlocks) == 0 {
			return cachetrack.ObserveInput{}, false
		}
		return cachetrack.ObserveInput{
			SessionID:     turn.SessionID,
			Model:         turn.Model,
			Scope:         "default", // R7 derivation lands in a C8 follow-up; default keeps the engine session-keyed but workspace-blind for now.
			Tier:          cachetrack.TierProxy,
			MessageID:     turn.RequestID,
			Now:           now,
			Fast:          turn.Fast,
			Blocks:        reqShape.CacheBlocks,
			Breakpoints:   reqShape.CacheBreakpoints,
			HandoffMarker: reqShape.HandoffMarker,
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:        turn.InputTokens,
				OutputTokens:          turn.OutputTokens,
				CacheReadTokens:       turn.CacheReadTokens,
				CacheCreationTokens:   turn.CacheCreationTokens,
				CacheCreation1hTokens: turn.CacheCreation1hTokens,
			},
			APITurnID: apiTurnID,
		}, true
	case models.ProviderOpenAI:
		// Implicit-cache surface: we need at minimum a model + a
		// session_id to track per-session prefix state. Without
		// either, drop — the engine can't usefully group events.
		if turn.SessionID == "" || turn.Model == "" {
			return cachetrack.ObserveInput{}, false
		}
		// Capability overlay: start with the Tier-1 proxy defaults
		// (so future engine code that consults UsageObserved /
		// BlocksAreCumulative inherits the right values) and
		// overlay ImplicitCache=true so ObserveTurn dispatches to
		// the reduced attribution path.
		caps := cachetrack.CapabilitiesFor(cachetrack.TierProxy)
		caps.ImplicitCache = true
		return cachetrack.ObserveInput{
			SessionID:     turn.SessionID,
			Model:         turn.Model,
			Scope:         "default",
			Tier:          cachetrack.TierProxy,
			Caps:          caps,
			MessageID:     turn.RequestID,
			Now:           now,
			Fast:          turn.Fast,
			HandoffMarker: reqShape.HandoffMarker, // provider-agnostic raw-body scan (parseRequest); consumed by the implicit lane's ruleImplicitHandoffRehydration on the bootstrap turn
			Usage: cachetrack.CacheUsageObserved{
				NetInputTokens:  turn.InputTokens, // NET non-cached (already netted upstream)
				OutputTokens:    turn.OutputTokens,
				CacheReadTokens: turn.CacheReadTokens, // cached_tokens scalar
				// cache_write_tokens (GPT-5.6 metered API-key lane) when
				// present — 0 on the ChatGPT-plan implicit-cache lane,
				// preserving prior behaviour. Passed through so cache_events
				// reflect real writes when they appear; the reduced
				// attribution path still ignores CacheCreation1hTokens
				// (OpenAI writes are untiered, no explicit-breakpoint
				// modeling until observed on the wire).
				CacheCreationTokens: turn.CacheCreationTokens,
			},
			APITurnID: apiTurnID,
		}, true
	default:
		return cachetrack.ObserveInput{}, false
	}
}

// applyCost populates turn.CostUSD using the configured CostComputer.
// No-op when the proxy was constructed without one, when the turn has
// no model, or when the model isn't in the pricing table — in those
// cases the column stays NULL and downstream readers (dashboard
// /api/cost, observer cost) compute it on the fly. The helper exists
// so the four insert sites stay consistent without a wrapping
// `insertTurn` method that would also have to thread compression and
// the audit-B2 drop filter.
func (p *Proxy) applyCost(t *models.APITurn) {
	if p.cost == nil || t.Model == "" {
		return
	}
	if usd, ok := p.cost.Compute(t.Model, CostTokens{
		Input:           t.InputTokens,
		Output:          t.OutputTokens,
		CacheRead:       t.CacheReadTokens,
		CacheCreation:   t.CacheCreationTokens,
		CacheCreation1h: t.CacheCreation1hTokens,
		Fast:            t.Fast,
		At:              t.Timestamp,
	}); ok {
		t.CostUSD = usd
	}
}

// resolveAPITurnSessionID picks the session_id that lands on the
// api_turn row, with provider-aware extraction.
//
// Anthropic: body (metadata.user_id) → X-Session-Id → SessionResolver.
//
// OpenAI: body (prompt_cache_key) → codex header fan-out → X-Session-Id
// → SessionResolver. The codex header fan-out closes the V4-4 gap:
// codex's ChatGPT-Plus auth path drops prompt_cache_key from the
// request body, so the pre-fix code returned "" and every chatgpt-auth
// turn collapsed to `<unattributed>` in `observer cost --group-by
// session`.
//
// Header names are HYPHEN-SEPARATED canonical (codex 0.130+ emits
// `Session-Id`, `Thread-Id`, `X-Client-Request-Id` — verified via
// 2026-05-28 wire capture against codex 0.133). Go's
// textproto.CanonicalMIMEHeaderKey treats `Session-Id` and
// `Session_Id` as distinct keys (underscore vs hyphen is NOT
// normalized), so an `r.Header.Get("session_id")` against a real
// codex request returns "" — the fallback must use the exact
// hyphenated form. Listed in codex's apparent precedence; first
// non-empty hit wins.
func (p *Proxy) resolveAPITurnSessionID(r *http.Request, provider string, reqBody []byte) string {
	var sid string
	switch provider {
	case models.ProviderAnthropic:
		sid = extractAnthropicSessionID(reqBody)
	case models.ProviderOpenAI:
		sid = extractOpenAISessionID(reqBody)
		if sid == "" {
			for _, h := range []string{"Session-Id", "Thread-Id", "X-Client-Request-Id"} {
				if v := r.Header.Get(h); v != "" {
					sid = v
					break
				}
			}
		}
	}
	// Hosted-app conversation identity (gateway rail): an app routed through
	// an explicit /up/<id> lane can correlate its calls by sending
	// X-Superbased-Session (our contract, pairs with X-Superbased-User), or
	// — for Open WebUI with ENABLE_FORWARD_USER_INFO_HEADERS — its native
	// X-OpenWebUI-Chat-Id. Lane-gated so Plane-B coding-agent lanes never
	// pick up a hosted-app convention header. Without one of these, a
	// hosted app's calls (main completion + title/tags/follow-up task
	// calls) land as uncorrelated single-call traces — the operator-reported
	// 4-rows-per-prompt class, 2026-08-14.
	if sid == "" && obsUpstreamLane(r) != "" {
		sid = hostedSessionHeader(r)
	}
	if sid == "" {
		sid = r.Header.Get("X-Session-Id")
	}
	// PLANE BOUNDARY: the SessionResolver maps a connection's remote addr to
	// the local CODING-AGENT process that owns the socket (Plane B). A
	// hosted-app request that arrived on an explicit /up/<id> lane (Plane A)
	// must NEVER borrow a coding-agent session_id from it — that fallback
	// attributed hosted-app turns (Open WebUI → /up/openrouter) to a codex/
	// claude-code session and polluted the Plane-B cost rollups (operator-
	// reported class, 2026-08-13). On /up lanes the session_id comes ONLY
	// from explicit sources (body metadata / X-Session-Id); absent those it
	// stays "" (unattributed) — same discriminator as the gateway rail and
	// admission gate (obsLaneCtxKey).
	if sid == "" && p.sessions != nil {
		if resolved, ok, err := p.sessions.Resolve(r.Context(), r.RemoteAddr); err != nil {
			p.logger.Debug("proxy: session resolve", "addr", r.RemoteAddr, "err", err)
		} else if ok && (obsUpstreamLane(r) == "" || strings.HasPrefix(resolved, models.ArenaSessionIDPrefix)) {
			// Explicit /up lanes normally reject pid-derived Plane-B identity.
			// The sole exception is an Arena runner's directly-bound synthetic
			// candidate id: it cannot be a nearby interactive coding session and
			// is required for named-provider harnesses such as Grok.
			sid = resolved
		}
	}
	return sid
}

// hostedAppSessionHeaders are the EXPLICIT hosted-app conversation-identity
// headers accepted on /up/<id> lanes, in precedence order:
// X-Superbased-Session (our contract, pairs with X-Superbased-User; the
// harness gateway sends it per chat session) and X-OpenWebUI-Chat-Id (Open
// WebUI's native header under ENABLE_FORWARD_USER_INFO_HEADERS). ONE owner
// for the list: both resolveAPITurnSessionID (api_turns.session_id) and
// synthesizeObsTrace (the obs trace's session_id) consult it — if the two
// sites drift, a conversation groups in Plane-B cost rollups but not in the
// Hosted Apps views, or vice versa.
var hostedAppSessionHeaders = []string{"X-Superbased-Session", "X-OpenWebUI-Chat-Id"}

// hostedSessionQueryParam is the query-string fallback for clients whose
// provider config can set per-request query params but NOT headers — codex
// 0.147 dropped model-provider http_headers, keeping only query_params
// (ModelProviderInfo; verified live 2026-08-14: `query_params.sb_session`
// lands as POST /v1/responses?sb_session=...). Same lane gate and same
// explicit-only posture as the headers.
const hostedSessionQueryParam = "sb_session"

// hostedSessionHeader returns the first non-blank hosted-app conversation
// identity on r — header first, then the sb_session query param — or "".
func hostedSessionHeader(r *http.Request) string {
	for _, h := range hostedAppSessionHeaders {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(r.URL.Query().Get(hostedSessionQueryParam))
}

// hostedIdentityHeaderPrefix is the reserved namespace for Observer's own
// hosted-app identity contract headers (X-Superbased-User,
// X-Superbased-Session, and any future X-Superbased-* addition). These
// headers identify the END USER of the hosted app sitting in front of the
// proxy — they must never reach the upstream LLM provider. Matched by
// prefix, not an enumerated list, so a future contract header doesn't
// silently reopen this leak.
const hostedIdentityHeaderPrefix = "X-Superbased-"

// hostedIdentityQueryParams lists forwarded-URL query parameters that carry
// hosted-app end-user/session identity and must be stripped before a
// request reaches the upstream provider. Today that's just sb_session
// (hostedSessionQueryParam); a future sb_app identity param (see
// docs/plans/obs-application-identity-spec-2026-08-15.md) belongs here too
// — this is the one list a later change needs to extend.
var hostedIdentityQueryParams = []string{hostedSessionQueryParam}

// gatewayCredentialHeaders enumerates EVERY provider-credential header shape a
// developer request can carry. In Gateway Mode (Sol S2 auth-substitution) all
// of them are stripped before the request reaches the org gateway, which
// authenticates with the org-issued virtual key instead — deny-listing every
// shape, not just Authorization / X-Api-Key, so a Gemini X-Goog-Api-Key or an
// Azure Api-Key can never carry the developer's own provider credential onto a
// gateway-bound request (custody blocker). Matched by canonical MIME key.
var gatewayCredentialHeaders = []string{
	"Authorization",  // OpenAI / Anthropic bearer + OAuth
	"X-Api-Key",      // Anthropic api-key
	"X-Goog-Api-Key", // Google Gemini api-key header
	"Api-Key",        // Azure OpenAI api-key
}

// gatewayCredentialQueryParams lists forwarded-URL query parameters that carry
// a PROVIDER API credential (Gemini's ?key=) rather than hosted-app identity.
// They are stripped ONLY on a gateway-bound request — a direct-provider (Node
// Mode) request legitimately carries the developer's own ?key= to Google, so
// this strip is gateway-mode-scoped, distinct from hostedIdentityQueryParams.
var gatewayCredentialQueryParams = []string{"key"}

// credentialQueryParam returns the value of the first gateway-credential query
// param present in rawQuery (Gemini's ?key=), or "" — captured before a
// gateway strip so a custody-acked direct fallback can restore it.
func credentialQueryParam(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return ""
	}
	for _, name := range gatewayCredentialQueryParams {
		if v := q.Get(name); v != "" {
			return v
		}
	}
	return ""
}

// stripGatewayCredentialQueryParams removes gatewayCredentialQueryParams from
// rawQuery and returns the re-encoded remainder. Only called when building a
// GATEWAY-bound request's URL (never on the original inbound request, never on
// a direct-provider forward). A malformed query is returned unchanged
// (fail-open, matching stripHostedIdentityQueryParams).
func stripGatewayCredentialQueryParams(rawQuery string) string {
	if rawQuery == "" {
		return rawQuery
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	changed := false
	for _, name := range gatewayCredentialQueryParams {
		if q.Has(name) {
			q.Del(name)
			changed = true
		}
	}
	if !changed {
		return rawQuery
	}
	return q.Encode()
}

// isHostedIdentityHeader reports whether k (in canonical MIME header form,
// as produced by iterating an http.Header or by http.CanonicalHeaderKey) is
// a hosted-app end-user/session identity header that must be stripped from
// any request forwarded to an upstream LLM provider: the X-Superbased-*
// contract namespace, the explicit hostedAppSessionHeaders list (covers
// third-party conventions like X-OpenWebUI-Chat-Id that don't share our
// prefix), and — when configured — the operator's admission user header
// ([observability.admission].user_header, the same name admissionUser(r)
// resolves; one source of truth, passed in by the caller rather than
// re-read here).
func isHostedIdentityHeader(k, admissionUserHeader string) bool {
	if strings.HasPrefix(k, hostedIdentityHeaderPrefix) {
		return true
	}
	for _, h := range hostedAppSessionHeaders {
		if strings.EqualFold(k, h) {
			return true
		}
	}
	return admissionUserHeader != "" && strings.EqualFold(k, admissionUserHeader)
}

// stripHostedIdentityQueryParams removes hostedIdentityQueryParams from
// rawQuery and returns the re-encoded remainder. Called only when building
// the OUTGOING/forwarded request's URL — never on the original inbound
// *http.Request — so it can never affect the proxy's own session/admission
// resolution, which always reads the inbound request directly (see
// resolveAPITurnSessionID / admissionUser) and, on every call site here,
// already runs before the forwarded request is built. A malformed query
// string is forwarded unchanged (fail-open: matches prior behavior, and a
// query the proxy itself can't parse isn't a shape it can safely mutate).
func stripHostedIdentityQueryParams(rawQuery string) string {
	if rawQuery == "" {
		return rawQuery
	}
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return rawQuery
	}
	changed := false
	for _, name := range hostedIdentityQueryParams {
		if q.Has(name) {
			q.Del(name)
			changed = true
		}
	}
	if !changed {
		return rawQuery
	}
	return q.Encode()
}

// explicitHostedSessionID is the obs-trace session identity: an explicit
// X-Session-Id first, else a hosted-app conversation header. NEVER the
// SessionResolver fallback (plane boundary — see the synthesizeObsTrace
// comment). Callers are already lane-gated to /up/<id> traffic.
func explicitHostedSessionID(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Session-Id")); v != "" {
		return v
	}
	return hostedSessionHeader(r)
}

// requestClass best-effort assembles the Track-R routing inputs for
// one request via the session resolver's optional [ToolResolver] /
// [CWDResolver] capabilities. Missing capabilities, errors, and
// misses leave fields "" — the profile router then falls back tier
// by tier (tool → provider; project → none). The production resolver
// caches per remote addr (30s TTL) and shares its cache with the
// session resolution that runs post-response, so the pre-forward
// calls here add at most one /proc walk per addr per TTL window.
func (p *Proxy) requestClass(r *http.Request, provider string) RequestClass {
	class := RequestClass{Provider: provider}
	if tr, ok := p.sessions.(ToolResolver); ok {
		tool, ok, err := tr.ResolveTool(r.Context(), r.RemoteAddr)
		switch {
		case err != nil:
			p.logger.Debug("proxy: tool resolve", "addr", r.RemoteAddr, "err", err)
		case ok:
			class.Tool = tool
		}
	}
	// L1 header fallback (D20): the pidbridge is fed only by hook-
	// registered tools, so hookless clients miss the bridge and used
	// to skip the per-tool tier entirely. The signature table supplies
	// the identity from request headers instead; bridge identity, when
	// present, has already filled Tool above and is never overridden.
	if class.Tool == "" {
		if tool, ok := toolFromHeaders(r.Header); ok {
			class.Tool = tool
		}
	}
	if cr, ok := p.sessions.(CWDResolver); ok {
		cwd, ok, err := cr.ResolveCWD(r.Context(), r.RemoteAddr)
		switch {
		case err != nil:
			p.logger.Debug("proxy: cwd resolve", "addr", r.RemoteAddr, "err", err)
		case ok:
			class.CWD = cwd
		}
	}
	return class
}

// upstreamForPath resolves the fixed provider upstream for a request that
// carries no explicit /up/<id> lane, OR (Sol S8, P5a) the org-wide AI
// Gateway primary destination when Gateway Mode is active for that
// request.
//
// The org-route override applies ONLY when upstreamLaneID == "" — an
// explicitly named /up/<id> lane never falls through to org-route; the
// caller already resolved it via stripUpstreamPrefix/explicitUpstream and
// never reaches this function for that case. lanes must be a single
// laneSnapshot() load from the caller so the mode/primary pair it reads
// here can never straddle two routing generations (Sol S7).
//
// The ChatGPT-backend / JWT-auth branch is deliberately checked FIRST and
// is NEVER redirected to the gateway: that channel authenticates with a
// ChatGPT session JWT, not a provider API key, and P5a's auth-substitution
// (Sol S2) only knows how to swap API-key-shaped credentials for a virtual
// key. Redirecting an unfamiliar auth wire contract into Gateway Mode
// without that groundwork would silently break it, so it is out of scope
// here and stays on p.chatgptURL regardless of org-route state.
//
// The second return value reports whether the org-route (Gateway Mode)
// branch was the one that resolved upstream, so the caller can decide
// whether to run Sol S2 auth-substitution — parsing/token capture is
// otherwise completely unaffected by which branch fired.
func (p *Proxy) upstreamForPath(path, provider string, chatgptAuth bool, lanes *laneTable, upstreamLaneID string) (*url.URL, bool) {
	if isChatGPTBackendPath(path) || chatgptAuth {
		return p.chatgptURL, false
	}
	if upstreamLaneID == "" && lanes != nil && lanes.orgRoute.mode == orgModeGateway && lanes.orgRoute.primary != nil {
		return lanes.orgRoute.primary, true
	}
	if provider == models.ProviderGoogle {
		return p.geminiURL, false
	}
	if provider == models.ProviderOpenAI {
		return p.openaiURL, false
	}
	return p.anthropicURL, false
}

// unknownUpstreamWarnCap bounds the unknownUpstreamWarned dedup map (and thus
// the number of distinct unknown ids ever warned about) so a long-running
// daemon cannot grow it without limit.
const unknownUpstreamWarnCap = 64

// autoLaneID is the virtual "auto" /up/ lane's reserved routing id (Phase 2,
// gateway config plane spec). internal/config.Validate rejects a literal
// "auto" key in [proxy.upstreams] and Proxy.SetUpstreams/SetLaneTable reject
// it too, so this id can never collide with a real configured lane.
const autoLaneID = "auto"

// laneTable is the single unit of state behind Proxy.lanes: the explicit
// /up/<id> upstream map, the virtual "auto" lane's fallback default, AND
// (Sol S7, P5a) the org-wide AI Gateway route, published together so one
// atomic.Pointer swap can never leave a reader with a map from one
// generation and a default id (or org-route, or generation id) from
// another (Phase 3, gateway config plane spec; extended by
// docs/plans/plane-b-dual-mode-gateway-rbac-ia-design-2026-08-29.md §2).
// The zero value (nil map, empty default, zero orgRoute, generation 0) is
// a valid "nothing configured" table — inert, byte-identical to pre-P5a
// behavior.
type laneTable struct {
	// upstreams maps a routing id to its parsed upstream URL. nil/empty
	// when no [proxy.upstreams] are configured.
	upstreams map[string]*url.URL
	// autoDefault is the fallback lane id the virtual "auto" lane resolves
	// to when the request's model carries no matching "<lane>/" prefix.
	// "" means no default (see resolveAutoLane).
	autoDefault string
	// orgRoute carries the org-wide AI Gateway routing mode, destination,
	// and fallback ladder (Sol S7/S8) as part of THIS SAME snapshot, so a
	// reader can never observe org-mode from one generation and a
	// route/ladder from another. Zero value (mode == orgModeNode) means
	// "no org-route installed" — upstreamForPath ignores it entirely.
	orgRoute orgRouteState
	// generation is a monotonically increasing id (from Proxy.laneGen)
	// stamped on every published snapshot by its setter. 0 only ever
	// appears before New's first Store; every live snapshot carries a
	// positive id.
	generation uint64
}

// orgModeNode and orgModeGateway are the two values laneTable.orgRoute.mode
// can take. orgModeNode (the zero value) is "not installed" — org-route is
// inert and default-lane traffic (upstreamLaneID == "") goes directly to
// the fixed upstreams, exactly like every pre-P5a build. orgModeGateway
// redirects that same default-lane traffic to orgRoute.primary (Sol S8)
// and is the trigger condition for auth-substitution (Sol S2).
const (
	orgModeNode    = ""
	orgModeGateway = "gateway"
)

// orgRouteState is the org-wide AI Gateway half of a laneTable snapshot
// (Sol S7). It is data only in P5a — the fallback ladder's runtime state
// machine (try each entry, apply a terminal policy) is Sol S10 / P5b; this
// type only guarantees the ladder can be carried atomically with the rest
// of the routing state.
type orgRouteState struct {
	// mode is orgModeNode or orgModeGateway. See the constants' doc.
	mode string
	// primary is the AI Gateway upstream to redirect default-lane traffic
	// to when mode == orgModeGateway. Always non-nil in that case (never
	// nil-primary + gateway mode — SetOrgGatewayRoute rejects that);
	// always nil when mode == orgModeNode.
	primary *url.URL
	// fallbacks is the ordered fallback ladder data (Sol S10 owns walking
	// it). Empty when no fallback policy is installed, regardless of mode.
	fallbacks []*url.URL
	// terminal is the compiled fallback-ladder terminal rung (terminalHold /
	// terminalBreakGlass / terminalDirect) reached after primary + every
	// fallback endpoint is exhausted (Sol S10 runtime executor, Luna L16 —
	// see gatewayfallback.go). Empty is treated as terminalHold (the safe
	// fail-closed default); only meaningful when mode == orgModeGateway.
	terminal string
	// custodyAck echoes the publisher's explicit custody-downgrade
	// acknowledgment. It gates terminalDirect: auto-fallback-to-direct is
	// only ever walked when custodyAck is true (the compile side already
	// refuses to emit terminalDirect without it — this is defence in depth).
	custodyAck bool
}

// newOrgRouteState validates and builds the org-route half of a routing
// snapshot for the two setters (SetOrgGatewayRoute / SetRoutingSnapshot*).
// mode must be orgModeNode ("" — a zero orgRouteState) or orgModeGateway;
// in gateway mode primary is required and every URL (primary + fallbacks)
// must parse (scheme + host). terminal is the compiled terminal rung
// (defaulting to terminalHold when empty); custodyAck echoes the
// custody-downgrade acknowledgment. All-or-nothing: any error leaves the
// caller free to keep the previous snapshot.
func newOrgRouteState(mode, primary string, fallbacks []string, terminal string, custodyAck bool) (orgRouteState, error) {
	switch mode {
	case orgModeNode:
		return orgRouteState{}, nil
	case orgModeGateway:
		if primary == "" {
			return orgRouteState{}, fmt.Errorf("primary is required in %q mode", orgModeGateway)
		}
		primaryURL, err := parseUpstream("org-gateway-primary", primary, "")
		if err != nil {
			return orgRouteState{}, err
		}
		var fbURLs []*url.URL
		for i, raw := range fallbacks {
			u, err := parseUpstream(fmt.Sprintf("org-gateway-fallback[%d]", i), raw, "")
			if err != nil {
				return orgRouteState{}, err
			}
			fbURLs = append(fbURLs, u)
		}
		term := terminal
		switch term {
		case "":
			term = terminalHold
		case terminalHold, terminalBreakGlass, terminalDirect:
			// ok
		default:
			return orgRouteState{}, fmt.Errorf("unknown terminal_policy %q (want %q, %q, or %q)", term, terminalHold, terminalBreakGlass, terminalDirect)
		}
		return orgRouteState{
			mode:       orgModeGateway,
			primary:    primaryURL,
			fallbacks:  fbURLs,
			terminal:   term,
			custodyAck: custodyAck && term == terminalDirect,
		}, nil
	default:
		return orgRouteState{}, fmt.Errorf("unknown mode %q (want %q or %q)", mode, orgModeNode, orgModeGateway)
	}
}

// warnUnknownUpstreamOnce logs the fail-open warning for a /up/ routing id
// that couldn't be resolved to a live upstream, at most once per id for the
// daemon's lifetime (bounded by unknownUpstreamWarnCap, which also caps the
// dedup map itself so it can't grow without limit). Shared by the legacy
// unknown-/up/<id> path in stripUpstreamPrefix and the auto lane's
// unresolvable fallback in serve() (Phase 2 — no prefix match and no usable
// auto_default_lane, or a configured default lane that vanished from a hot
// SetUpstreams swap).
func (p *Proxy) warnUnknownUpstreamOnce(id, path string, configuredCount int) {
	if mapLen(&p.unknownUpstreamWarned) >= unknownUpstreamWarnCap {
		return
	}
	if _, seen := p.unknownUpstreamWarned.LoadOrStore(id, struct{}{}); !seen {
		p.logger.Warn("proxy: unknown /up/ upstream id — not routed, falling back to the fixed upstream",
			"id", id, "path", path, "configured", configuredCount)
	}
}

// stripUpstreamPrefix detects a `/up/<id>/` routing prefix on r.URL.Path
// (Phase C). When present AND <id> maps to a configured explicit upstream,
// it rewrites r.URL.Path (and clears RawPath so net/http re-derives it) to
// drop the `/up/<id>` segment and returns the mapped upstream. Returns nil
// — leaving the request untouched — when no upstreams are configured, the
// path has no prefix, or the id is unknown (fail-open: the caller then uses
// the fixed-upstream selection). The stripped path keeps any version suffix
// (e.g. `/v1/chat/completions`) so it joins onto the upstream's host root
// exactly like the fixed upstreams.
// It also returns the routing id itself so serve() can stamp it on the
// request context (obsLaneCtxKey) — the gateway rail's Plane-A/Plane-B lane
// discriminator. "" when no explicit upstream matched.
//
// The reserved id "auto" (Phase 2, gateway config plane spec) is a special
// case: it's stripped like any known id, but its URL can't be resolved here
// — routing depends on the request's top-level model, which needs the body
// this function runs before. It returns (nil, autoLaneID) so serve() knows
// to call resolveAutoLane once the body is buffered.
func (p *Proxy) stripUpstreamPrefix(r *http.Request) (*url.URL, string) {
	const marker = "/up/"
	upstreams := p.upstreamsSnapshot()
	if len(upstreams) == 0 || !strings.HasPrefix(r.URL.Path, marker) {
		return nil, ""
	}
	rest := r.URL.Path[len(marker):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return nil, "" // no id, or id with no trailing path segment
	}
	id := rest[:slash]
	if id == autoLaneID {
		r.URL.Path = rest[slash:]
		r.URL.RawPath = ""
		return nil, autoLaneID
	}
	up, ok := upstreams[id]
	if !ok {
		// Fail-open (unchanged): the request keeps its unstripped `/up/<id>/…`
		// path and goes to the fixed upstream, where it dies as an opaque
		// 404/401 that names nothing. Say it ONCE per unknown id (mirrors
		// codexVariantWarned) so a typo'd/missing `[proxy.upstreams]` entry is
		// diagnosable instead of silent — this is exactly how a launcher's
		// `--upstream` typo presents. Routing behaviour is untouched.
		p.warnUnknownUpstreamOnce(id, r.URL.Path, len(upstreams))
		return nil, ""
	}
	r.URL.Path = rest[slash:] // keep the leading slash of the canonical path
	r.URL.RawPath = ""        // force net/url to re-derive the escaped form
	return up, id
}

// isEmptyUsage reports whether a parsed turn carries no usable token
// counts at all. Such turns happen when the upstream response stream
// ended before any usage event arrived (cancellation, mid-flight error,
// or an envelope with model + id but no usage block). Recording them
// distorts averages and turn counts without adding analytical value.
// looksLikeSSE returns true when body's first non-whitespace bytes match
// the SSE wire format ("event:" or "data:" line prefix). Used as a
// content-sniffing fallback when the upstream omits the Content-Type
// header — chatgpt.com/backend-api/codex/responses returns SSE with
// empty Content-Type as of codex 0.129.0 / observation 2026-05-08.
//
// Conservative — looks at the first 64 bytes only; mismatched bytes
// fall through to the JSON branch as before. Cross-checked against the
// Anthropic and OpenAI standard SSE preludes (both start with one of
// these two prefixes after any leading whitespace).
func looksLikeSSE(body []byte) bool {
	for i, b := range body {
		if b == ' ' || b == '\r' || b == '\n' || b == '\t' {
			continue
		}
		if i > 64 {
			return false
		}
		rest := body[i:]
		return bytes.HasPrefix(rest, []byte("event:")) ||
			bytes.HasPrefix(rest, []byte("event: ")) ||
			bytes.HasPrefix(rest, []byte("data:")) ||
			bytes.HasPrefix(rest, []byte("data: "))
	}
	return false
}

func isEmptyUsage(t models.APITurn) bool {
	return t.InputTokens == 0 &&
		t.OutputTokens == 0 &&
		t.CacheReadTokens == 0 &&
		t.CacheCreationTokens == 0
}

func hasCompressionEvidence(c CompressionResult) bool {
	if c.Skipped {
		return false
	}
	return c.OriginalBytes > 0 ||
		c.CompressedBytes > 0 ||
		c.CompressedCount > 0 ||
		c.DroppedCount > 0 ||
		c.MarkerCount > 0 ||
		c.MessagePrefixHash != "" ||
		len(c.Events) > 0
}

// applyCompressionMeta copies compression fields from the pre-forward
// CompressionResult onto the APITurn so the cost engine and dashboard
// can aggregate savings per model/session/day.
func applyCompressionMeta(t *models.APITurn, c CompressionResult) {
	if c.Skipped {
		return
	}
	t.MessagePrefixHash = c.MessagePrefixHash
	t.CompressionOriginalBytes = int64(c.OriginalBytes)
	t.CompressionCompressedBytes = int64(c.CompressedBytes)
	t.CompressionCount = int64(c.CompressedCount)
	t.CompressionDroppedCount = int64(c.DroppedCount)
	t.CompressionMarkerCount = int64(c.MarkerCount)
	if len(c.Events) > 0 {
		t.CompressionEvents = make([]models.CompressionEvent, 0, len(c.Events))
		for _, e := range c.Events {
			t.CompressionEvents = append(t.CompressionEvents, models.CompressionEvent{
				Timestamp:       t.Timestamp, // share the turn timestamp
				Mechanism:       e.Mechanism,
				OriginalBytes:   int64(e.OriginalBytes),
				CompressedBytes: int64(e.CompressedBytes),
				MsgIndex:        e.MsgIndex,
				ImportanceScore: e.ImportanceScore,
				BodyHash:        e.BodyHash,
			})
		}
	}
}

// recordCompression logs a per-turn compression summary to the
// observer_log telemetry channel so the dashboard and `observer cost`
// can aggregate savings (spec §10 Layer 3 step 11). Silent no-op when no
// ObserverLogSink is wired.
func (p *Proxy) recordCompression(ctx context.Context, provider string, c CompressionResult) {
	if p.obsLog == nil {
		return
	}
	details := fmt.Sprintf(
		`{"provider":%q,"original_bytes":%d,"compressed_bytes":%d,"compressed_count":%d,"dropped_count":%d,"marker_count":%d,"prefix_hash":%q}`,
		provider,
		c.OriginalBytes,
		c.CompressedBytes,
		c.CompressedCount,
		c.DroppedCount,
		c.MarkerCount,
		c.MessagePrefixHash,
	)
	msg := fmt.Sprintf("conversation compression: %d → %d bytes (%d%% saved)",
		c.OriginalBytes, c.CompressedBytes, savingsPercent(c.OriginalBytes, c.CompressedBytes))
	if err := p.obsLog.InsertObserverLog(ctx, "info", "compress", msg, details); err != nil {
		p.logger.Warn("proxy: observer_log write", "err", err)
	}
}

// savingsPercent is a small helper returning 0..100. Used only for the
// human-readable observer_log message; stats callers should compute
// ratios themselves.
func savingsPercent(before, after int) int {
	if before <= 0 {
		return 0
	}
	saved := before - after
	if saved <= 0 {
		return 0
	}
	return saved * 100 / before
}

// buildTurn constructs an APITurn from a completed non-streaming exchange.
// It returns the turn even when usage fields are zero so the caller can
// decide whether to store it; the serve() path drops turns with an empty
// Model since those almost always indicate an error body we couldn't parse.
// stampRoute writes the Plane B per-turn authority stamps (Sol S5 / Luna
// L15, migration 095) onto a turn just before it is persisted: how the node
// proxy served it (direct vs the org AI Gateway), the routing-snapshot
// generation it resolved under, and which source owns its org-level usage
// authority. Content-free metadata only — never touches request bytes.
//
// A gateway-routed turn declares the gateway as its usage authority
// (models.TurnAuthorityGateway) so a mixed-mode org rollup lets the
// gateway's own audit row win on a request_id collision rather than
// double-counting the node-side shadow. A fallback-rung turn is stamped by
// the fallback executor (Sol S10) which re-labels Route after the ladder
// walk; this base stamp covers the direct and primary-gateway cases.
func stampRoute(t *models.APITurn, gatewayRouted bool, generation uint64) {
	t.RoutingGeneration = int64(generation)
	if gatewayRouted {
		t.Route = models.TurnRouteGateway
		t.AuthoritySource = models.TurnAuthorityGateway
		return
	}
	t.Route = models.TurnRouteDirect
	t.AuthoritySource = models.TurnAuthorityNode
}

func (p *Proxy) buildTurn(
	provider string,
	req requestShape,
	respBody []byte,
	respHeader http.Header,
	start time.Time,
	sessionID string,
) models.APITurn {
	var resp responseShape
	switch provider {
	case models.ProviderAnthropic:
		resp = parseAnthropicResponse(respBody)
	case models.ProviderGoogle:
		resp = parseGeminiResponse(respBody)
	default:
		resp = parseOpenAIResponse(respBody)
	}
	model := resp.Model
	if model == "" {
		model = req.Model
	}
	requestID := resp.RequestID
	if requestID == "" {
		requestID = respHeader.Get("X-Request-Id")
	}
	return models.APITurn{
		SessionID:             sessionID,
		Timestamp:             start.UTC(),
		Provider:              provider,
		Model:                 model,
		RequestID:             requestID,
		InputTokens:           resp.InputTokens,
		OutputTokens:          resp.OutputTokens,
		CacheReadTokens:       resp.CacheReadTokens,
		CacheCreationTokens:   resp.CacheCreationTokens,
		CacheCreation1hTokens: resp.CacheCreation1hTokens,
		MessageCount:          req.MessageCount,
		ToolUseCount:          req.ToolUseCount,
		SystemPromptHash:      req.SystemPromptHash,
		TotalResponseMS:       p.now().Sub(start).Milliseconds(),
		StopReason:            resp.StopReason,
		// Fast-mode flag: Anthropic Messages API's `speed:"fast"` selects
		// the Opus 4.8 low-latency premium tier; OpenAI/Codex's
		// `service_tier:"priority"` selects Codex Fast mode. The proxy is
		// the only reliable seam where both the request body AND the served
		// tier (resp.ServiceTier) are observable — adapters reading on-disk
		// logs don't surface either selector reliably. Cost engine picks up
		// b.Fast at insert time and applies FastMultiplier.
		Fast: isFastTurn(req, resp.ServiceTier),
	}
}

// buildStreamTurn constructs an APITurn from a captured SSE exchange. The
// request shape carries message/tool counts; the captured body carries the
// accurate token counts and stop_reason from the stream's terminal events.
func (p *Proxy) buildStreamTurn(
	provider string,
	req requestShape,
	captured []byte,
	respHeader http.Header,
	start time.Time,
	sessionID string,
) models.APITurn {
	result := parseSSEStream(captured, provider)
	model := result.Model
	if model == "" {
		model = req.Model
	}
	requestID := result.RequestID
	if requestID == "" {
		requestID = respHeader.Get("X-Request-Id")
	}
	return models.APITurn{
		SessionID:             sessionID,
		Timestamp:             start.UTC(),
		Provider:              provider,
		Model:                 model,
		RequestID:             requestID,
		InputTokens:           result.InputTokens,
		OutputTokens:          result.OutputTokens,
		CacheReadTokens:       result.CacheReadTokens,
		CacheCreationTokens:   result.CacheCreationTokens,
		CacheCreation1hTokens: result.CacheCreation1hTokens,
		MessageCount:          req.MessageCount,
		ToolUseCount:          req.ToolUseCount,
		SystemPromptHash:      req.SystemPromptHash,
		TotalResponseMS:       p.now().Sub(start).Milliseconds(),
		StopReason:            result.StopReason,
		// See buildTurn() above. Anthropic speed:"fast" rides the request
		// shape; OpenAI/Codex priority rides the served tier parsed from
		// the SSE response.completed event (result.ServiceTier).
		Fast: isFastTurn(req, result.ServiceTier),
	}
}

// doWithRetry wraps p.client.Do with a single retry on transient
// transport-layer errors. The Go http client auto-retries when the
// request body hasn't been written yet AND the connection failure
// happens before the request goes on the wire — but if the failure
// surfaces mid-write (the typical "write tcp ...: connection reset by
// peer" symptom on a stale keep-alive entry that NAT closed), the
// auto-retry is suppressed and the error bubbles to the caller.
//
// We retry once for that specific class of error: connection reset,
// EOF, or broken pipe surfacing as a net.OpError on Write or as a
// url.Error wrapping one. Exactly one retry — never more — so a
// genuine upstream outage doesn't get masked. The retry rebuilds the
// request because http.NewRequestWithContext + bytes.NewReader gives
// us a body that's already been consumed once on the failed attempt.
//
// We do NOT retry on context cancellation, on non-transient transport
// errors (TLS handshake failure, dial failure mid-handshake), or on
// any HTTP-level response (a 5xx is the upstream's job to surface).
func (p *Proxy) doWithRetry(req *http.Request, body []byte) (*http.Response, error) {
	resp, err := p.client.Do(req)
	if err == nil {
		return resp, nil
	}
	if !isRetryableTransportError(err) || req.Context().Err() != nil {
		return nil, err
	}
	// Transport-level transient. Drain whatever pooled idle connection
	// might still be poisoned, then rebuild and retry once.
	p.logger.Info("proxy: upstream transport hiccup, retrying once", "err", err)
	if rt, ok := p.client.Transport.(*http.Transport); ok {
		rt.CloseIdleConnections()
	}
	retryReq, rerr := http.NewRequestWithContext(req.Context(), req.Method, req.URL.String(), bytes.NewReader(body))
	if rerr != nil {
		return nil, err
	}
	retryReq.Header = req.Header.Clone()
	retryReq.Host = req.Host
	retryReq.ContentLength = int64(len(body))
	resp, retryErr := p.client.Do(retryReq)
	if retryErr != nil {
		// Surface the retry error, not the original — it's the most
		// recent signal of upstream state.
		return nil, retryErr
	}
	return resp, nil
}

// isRetryableTransportError matches the transport-level transient
// errors worth a single retry. The Go stdlib doesn't expose stable
// types for these (most are syscall.Errno wrapped through several
// layers of net.OpError / url.Error), so we string-match on the
// canonical messages. Conservative: only matches the exact phrases
// our deployment has observed, not a broad "any net error" sweep.
func isRetryableTransportError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "connection reset by peer"):
		return true
	case strings.Contains(s, "broken pipe"):
		return true
	case strings.Contains(s, "use of closed network connection"):
		return true
	case strings.HasSuffix(s, ": EOF"):
		return true
	}
	return false
}

func (p *Proxy) serveUpgradePassthrough(w http.ResponseWriter, r *http.Request, upstream *url.URL) {
	target := *upstream
	proxy := httputil.NewSingleHostReverseProxy(&target)
	if p.client != nil {
		proxy.Transport = p.client.Transport
	}
	originalDirector := proxy.Director
	proxy.Director = func(outReq *http.Request) {
		originalDirector(outReq)
		outReq.URL.Path = joinPath(upstream.Path, r.URL.Path)
		outReq.URL.RawQuery = stripHostedIdentityQueryParams(r.URL.RawQuery)
		outReq.Host = upstream.Host
		outReq.Header.Del("X-Session-Id")
		// outReq.Header is a fresh clone of r.Header made by
		// httputil.ReverseProxy before Director runs (req.Clone), so
		// deleting here never touches the original inbound request —
		// same non-mutation guarantee as copyRequestHeaders below.
		for k := range outReq.Header {
			if isHostedIdentityHeader(k, p.admissionUserHeader) {
				outReq.Header.Del(k)
			}
		}
	}
	proxy.ErrorLog = slog.NewLogLogger(p.logger.Handler(), slog.LevelWarn)
	proxy.ServeHTTP(w, r)
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		headerHasToken(r.Header.Get("Connection"), "upgrade")
}

func headerHasToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

func isZstdEncoded(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "zstd")
}

// isGzipEncoded reports whether a Content-Encoding value is gzip. The proxy
// deliberately does NOT decode gzip request bodies before admission/egress
// (only zstd is decoded, §3.5): a gzip-encoded request reaches extraction as
// compressed bytes, so admission and egress both no-op (fail-open). This helper
// makes that posture explicit and greppable rather than an implicit gap.
func isGzipEncoded(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), "gzip")
}

// newRequestID returns a stable per-request correlation id, established BEFORE
// admission runs (design P0 finding). It is threaded into AdmitInput.RequestID
// (so the admission/egress audit rows carry it) and stamped onto the api_turn
// as the request_id fallback when the upstream response carried none, so those
// rows soft-join to the turn. The "sbo-" prefix keeps it distinguishable from a
// provider-issued id in the audit trail.
func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fail-soft: a nanosecond timestamp is still unique enough to correlate
		// one request's admission/egress rows with its turn on this node.
		return fmt.Sprintf("sbo-%x", time.Now().UnixNano())
	}
	return "sbo-" + hex.EncodeToString(b[:])
}

// orRequestID returns id when non-empty, else fallback — used to stamp the
// stable proxy request id onto a turn only when the upstream response supplied
// none (the provider's own id always wins).
func orRequestID(id, fallback string) string {
	if id != "" {
		return id
	}
	return fallback
}

func decodeZstd(body []byte) ([]byte, error) {
	decoder, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer decoder.Close()
	return decoder.DecodeAll(body, nil)
}

func encodeZstd(body []byte) ([]byte, error) {
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		return nil, err
	}
	defer encoder.Close()
	return encoder.EncodeAll(body, nil), nil
}

// joinPath appends r onto base, preserving the base path's trailing segment
// semantics. url.JoinPath isn't used because it collapses empty base paths
// to /, which breaks against hosts like https://api.anthropic.com with no
// configured path prefix.
func joinPath(base, path string) string {
	if base == "" || base == "/" {
		return path
	}
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// hopByHopHeaders are stripped from forwarded requests and responses.
// RFC 7230 §6.1.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// copyRequestHeaders copies client headers onto the upstream request,
// stripping hop-by-hop headers and the X-Session-Id metadata header which
// belongs to the proxy, not the upstream API.
// copyRequestHeaders is a method (not a free function) so it can consult
// p.admissionUserHeader — the operator-configured admission user header
// name is itself hosted-app end-user identity and must be stripped from
// what reaches the upstream provider, same as the X-Superbased-* contract
// and hostedAppSessionHeaders.
func (p *Proxy) copyRequestHeaders(dst, src http.Header) {
	for k, vs := range src {
		if _, hop := hopByHopHeaders[k]; hop {
			continue
		}
		if k == "X-Session-Id" {
			continue
		}
		if isHostedIdentityHeader(k, p.admissionUserHeader) {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// copyResponseHeaders copies upstream headers onto the client response,
// stripping hop-by-hop headers.
func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		if _, hop := hopByHopHeaders[k]; hop {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// sha256Hex returns the lowercase hex SHA-256 of b. The proxy uses it for
// the system_prompt_hash column — stable across runs so an analyst can tell
// when the same prompt prefix is being reused.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
