package proxy

import (
	"context"
	"net/http"
	"time"
)

// ObsSink is the optional "gateway rail" seam (Plane-A general observability
// — docs/observability.md "proxy turn (automatic)"): when non-nil on
// [Options], the proxy hands it one ChatTurnFacts per SUCCESSFULLY inserted
// api_turns row whose request arrived on an explicit /up/<id> upstream lane
// (success or error turns — a co-resident hosted app such as Open WebUI that
// routes through /up/<id> without ever emitting its own OTLP), so it can
// synthesize an obs_traces/obs_spans "chat.turn"/"chat.completions" pair.
// That makes the turn show up in the org Trajectory explorer with zero app
// instrumentation. Default provider lanes (Plane-B coding agents) NEVER
// reach this sink — see obsLaneCtxKey.
//
// Bound at the obs wiring point (cmd/observer/obs_wire.go) so internal/proxy
// never imports internal/obs — the reverse-import boundary
// (tests/invariant/obs_boundary_test.go). nil ⇒ disabled, zero overhead
// beyond a nil check.
//
// SynthesizeChatTurn is called FIRE-AND-FORGET: p.synthesizeObsTrace spawns
// it on its own goroutine, AFTER the client already has its response bytes
// and the api_turn insert has completed, on its own detached context
// (mirrors the insertTurnDetached / captureProcessNetwork precedent). The
// response path never waits on it — a slow or hung sink cannot add latency
// to the handler, only to how promptly its own trace appears. It is
// fail-open in two ways: a panic inside the call is recovered (never crashes
// the proxy) and a returned error is logged at DEBUG and never surfaces to
// the caller or affects the turn that was already durably recorded.
type ObsSink interface {
	SynthesizeChatTurn(ctx context.Context, facts ChatTurnFacts) error
}

// ObsContentExtractor is the optional seam that closes the gateway-rail
// content-truncation class (trajectory-ui-rollup-and-spandetail-fixes spec,
// Lane B): when [Options].ObsContentExtractor is non-nil, synthesizeObsTrace
// calls it SYNCHRONOUSLY, on the request-handling path, AFTER the client
// already has its response bytes — over the FULL, uncopied reqBody/respBody
// (never the 64 KiB obsClipBody/obsClipResponseBody prefix/tail those
// helpers exist for in the no-extractor fallback path). Extracting from the
// full bodies at the source fixes the truncation class outright: a tail-clip
// of a long SSE stream loses the response's HEAD (a live capture started
// mid-sentence); a head-clip of a >64 KiB request body cuts mid-JSON and
// drops the prompt entirely.
//
// Implementations MUST return bounded strings (the cmd/observer wiring
// returns text already clipped to its own content-clip bound) — the caller
// treats the return values as ready to store, not as raw bodies to clip
// again. Either return value may be "" when nothing could be extracted
// (unparseable/absent body) — never an error; a body this seam can't make
// sense of simply yields no content, exactly like the legacy path.
//
// Bound at the obs wiring point (cmd/observer/obs_wire.go), same as ObsSink
// — internal/proxy must never import internal/obs or any cmd/observer code
// (the reverse-import boundary, tests/invariant/obs_boundary_test.go). nil
// (the default) leaves synthesizeObsTrace's behavior byte-identical to
// before this seam existed: bodies are clipped by obsClipBody/
// obsClipResponseBody and handed across on ChatTurnFacts.Request/ResponseBody
// for the sink to extract from itself.
type ObsContentExtractor func(reqBody, respBody []byte) (prompt, response string)

// obsLaneCtxKey carries the /up/<id> upstream-lane routing id on the request
// context (stamped in serve() right after resolveUpstreamPrefix). Its presence
// is the PLANE BOUNDARY discriminator for the gateway rail: Plane A (general
// observability of hosted apps) synthesizes traces ONLY for turns that
// arrived via an explicit /up/<id> lane — the lane a co-resident hosted app
// (Open WebUI → /up/openrouter) is pointed at. The default provider lanes
// (ANTHROPIC_BASE_URL, codex base_url, gemini) carry Plane-B coding-agent
// traffic, which already has its own rail (api_turns → sessions →
// coding-agent org rollups) and must NEVER appear in the Hosted Apps
// Trajectory explorer. A coding agent deliberately routed through a /up/
// lane (hermes → OpenRouter) is the documented residual — see
// docs/observability.md.
type obsLaneCtxKey struct{}

// obsUpstreamLane returns the /up/<id> routing id the request arrived on, or
// "" for the default (Plane-B) provider lanes.
func obsUpstreamLane(r *http.Request) string {
	if r == nil {
		return ""
	}
	id, _ := r.Context().Value(obsLaneCtxKey{}).(string)
	return id
}

// ChatTurnFacts is the plain, obs-type-free projection of one proxied LLM
// turn the gateway-rail sink needs to synthesize a trace. It mirrors the
// subset of models.APITurn's public fields the sink cares about rather than
// handing across the APITurn value itself, so a future APITurn field never
// forces an edit on the obs side of the reverse-import boundary, and no
// models.APITurn (or obs type) crosses this seam undeclared.
//
// RequestBody/ResponseBody carry the RAW upstream HTTP bodies (whatever
// shape captureNetwork already captured for this call — Anthropic Messages
// API or OpenAI Chat Completions, success or error) so the sink can
// synthesize "audited view" content (prompt/response text) the same way the
// OTLP ingest path does. This is plain bytes, not obs types — the sink is
// responsible for parsing, extracting, gating (its node's content posture),
// and bounding what it persists; a parse failure must never fail the turn.
// May be nil (e.g. a body-less call site, or bodies the caller chose not to
// thread through) — the sink must tolerate that and simply capture nothing.
type ChatTurnFacts struct {
	// APITurnID is the already-inserted api_turns row this trace anchors to
	// (soft join, like Span.RequestID — not an FK). Always non-zero: the
	// proxy only calls SynthesizeChatTurn after a successful insert.
	APITurnID int64
	// RequestID is the upstream/provider request id, used to mint
	// deterministic trace/span ids (§ obs_wire.go) so a later real OTLP span
	// for the same call reconciles instead of double-counting. May be empty
	// for turns where the provider never echoed one; the sink is expected to
	// skip synthesis rather than mint an id from an empty string.
	RequestID string
	SessionID string
	// User is the resolved admission-user identity (p.admissionUser(r)),
	// populated whenever this sink is wired even if admission itself is
	// disabled — see cmd/observer/obs_wire.go's AdmissionUserHeader lift.
	// Empty when no identity header was sent/configured.
	User string
	// Service is the app's service name from X-Superbased-Service on the
	// lane (applane.go; L7 gap 1): the synthesized trace carries it, so
	// service-scoped app caps and the AI Apps service views see the call.
	// Empty when the app sent none.
	Service  string
	Provider string
	Model    string

	// Timestamp is the turn's start time (Trace/root-span StartedAt).
	Timestamp time.Time
	// TotalResponseMS is wall-clock turn duration; EndedAt = Timestamp +
	// TotalResponseMS.
	TotalResponseMS int64
	// TimeToFirstTokenMS is 0 when not applicable (non-streaming, or the
	// turn never produced a first token) — a real, representable duration
	// vs. "unknown" is not currently distinguished on models.APITurn either.
	TimeToFirstTokenMS int64

	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64

	// CostUSD is the proxy-priced cost (never re-priced by the sink — the
	// span's CostSource is always "reported", CLAUDE.md rule: one owner per
	// piece of state, the proxy cost engine owns pricing). 0 is a valid,
	// meaningful value (e.g. a free-tier / local model), not "unknown".
	CostUSD float64

	StopReason string

	// HTTPStatus/ErrorClass/ErrorMessage are populated on error / guard-deny
	// turns (buildErrorTurn); HTTPStatus 0 or 2xx ⇒ a normal success turn.
	HTTPStatus   int
	ErrorClass   string
	ErrorMessage string

	// RequestBody/ResponseBody are the raw upstream HTTP bodies for this
	// call, as already captured by the proxy's own network-capture path
	// (see the type doc comment above). Either may be nil/empty.
	//
	// LEGACY MODE (ObsContentExtractor unwired, ContentExtracted false):
	// these carry the obsClipBody/obsClipResponseBody-clipped bodies, and
	// the sink is expected to extract prompt/response text from them
	// itself — see PromptText/ResponseText below for the alternative.
	//
	// EXTRACTED MODE (ObsContentExtractor wired, ContentExtracted true):
	// these are always NIL — the extractor already ran over the FULL
	// bodies before ChatTurnFacts was built, so there is nothing left for
	// the sink to parse and no reason to retain the (potentially large)
	// raw bytes past that point.
	RequestBody  []byte
	ResponseBody []byte

	// PromptText/ResponseText carry the ALREADY-EXTRACTED, already-bounded
	// prompt/response text when [Options].ObsContentExtractor is wired (see
	// ContentExtracted). Authoritative in that mode — read these instead of
	// attempting to parse Request/ResponseBody (which are nil then). Zero
	// value ("") in legacy mode, where the sink extracts from the bodies
	// itself instead.
	PromptText   string
	ResponseText string

	// ContentExtracted reports which of the two content-carrying schemes
	// above is populated for this ChatTurnFacts: true ⇒ PromptText/
	// ResponseText are authoritative and Request/ResponseBody are nil;
	// false (the default, legacy mode — no extractor wired) ⇒ the reverse.
	// A sink branches on this field once, at the top of its own content
	// extraction, rather than probing which fields happen to be non-empty.
	ContentExtracted bool
}
