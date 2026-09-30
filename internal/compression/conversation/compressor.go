package conversation

import (
	"github.com/marmutapp/superbased-observer/internal/compression/conversation/types"
)

// Compressor transforms a tool_result body into a shorter form appropriate
// for its content type. Compressors are deterministic and side-effect free:
// the same input always produces the same output, and the output is safe to
// forward upstream in place of the original body. When compression would
// not reduce size, implementations may return the original body unchanged.
type Compressor interface {
	// Compress returns the compressed body. It never returns nil — an empty
	// input yields an empty output.
	Compress(body []byte) []byte
	// Type is the content type this compressor handles.
	Type() types.ContentType
}

// HintedCompressor is an OPTIONAL interface compressors can implement to
// receive contextual hints (filename, code-index symbols) the
// caller has at hand but wouldn't normally pass through the bare
// [Compressor] surface. Registry detects implementations via type
// assertion at compress-time; compressors that don't implement it
// fall through to the basic [Compressor.Compress].
//
// Today only LogsCompressor opts in — it enriches the elision marker
// with the filename + a top-N symbol summary so codex-variant models
// reading the marker get structural context instead of a bare
// `[N lines elided]`. (V7-11 mitigation (e); see
// docs/v4-codex-compression-recipe-and-issues.md.)
//
// Implementations MUST tolerate a zero-valued [CompressHints] — empty
// filename + nil Symbols MUST produce identical output to plain
// Compress(body). This keeps the type-assertion plumbing safe even
// when the caller doesn't supply hints.
type HintedCompressor interface {
	Compressor
	CompressHinted(body []byte, hints CompressHints) []byte
}

// CompressHints carries optional context the caller forwards to a
// HintedCompressor. All fields are best-effort — the zero value is a
// valid, fully-degraded hint that reduces compressor behaviour to the
// plain [Compressor.Compress] form.
type CompressHints struct {
	// Filename is the source filename when the producing tool's
	// argument carried a path. Used by LogsCompressor to enrich the
	// elision marker. Empty when the body has no associated file
	// (e.g. ad-hoc shell command output, network responses).
	Filename string

	// Symbols, when non-empty, is the pre-fetched top-N symbol summary
	// from the code index (codeintel) for Filename. Caller is
	// responsible for the staleness check (see SymbolLookup.Stale);
	// compressors trust the data they receive. nil means "no enrichment
	// data available" — either the index is disabled, the file isn't
	// indexed, or
	// the index is stale.
	Symbols []CompressorSymbol
}

// CompressorSymbol is the pure-data representation of a code symbol
// the conversation package uses for marker enrichment. Mirrors
// codeintel.Symbol but lives in this package so we don't import
// internal/codeintel (avoiding bidirectional coupling — the
// conversation package never depends on codeintel internals; the
// adapter at cmd/observer/proxy.go bridges the two).
type CompressorSymbol struct {
	// Name is the symbol's identifier as it appears in the source
	// (function name, class name, etc.). Used in the marker.
	Name string
	// Kind is the symbol's category ("function", "class", "interface",
	// "type", "method"). Used to prefix the symbol in the marker
	// (e.g. "fn handleClick", "class Editor").
	Kind string
	// StartLine + EndLine carry the symbol's location in the source.
	// Used for sorting (deterministic marker output across repeated
	// compressions of identical bodies — critical for prefix-cache hits)
	// AND, when Exact, as the body-collapse span.
	StartLine int
	EndLine   int
	// Exact reports whether the span is byte-accurate (an exact-span
	// backend). ADR-0005: the aggressive code-collapse pass collapses a
	// body ONLY for Exact symbols; a heuristic/approximate span is
	// non-destructive (enrichment + content-preserving only). Zero value
	// (false) is the safe default for every existing producer.
	Exact bool
}

// Registry maps a ContentType to its Compressor.
type Registry struct {
	m map[types.ContentType]Compressor
}

// NewRegistry builds an empty Registry.
func NewRegistry() *Registry {
	return &Registry{m: make(map[types.ContentType]Compressor)}
}

// DefaultRegistry builds a Registry populated with the built-in compressors
// for every content type exposed by [types.All].
func DefaultRegistry() *Registry {
	r := NewRegistry()
	r.Register(NewJSONCompressor())
	r.Register(NewLogsCompressor())
	r.Register(NewTextCompressor(TextOptions{}))
	r.Register(NewDiffCompressor())
	r.Register(NewHTMLCompressor())
	r.Register(NewCodeCompressor())
	return r
}

// RegistryOptions bundles the per-compressor knobs that come from the
// `[compression.conversation]` TOML block. Zero-valued fields fall back
// to each compressor's own defaults (matching [DefaultRegistry]).
//
// New per-type knobs surface here as they are exposed to operators —
// keeps the production wiring (`cmd/observer/proxy.go`) one-call away
// from a fully-configured Registry without having to know each
// compressor's constructor.
type RegistryOptions struct {
	Logs LogsOptions
	Text TextOptions
}

// BuildRegistryFromConfig builds a Registry whose mutable-knob
// compressors (LogsCompressor, TextCompressor) honour opts. Other
// compressors (JSON, Diff, HTML, Code) carry no operator-tunable state
// today and are constructed with their package defaults. Mirrors
// [DefaultRegistry] when opts is a zero value.
func BuildRegistryFromConfig(opts RegistryOptions) *Registry {
	r := NewRegistry()
	r.Register(NewJSONCompressor())
	r.Register(NewLogsCompressorWithOptions(opts.Logs))
	r.Register(NewTextCompressor(opts.Text))
	r.Register(NewDiffCompressor())
	r.Register(NewHTMLCompressor())
	r.Register(NewCodeCompressor())
	return r
}

// Register installs c under its Type. A later registration for the same type
// replaces the earlier one.
func (r *Registry) Register(c Compressor) {
	r.m[c.Type()] = c
}

// Get returns the compressor for t, or (nil, false) when none is registered.
func (r *Registry) Get(t types.ContentType) (Compressor, bool) {
	c, ok := r.m[t]
	return c, ok
}

// Compress detects the type of body (using filename as an optional hint) and
// runs the matching compressor. Returns (compressed, detected, true) on a
// successful compression, or (body, detected, false) when no compressor is
// registered for the detected type. Unknown types are returned unchanged.
//
// When the matched compressor implements [HintedCompressor], filename is
// forwarded via CompressHints so the compressor can enrich any markers
// it emits with the file path. Other compressors fall through to the
// basic [Compressor.Compress] path — they receive no hint surface and
// produce identical output to pre-v1.7.7 behaviour.
func (r *Registry) Compress(body []byte, filename string) ([]byte, types.ContentType, bool) {
	t := types.Detect(body, filename)
	if t == types.Unknown {
		return body, t, false
	}
	c, ok := r.Get(t)
	if !ok {
		return body, t, false
	}
	if hc, ok := c.(HintedCompressor); ok {
		return hc.CompressHinted(body, CompressHints{Filename: filename}), t, true
	}
	return c.Compress(body), t, true
}
