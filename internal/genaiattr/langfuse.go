package genaiattr

import (
	"bytes"
	"encoding/json"
	"strings"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

// The langfuse dialect (Plane A build-out W5-2, lane C7): the attributes the
// Langfuse SDKs put on the OTel spans they export, so a team already
// instrumented with Langfuse can point its exporter at superbased unchanged.
//
// Grounding (no network call, no key): the SDK sources as published,
// consulted 2026-11-19.
//   - Python `langfuse` 5.2.0, 4.18.0 and 3.15.0 from PyPI:
//     langfuse/_client/attributes.py (LangfuseOtelSpanAttributes,
//     create_generation_attributes, _flatten_and_serialize_metadata),
//     _client/constants.py (the observation types), _client/propagation.py
//     (user, session, tags, metadata, environment), _client/span_processor.py
//     (the exporter: Basic public:secret auth, path
//     /api/public/otel/v1/traces), openai.py::_parse_usage and
//     langchain/CallbackHandler.py::_parse_usage_model (the usage_details
//     shapes).
//   - JS `@langfuse/core`, `@langfuse/tracing` and `@langfuse/otel` 6.1.1
//     from npm: the same attribute enum plus the compat keys
//     langfuse.user.id / langfuse.session.id, and the same exporter path.
//
// The tracer scope is LangfuseScopeName; the scope version is the SDK
// version. Python 3.x/4.x and JS 6.x also write langfuse.trace.input /
// langfuse.trace.output on the span that carries the trace's I/O; Python 5.x
// dropped them. Python 5.x and JS 6.x JSON-encode EVERY metadata value,
// strings included (MetadataValueText undoes that).
//
// Identity (user.id, session.id, langfuse.user.id, langfuse.session.id,
// langfuse.trace.tags, langfuse.trace.metadata[.*], langfuse.release,
// langfuse.environment) lives in internal/otelident; the trace's environment
// label there is the APP's, never the workspace environment, which comes from
// the ingest credential only (plan §3 principle 3). Tags ship raw only under
// shipsRawContent() (D25); a reported cost stays "reported" (D24).
//
// Scores are NOT on the OTLP wire: the Langfuse SDKs send them over the
// Langfuse REST API (POST /api/public/scores), which superbased does not
// emulate; the superbased SDK's score API or the gen_ai.evaluation.result
// event is the score path (evaluation.go).

// DialectLangfuse is the Langfuse SDKs' langfuse.* attribute vocabulary.
const DialectLangfuse Dialect = "langfuse"

// DialectAISDK is the Vercel AI SDK's own ai.* telemetry keys (beside the
// GenAI semconv keys it also emits).
const DialectAISDK Dialect = "ai_sdk"

const (
	lf  = DialectLangfuse
	ais = DialectAISDK
)

// The Langfuse names this package reads (attributes.py
// LangfuseOtelSpanAttributes, langfuse 5.2.0).
const (
	LangfuseScopeName           = "langfuse-sdk"
	LangfuseObservationType     = "langfuse.observation.type"
	LangfuseObservationInput    = "langfuse.observation.input"
	LangfuseObservationOutput   = "langfuse.observation.output"
	LangfuseTraceInput          = "langfuse.trace.input"
	LangfuseTraceOutput         = "langfuse.trace.output"
	LangfuseObservationModel    = "langfuse.observation.model.name"
	LangfuseModelParameters     = "langfuse.observation.model.parameters"
	LangfuseUsageDetails        = "langfuse.observation.usage_details"
	LangfuseCostDetails         = "langfuse.observation.cost_details"
	LangfusePromptName          = "langfuse.observation.prompt.name"
	LangfusePromptVersion       = "langfuse.observation.prompt.version"
	LangfuseStatusMessage       = "langfuse.observation.status_message"
	LangfuseCompletionStartTime = "langfuse.observation.completion_start_time"
)

// LangfuseOTLPTracesPath is the path the Langfuse SDK exporters append to
// LANGFUSE_BASE_URL (span_processor.py, @langfuse/otel). The machine
// receiver and the org gateway serve it as an alias of /v1/traces, with
// superbased's own auth (docs/sdk/langfuse.md).
const LangfuseOTLPTracesPath = "/api/public/otel/v1/traces"

// The langfuse dialect's own fields (each a single key).
const (
	// FieldObservationType is the Langfuse observation type
	// (ObservationTypes).
	FieldObservationType Field = "observation_type"
	// FieldStatusMessage is a status message carried as an attribute (the
	// OTLP status message wins).
	FieldStatusMessage Field = "status_message"
	// FieldUsageDetails is a JSON usage object (ReadUsage decodes it).
	FieldUsageDetails Field = "usage_details"
	// FieldCostDetails is a JSON cost object, USD (ReadCost decodes it).
	FieldCostDetails Field = "cost_details"
	// FieldModelParameters is a JSON request-parameter object
	// (RequestParams merges it like OpenInference's invocation parameters).
	FieldModelParameters Field = "model_parameters"
	// FieldCompletionStartTime is the time the first output token arrived
	// (a JSON-encoded ISO-8601 string). Read, not stored: no column yet.
	FieldCompletionStartTime Field = "completion_start_time"
)

// langfuseRows are the langfuse dialect's own fields. Its spellings of the
// shared fields (model, input/output, prompt) sit in those fields' rows in
// registry.go, at their precedence.
func langfuseRows() []Key {
	return concat(
		rows(FieldObservationType, LangfuseObservationType, lf),
		rows(FieldStatusMessage, LangfuseStatusMessage, lf),
		rows(FieldUsageDetails, LangfuseUsageDetails, lf),
		rows(FieldCostDetails, LangfuseCostDetails, lf),
		rows(FieldModelParameters, LangfuseModelParameters, lf),
		rows(FieldCompletionStartTime, LangfuseCompletionStartTime, lf),
	)
}

// ObservationTypes is the closed Langfuse observation-type vocabulary
// (constants.py ObservationTypeLiteral, langfuse 5.2.0; @langfuse/tracing
// LangfuseObservationType 6.1.1), each with the canonical kind class it
// names. "span" (the default) and "event" name no class: a mapper keeps
// classifying such a span by its other attributes.
var ObservationTypes = map[string]string{
	"generation": "llm",
	"embedding":  "embedding",
	"agent":      "agent",
	"tool":       "tool",
	"chain":      "chain",
	"retriever":  "retriever",
	"evaluator":  "evaluator",
	"guardrail":  "guardrail",
	"span":       "",
	"event":      "",
}

// ObservationKind returns the canonical kind class a span's Langfuse
// observation type names ("llm", "tool", ...), "" when it names none.
func ObservationKind(a Attrs) string {
	return ObservationTypes[strings.ToLower(strings.TrimSpace(a.First(Keys(FieldObservationType))))]
}

// ---- usage_details ----

// maxDetailsBytes bounds a usage/cost details blob; a larger one is ignored
// (it is still retained, bounded, in the raw-attribute envelope).
const maxDetailsBytes = 16 << 10

// usageShape is one usage_details vocabulary. A bucket's "sum" list adds
// every present key (Langfuse's disjoint buckets: its total is the sum of
// every usage type), its "first" list takes the first present key. A key
// ending in "_" is a prefix: every integer member starting with it counts,
// minus the excluded prefixes.
type usageShape struct {
	name    string
	detect  []string // any member present selects the shape
	input   []string // summed into the GROSS input
	output  []string // summed into the GROSS output
	total   []string
	cacheR  []string
	cacheW  []string
	reason  []string
	exclude []string // prefixes never summed
}

// usageShapes are walked top-down; the first whose detect key is present
// decodes the blob.
//
//   - openai_chat / openai_responses: the provider's own usage object, which
//     the Langfuse OpenAI integration and the LangChain handler pass through
//     for the Langfuse server to normalize. Its input / output counts are
//     already GROSS; the cache and reasoning counts are nested subsets.
//   - langfuse: the Langfuse model, disjoint buckets whose sum is the total.
//     The LangChain handler subtracts every input_* / output_* detail from
//     input / output (CallbackHandler.py), and Anthropic's raw usage counts
//     input_tokens net of cache_read_input_tokens / cache_creation_input_tokens,
//     so the GROSS input is the sum of every input bucket. This decodes the
//     dialect's definition; it is not a provider netting rule (the host
//     pricer still owns those).
var usageShapes = []usageShape{
	{
		name:   "openai_chat",
		detect: []string{"prompt_tokens", "completion_tokens"},
		input:  []string{"prompt_tokens"}, output: []string{"completion_tokens"},
		total:  []string{"total_tokens"},
		cacheR: []string{"prompt_tokens_details.cached_tokens"},
		cacheW: []string{"prompt_tokens_details.cache_creation_tokens"},
		reason: []string{"completion_tokens_details.reasoning_tokens"},
	},
	{
		name:   "openai_responses",
		detect: []string{"input_tokens_details", "output_tokens_details"},
		input:  []string{"input_tokens"}, output: []string{"output_tokens"},
		total:  []string{"total_tokens"},
		cacheR: []string{"input_tokens_details.cached_tokens"},
		reason: []string{"output_tokens_details.reasoning_tokens"},
	},
	{
		name:   "langfuse",
		detect: []string{"input", "output", "total", "input_", "output_", "cache_read_input_tokens", "cache_creation_input_tokens"},
		input:  []string{"input", "input_", "cache_read_input_tokens", "cache_creation_input_tokens"},
		output: []string{"output", "output_"},
		total:  []string{"total"},
		cacheR: []string{"input_cache_read", "input_cached_tokens", "input_cache_read_tokens", "cache_read_input_tokens"},
		cacheW: []string{"input_cache_creation", "input_cache_creation_tokens", "input_cache_write", "cache_creation_input_tokens"},
		reason: []string{"output_reasoning", "output_reasoning_tokens"},
		// Priority-tier keys are not exclusive sub-categories
		// (CallbackHandler.py skips them when netting).
		exclude: []string{"input_priority", "output_priority"},
	},
}

// detailsObject decodes a details blob into a flat map: nested objects are
// flattened one level deep with a "." separator. nil when the value is not
// a JSON object (or is too large).
func detailsObject(s string) map[string]json.Number {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxDetailsBytes || !strings.HasPrefix(s, "{") {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var obj map[string]any
	if dec.Decode(&obj) != nil {
		return nil
	}
	out := make(map[string]json.Number, len(obj))
	for k, v := range obj {
		switch x := v.(type) {
		case json.Number:
			out[k] = x
		case map[string]any:
			out[k] = "" // present (a shape may detect on it), never a count
			for nk, nv := range x {
				if n, ok := nv.(json.Number); ok {
					out[k+"."+nk] = n
				}
			}
		}
	}
	return out
}

// matches reports whether member m is named by pattern p (exact, or a
// prefix pattern ending in "_").
func matches(p, m string) bool {
	if strings.HasSuffix(p, "_") {
		return strings.HasPrefix(m, p)
	}
	return m == p
}

func excluded(m string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

// integral returns n as an int64 when it is a whole, non-negative count.
func integral(n json.Number) (int64, bool) {
	if i, err := n.Int64(); err == nil {
		return i, i >= 0
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f != float64(int64(f)) {
		return 0, false
	}
	return int64(f), true
}

// sumMembers adds every integral member named by pats (each member once).
// nil when none is present.
func sumMembers(obj map[string]json.Number, pats, exclude []string) *int64 {
	var sum int64
	found := false
	for m, n := range obj {
		if strings.Contains(m, ".") || excluded(m, exclude) {
			continue
		}
		for _, p := range pats {
			if matches(p, m) {
				if v, ok := integral(n); ok {
					sum += v
					found = true
				}
				break
			}
		}
	}
	if !found {
		return nil
	}
	return &sum
}

// firstMember returns the first integral member of keys present.
func firstMember(obj map[string]json.Number, keys []string) *int64 {
	for _, k := range keys {
		if n, ok := obj[k]; ok {
			if v, ok := integral(n); ok {
				return &v
			}
		}
	}
	return nil
}

func (sh usageShape) detected(obj map[string]json.Number) bool {
	for m := range obj {
		for _, p := range sh.detect {
			if matches(p, m) {
				return true
			}
		}
	}
	return false
}

// usageFromDetails decodes a usage_details blob onto the Usage buckets (the
// package doc's bucket semantics: gross input, output incl. reasoning). The
// zero Usage when the blob is absent or matches no shape.
func usageFromDetails(s string) Usage {
	obj := detailsObject(s)
	if obj == nil {
		return Usage{}
	}
	for _, sh := range usageShapes {
		if !sh.detected(obj) {
			continue
		}
		return Usage{
			Input:      sumMembers(obj, sh.input, sh.exclude),
			Output:     sumMembers(obj, sh.output, sh.exclude),
			Total:      firstMember(obj, sh.total),
			CacheRead:  firstMember(obj, sh.cacheR),
			CacheWrite: firstMember(obj, sh.cacheW),
			Reasoning:  firstMember(obj, sh.reason),
		}
	}
	return Usage{}
}

// empty reports whether no bucket of u is set.
func (u Usage) empty() bool {
	return u.Input == nil && u.Output == nil && u.Total == nil &&
		u.CacheRead == nil && u.CacheWrite == nil && u.Reasoning == nil
}

// ---- cost_details ----

// costShape names the cost_details members of each reported-cost component
// (first present wins). cost_details keys mirror the usage types, so Input is
// the non-cached input cost and never overlaps the cache components.
var costShape = struct {
	total, input, output, cacheR, cacheW, reason []string
}{
	total:  []string{"total"},
	input:  []string{"input"},
	output: []string{"output"},
	cacheR: []string{"input_cache_read", "input_cached_tokens", "input_cache_read_tokens", "cache_read_input_tokens"},
	cacheW: []string{"input_cache_creation", "input_cache_creation_tokens", "input_cache_write", "cache_creation_input_tokens"},
	reason: []string{"output_reasoning", "output_reasoning_tokens"},
}

func firstFloat(obj map[string]json.Number, keys []string) *float64 {
	for _, k := range keys {
		if n, ok := obj[k]; ok {
			if f, err := n.Float64(); err == nil {
				return &f
			}
		}
	}
	return nil
}

// costFromDetails decodes a cost_details blob (USD). With no "total"
// member, the total is the sum of every top-level member: Langfuse's own
// definition of a total cost.
func costFromDetails(s string) Cost {
	obj := detailsObject(s)
	if obj == nil {
		return Cost{}
	}
	c := Cost{
		Total:      firstFloat(obj, costShape.total),
		Input:      firstFloat(obj, costShape.input),
		Output:     firstFloat(obj, costShape.output),
		CacheRead:  firstFloat(obj, costShape.cacheR),
		CacheWrite: firstFloat(obj, costShape.cacheW),
		Reasoning:  firstFloat(obj, costShape.reason),
	}
	if c.Total == nil {
		var sum float64
		found := false
		for m, n := range obj {
			if strings.Contains(m, ".") {
				continue
			}
			if f, err := n.Float64(); err == nil {
				sum += f
				found = true
			}
		}
		if found {
			c.Total = &sum
		}
	}
	return c
}

// ---- metadata ----

// jsonEncodedMetadataPrefixes are the flattened-metadata prefixes whose
// values an emitter JSON-encodes (Python langfuse >= 5, @langfuse/* 6.x:
// "123" and 123 stay distinct, so a string arrives as "\"pro\"").
var jsonEncodedMetadataPrefixes = []string{"langfuse.trace.metadata."}

// MetadataValueText renders one flattened metadata attribute's value: Text,
// except that under a JSON-encoding prefix a JSON string literal is decoded
// to its string (a number, bool, array or object stays its JSON text). An
// older SDK's plain string that happens to be a quoted JSON literal is
// decoded too; that is the accepted cost of one rule for every SDK version.
func MetadataValueText(key string, v *commonpb.AnyValue) string {
	s := Text(v)
	for _, p := range jsonEncodedMetadataPrefixes {
		if !strings.HasPrefix(key, p) {
			continue
		}
		if t := strings.TrimSpace(s); len(t) >= 2 && t[0] == '"' && t[len(t)-1] == '"' {
			var out string
			if json.Unmarshal([]byte(t), &out) == nil {
				return out
			}
		}
		break
	}
	return s
}
