package genaiattr

// CountShape says what a reported usage count includes, relative to the
// vocabulary's bucket definition (the package doc's "Token buckets"). It is a
// mapped FACT, resolved here at the mapping boundary, so a pricer nets or
// adds by it and never by a provider name (review finding E-18).
type CountShape string

// The count shapes.
const (
	// ShapeGross is the vocabulary's definition: Input includes the cache
	// read and cache write tokens, Output includes the reasoning tokens.
	// It is the zero value's meaning (an empty shape reads as gross).
	ShapeGross CountShape = ""
	// ShapeNet is a count reported NET of its subsets: an Input that
	// excludes the cache tokens (Bedrock through OpenInference JS), an Output
	// that excludes the reasoning tokens (Gemini's candidatesTokenCount
	// through OpenLLMetry).
	ShapeNet CountShape = "net"
)

// shapeRule is one row of the shape table: when the reported total equals
// the input and output counts read with the row's shapes, the row's shapes
// are the span's.
type shapeRule struct {
	name          string
	input, output CountShape
}

// shapeRules is walked top-down; the first row whose arithmetic matches the
// REPORTED total wins. The gross/gross row is first, so a span whose counts
// are consistent with the vocabulary is always read as the vocabulary
// defines it. A row that would need an absent subset (a net input with no
// cache count, a net output with no reasoning count) never matches, so
// those cases cannot shadow the gross row. With no reported total, or no row
// matching, the counts keep the vocabulary's meaning (gross): genaiattr's
// keys are all gross by their dialect's own specification (GenAI semconv,
// OpenInference prompt_details subsets, Traceloop, the decoded Langfuse
// usage_details), so a net reporter is an emitter that departs from its
// dialect, and only the reported total can reveal it.
var shapeRules = []shapeRule{
	{name: "consistent with the vocabulary", input: ShapeGross, output: ShapeGross},
	{name: "input reported net of the cache tokens", input: ShapeNet, output: ShapeGross},
	{name: "output reported net of the reasoning tokens", input: ShapeGross, output: ShapeNet},
	{name: "both reported net", input: ShapeNet, output: ShapeNet},
}

// resolveShapes sets u.InputShape and u.OutputShape from the reported total.
// A derived total proves nothing (it is Input + Output by construction).
func resolveShapes(u *Usage) {
	if u.Total == nil || u.TotalDerived || (u.Input == nil && u.Output == nil) {
		return
	}
	in, out := val(u.Input), val(u.Output)
	cache := val(u.CacheRead) + val(u.CacheWrite)
	reasoning := val(u.Reasoning)
	for _, r := range shapeRules {
		if r.input == ShapeNet && cache <= 0 {
			continue
		}
		if r.output == ShapeNet && reasoning <= 0 {
			continue
		}
		total := in + out
		if r.input == ShapeNet {
			total += cache
		}
		if r.output == ShapeNet {
			total += reasoning
		}
		if total == *u.Total {
			u.InputShape, u.OutputShape = r.input, r.output
			return
		}
	}
}

// ShapeRuleNames returns the shape table's row names in order (tests and
// docs).
func ShapeRuleNames() []string {
	out := make([]string, len(shapeRules))
	for i, r := range shapeRules {
		out[i] = r.name
	}
	return out
}

func val(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}
