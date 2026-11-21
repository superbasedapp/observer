package genaiattr

import "testing"

// TestReadUsageShapes has one case per shape-table row plus the no-total and
// no-match edges. The counts are the C5/C6 instrument fixtures' (bedrock-ts,
// gemini-ts, anthropic) and synthetic rows for the rest.
func TestReadUsageShapes(t *testing.T) {
	cases := []struct {
		name          string
		attrs         map[string]any
		input, output CountShape
	}{
		{"gross/gross: OpenInference anthropic (anthropic.json)", map[string]any{
			"llm.token_count.prompt": int64(2130), "llm.token_count.completion": int64(5), "llm.token_count.total": int64(2135),
			"llm.token_count.prompt_details.cache_read": int64(2000), "llm.token_count.prompt_details.cache_write": int64(100),
		}, ShapeGross, ShapeGross},
		{"net input: OpenInference Bedrock JS (bedrock-ts.json)", map[string]any{
			"llm.token_count.prompt": int64(30), "llm.token_count.completion": int64(5), "llm.token_count.total": int64(2135),
			"llm.token_count.prompt_details.cache_read": int64(2000), "llm.token_count.prompt_details.cache_write": int64(100),
		}, ShapeNet, ShapeGross},
		{"net output: OpenLLMetry Gemini (gemini-ts.json)", map[string]any{
			"gen_ai.usage.input_tokens": int64(1200), "gen_ai.usage.output_tokens": int64(24), "gen_ai.usage.total_tokens": int64(1240),
			"gen_ai.usage.cache_read.input_tokens": int64(1024), "gen_ai.usage.reasoning_tokens": int64(16),
		}, ShapeGross, ShapeNet},
		{"both net", map[string]any{
			"gen_ai.usage.input_tokens": int64(10), "gen_ai.usage.output_tokens": int64(4), "gen_ai.usage.total_tokens": int64(120),
			"gen_ai.usage.cache_read.input_tokens": int64(100), "gen_ai.usage.reasoning_tokens": int64(6),
		}, ShapeNet, ShapeNet},
		{"no reported total: the vocabulary's gross", map[string]any{
			"gen_ai.usage.input_tokens": int64(30), "gen_ai.usage.output_tokens": int64(5),
			"gen_ai.usage.cache_read.input_tokens": int64(2000),
		}, ShapeGross, ShapeGross},
		{"no row matches: the vocabulary's gross", map[string]any{
			"gen_ai.usage.input_tokens": int64(30), "gen_ai.usage.output_tokens": int64(5), "gen_ai.usage.total_tokens": int64(999),
			"gen_ai.usage.cache_read.input_tokens": int64(2000),
		}, ShapeGross, ShapeGross},
		{"no cache: a net row cannot match", map[string]any{
			"gen_ai.usage.input_tokens": int64(30), "gen_ai.usage.output_tokens": int64(5), "gen_ai.usage.total_tokens": int64(35),
		}, ShapeGross, ShapeGross},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u := ReadUsage(mapAttrs(c.attrs))
			if u.InputShape != c.input || u.OutputShape != c.output {
				t.Fatalf("shapes = %q/%q, want %q/%q", u.InputShape, u.OutputShape, c.input, c.output)
			}
		})
	}
	if n := len(ShapeRuleNames()); n != 4 {
		t.Fatalf("shape rules = %d, want 4 (one case per row above)", n)
	}
}

// mapAttrs renders integer test attributes as OTLP values.
func mapAttrs(m map[string]any) Attrs {
	out := Attrs{}
	for k, v := range m {
		out[k] = iv(v.(int64))
	}
	return out
}
