package otlpvendor

import (
	"reflect"
	"testing"
)

// TestGenAIKeysAreGenaiattrViews pins the GenAI key lists the vendor rows
// read: each is a view of internal/genaiattr (lane A2, W1a-1), current
// semconv spelling first, so a renamed-away spelling still maps.
func TestGenAIKeysAreGenaiattrViews(t *testing.T) {
	for name, c := range map[string]struct{ got, want []string }{
		"request":     {genAIRequest, []string{"gen_ai.response.id"}},
		"model":       {genAIModel, []string{"gen_ai.response.model", "gen_ai.request.model"}},
		"provider":    {genAIProvider, []string{"gen_ai.provider.name", "gen_ai.system"}},
		"input":       {genAIInput, []string{"gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens"}},
		"output":      {genAIOutput, []string{"gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens"}},
		"cache_read":  {genAICacheRead, []string{"gen_ai.usage.cache_read.input_tokens", "gen_ai.usage.cache_read_input_tokens", "gen_ai.usage.cached_tokens"}},
		"cache_write": {genAICacheWrite, []string{"gen_ai.usage.cache_write.input_tokens", "gen_ai.usage.cache_creation.input_tokens", "gen_ai.usage.cache_creation_input_tokens"}},
		"reasoning":   {genAIReasoning, []string{"gen_ai.usage.reasoning.output_tokens", "gen_ai.usage.reasoning_tokens", "gen_ai.usage.completion_tokens_details.reasoning_tokens"}},
		"tool_name":   {genAIToolName, []string{"gen_ai.tool.name"}},
		"tool_call":   {genAIToolCallID, []string{"gen_ai.tool.call.id"}},
		"tool_args":   {genAIToolArgs, []string{"gen_ai.tool.call.arguments"}},
		"tool_result": {genAIToolResult, []string{"gen_ai.tool.call.result"}},
		"error":       {genAIError, []string{"error.type"}},
	} {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}
}
