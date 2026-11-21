package genaiattr

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/otelident"
)

// TestTableRowsUnique: a (key, field) pair appears once, every row names a
// known dialect, and every field has at least one key.
func TestTableRowsUnique(t *testing.T) {
	known := map[Dialect]bool{
		DialectGenAI: true, DialectGenAILegacy: true, DialectOpenInference: true,
		DialectTraceloop: true, DialectGeneric: true, DialectIdentity: true,
		DialectLangfuse: true, DialectAISDK: true,
	}
	seen := map[[2]string]bool{}
	for _, k := range Table() {
		pair := [2]string{k.Name, string(k.Field)}
		if seen[pair] {
			t.Errorf("duplicate row %v", pair)
		}
		seen[pair] = true
		if !known[k.Dialect] || k.Name == "" {
			t.Errorf("bad row %+v", k)
		}
	}
	for _, f := range AllFields() {
		if len(Keys(f)) == 0 {
			t.Errorf("field %q has no keys", f)
		}
	}
}

// TestShippedOrderKept: the precedence the two mappers shipped before this
// package existed survives as a subsequence of each field's list, so no
// existing span maps differently; only pinned names were added ahead.
func TestShippedOrderKept(t *testing.T) {
	shipped := map[Field][]string{
		FieldModel:            {"gen_ai.response.model", "gen_ai.request.model", "llm.model_name", "llm.model", "model"},
		FieldProvider:         {"gen_ai.provider.name", "gen_ai.system", "llm.provider", "llm.system", "llm.vendor", "provider"},
		FieldInputTokens:      {"gen_ai.usage.input_tokens", "gen_ai.usage.prompt_tokens", "llm.token_count.prompt", "llm.usage.prompt_tokens"},
		FieldOutputTokens:     {"gen_ai.usage.output_tokens", "gen_ai.usage.completion_tokens", "llm.token_count.completion", "llm.usage.completion_tokens"},
		FieldTotalTokens:      {"gen_ai.usage.total_tokens", "llm.token_count.total", "llm.usage.total_tokens"},
		FieldCacheReadTokens:  {"gen_ai.usage.cache_read_input_tokens", "gen_ai.usage.cached_tokens", "llm.token_count.prompt_details.cache_read", "llm.token_count.cache_read"},
		FieldCacheWriteTokens: {"gen_ai.usage.cache_creation_input_tokens", "llm.token_count.prompt_details.cache_write", "llm.token_count.cache_write"},
		FieldReasoningTokens:  {"gen_ai.usage.reasoning_tokens", "gen_ai.usage.completion_tokens_details.reasoning_tokens", "llm.token_count.completion_details.reasoning", "llm.token_count.reasoning"},
		FieldRequestID:        {"gen_ai.request.id", "request.id", "request_id", "http.request.header.x-request-id"},
		FieldResponseID:       {"gen_ai.response.id", "llm.response.id", "response.id"},
		FieldSession:          {"sbo.session", "session.id", "gen_ai.conversation.id", "conversation.id", "langfuse.session.id", "traceloop.association.properties.session_id", "thread.id"},
		FieldThread:           {"thread.id", "gen_ai.thread.id"},
		FieldToolName:         {"tool.name", "gen_ai.tool.name"},
		FieldToolCallID:       {"gen_ai.tool.call.id", "tool_call.id", "tool.call_id"},
		FieldPromptValue:      {"input.value", "gen_ai.prompt", "llm.prompt", "prompt"},
		FieldResponseValue:    {"output.value", "gen_ai.output.value", "gen_ai.completion", "llm.completion", "completion"},
		FieldEntityName:       {"traceloop.entity.name", "traceloop.workflow.name"},
	}
	for f, want := range shipped {
		got := Keys(f)
		i := 0
		for _, k := range got {
			if i < len(want) && k == want[i] {
				i++
			}
		}
		if i != len(want) {
			t.Errorf("%s = %v lost the shipped order %v", f, got, want)
		}
	}
}

// TestPinnedNamesLead: every pinned GenAI usage name leads its bucket, and
// the underscore forms stay accepted.
func TestPinnedNamesLead(t *testing.T) {
	for f, lead := range map[Field]string{
		FieldCacheReadTokens:  "gen_ai.usage.cache_read.input_tokens",
		FieldCacheWriteTokens: "gen_ai.usage.cache_write.input_tokens",
		FieldReasoningTokens:  "gen_ai.usage.reasoning.output_tokens",
		FieldToolArguments:    "gen_ai.tool.call.arguments",
		FieldToolResult:       "gen_ai.tool.call.result",
		FieldFinishReasons:    "gen_ai.response.finish_reasons",
	} {
		if ks := Keys(f); len(ks) == 0 || ks[0] != lead {
			t.Errorf("%s leads with %v, want %q", f, ks, lead)
		}
	}
	for _, k := range []string{"gen_ai.usage.cache_read_input_tokens", "gen_ai.usage.cache_creation_input_tokens", "gen_ai.usage.cache_creation.input_tokens"} {
		if _, ok := KeySet(FieldCacheReadTokens, FieldCacheWriteTokens)[k]; !ok {
			t.Errorf("%s no longer accepted", k)
		}
	}
}

// TestIdentityFromOtelident: tenant and user are otelident's lists, never
// redefined here.
func TestIdentityFromOtelident(t *testing.T) {
	if !reflect.DeepEqual(Keys(FieldTenant), otelident.TenantKeys) || !reflect.DeepEqual(Keys(FieldUser), otelident.UserKeys) {
		t.Errorf("identity keys diverged from otelident: %v %v", Keys(FieldTenant), Keys(FieldUser))
	}
}

// TestKeysWhere filters by dialect in precedence order.
func TestKeysWhere(t *testing.T) {
	got := KeysWhere(FieldCacheReadTokens, func(k Key) bool { return k.Dialect == DialectOpenInference })
	want := []string{"llm.token_count.prompt_details.cache_read", "llm.token_count.cache_read"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("KeysWhere = %v, want %v", got, want)
	}
}

// TestSessionKeysHaveOneOwner pins review E-22: the session field is
// internal/otelident's list, not a second copy that drifts from it.
func TestSessionKeysHaveOneOwner(t *testing.T) {
	if got := Keys(FieldSession); !reflect.DeepEqual(got, otelident.SessionKeys) {
		t.Fatalf("Keys(FieldSession) = %v, want otelident.SessionKeys %v", got, otelident.SessionKeys)
	}
}
