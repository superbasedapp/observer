package genaiattr

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"

	"github.com/marmutapp/superbased-observer/internal/otelident"
)

// conformanceFile is one dialect's fixture under testdata/conformance.
type conformanceFile struct {
	Source struct {
		Dialect   string `json:"dialect"`
		Grounding string `json:"grounding"`
	} `json:"_source"`
	Cases []struct {
		Name  string                     `json:"name"`
		Attrs map[string]json.RawMessage `json:"attrs"`
		Want  map[string]json.RawMessage `json:"want"`
	} `json:"cases"`
}

// toAnyValue builds an OTLP value from a fixture's JSON value: a string, an
// integer (no fraction or exponent), a double, a bool, an array or an object
// (a kvlist, keys sorted so the case is deterministic).
func toAnyValue(t *testing.T, raw json.RawMessage) *commonpb.AnyValue {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode attr %s: %v", raw, err)
	}
	return anyFromGo(t, v)
}

func anyFromGo(t *testing.T, v any) *commonpb.AnyValue {
	switch x := v.(type) {
	case string:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: x}}
	case bool:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: x}}
	case json.Number:
		if !strings.ContainsAny(string(x), ".eE") {
			n, err := x.Int64()
			if err != nil {
				t.Fatalf("int %s: %v", x, err)
			}
			return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: n}}
		}
		f, err := x.Float64()
		if err != nil {
			t.Fatalf("double %s: %v", x, err)
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: f}}
	case []any:
		arr := &commonpb.ArrayValue{}
		for _, e := range x {
			arr.Values = append(arr.Values, anyFromGo(t, e))
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: arr}}
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		kvl := &commonpb.KeyValueList{}
		for _, k := range keys {
			kvl.Values = append(kvl.Values, &commonpb.KeyValue{Key: k, Value: anyFromGo(t, x[k])})
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: kvl}}
	}
	t.Fatalf("unsupported fixture value %T", v)
	return nil
}

// fieldGetters is the closed table of fixture "want" names: each returns
// the normalised value of one Fields member in a JSON-comparable form.
var fieldGetters = map[string]func(Fields) any{
	"model":               func(f Fields) any { return f.Model },
	"request_model":       func(f Fields) any { return f.RequestModel },
	"response_model":      func(f Fields) any { return f.ResponseModel },
	"provider":            func(f Fields) any { return f.Provider },
	"operation":           func(f Fields) any { return f.Operation },
	"request_type":        func(f Fields) any { return f.RequestType },
	"input_tokens":        func(f Fields) any { return f.Usage.Input },
	"output_tokens":       func(f Fields) any { return f.Usage.Output },
	"total_tokens":        func(f Fields) any { return f.Usage.Total },
	"total_derived":       func(f Fields) any { return f.Usage.TotalDerived },
	"cache_read_tokens":   func(f Fields) any { return f.Usage.CacheRead },
	"cache_write_tokens":  func(f Fields) any { return f.Usage.CacheWrite },
	"reasoning_tokens":    func(f Fields) any { return f.Usage.Reasoning },
	"cost_total":          func(f Fields) any { return f.Cost.Total },
	"cost_input":          func(f Fields) any { return f.Cost.Input },
	"cost_output":         func(f Fields) any { return f.Cost.Output },
	"cost_cache_read":     func(f Fields) any { return f.Cost.CacheRead },
	"response_id":         func(f Fields) any { return f.ResponseID },
	"tool_name":           func(f Fields) any { return f.ToolName },
	"tool_call_id":        func(f Fields) any { return f.ToolCallID },
	"tool_arguments":      func(f Fields) any { return jsonOrText(f.ToolArguments) },
	"tool_result":         func(f Fields) any { return jsonOrText(f.ToolResult) },
	"agent_name":          func(f Fields) any { return f.AgentName },
	"agent_id":            func(f Fields) any { return f.AgentID },
	"entity_name":         func(f Fields) any { return f.EntityName },
	"input_messages":      func(f Fields) any { return jsonOrText(f.InputMessages) },
	"output_messages":     func(f Fields) any { return jsonOrText(f.OutputMessages) },
	"system_instructions": func(f Fields) any { return jsonOrText(f.SystemInstructions) },
	"prompt_value":        func(f Fields) any { return f.PromptValue },
	"response_value":      func(f Fields) any { return f.ResponseValue },
	"input_value":         func(f Fields) any { return jsonOrText(f.InputValue) },
	"output_value":        func(f Fields) any { return jsonOrText(f.OutputValue) },
	"error_type":          func(f Fields) any { return f.ErrorType },
	"finish_reasons":      func(f Fields) any { return f.FinishReasons },
	"request_params":      func(f Fields) any { return jsonOrText(f.RequestParams) },
	"cost_cache_write":    func(f Fields) any { return f.Cost.CacheWrite },
	"cost_reasoning":      func(f Fields) any { return f.Cost.Reasoning },
	"observation_type":    func(f Fields) any { return f.ObservationType },
	"observation_kind":    func(f Fields) any { return ObservationTypes[f.ObservationType] },
	"status_message":      func(f Fields) any { return f.StatusMessage },
}

// attrGetters are the fixture "want" names read straight off the attributes:
// the prompt stamp and the identity keys (internal/otelident), which Fields
// does not carry.
var attrGetters = map[string]func(Attrs) any{
	"prompt_name":    func(a Attrs) any { return a.First(Keys(FieldPromptName)) },
	"prompt_version": func(a Attrs) any { return a.First(Keys(FieldPromptVersion)) },
	"user":           func(a Attrs) any { return a.First(otelident.UserKeys) },
	"session":        func(a Attrs) any { return a.First(otelident.SessionKeys) },
	"environment":    func(a Attrs) any { return a.First(otelident.EnvironmentKeys) },
	"release":        func(a Attrs) any { return a.First(otelident.ReleaseKeys) },
	"tags":           func(a Attrs) any { return otelident.ParseTags(a.First(otelident.TagKeys)) },
	"metadata": func(a Attrs) any {
		out := map[string]string{}
		for k, v := range a {
			if name, ok := otelident.MetadataKeyFor(k); ok {
				out[name] = MetadataValueText(k, v)
			}
		}
		return out
	},
}

// jsonOrText decodes s when it is a JSON array or object (so a structured
// want compares semantically), else keeps the text.
func jsonOrText(s string) any {
	trim := strings.TrimSpace(s)
	if strings.HasPrefix(trim, "[") || strings.HasPrefix(trim, "{") {
		var v any
		if err := json.Unmarshal([]byte(trim), &v); err == nil {
			return v
		}
	}
	return s
}

// normalize round-trips v through JSON so a Go value and a fixture value
// compare by content.
func normalize(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestDialectConformance drives every fixture under testdata/conformance
// (one per dialect: GenAI current, GenAI legacy, OpenInference, Traceloop)
// through Read and checks each named canonical field (plan W1a-4). A want
// that names no getter fails, so a fixture can never assert silently.
func TestDialectConformance(t *testing.T) {
	files, err := filepath.Glob("testdata/conformance/*.json")
	if err != nil || len(files) < 4 {
		t.Fatalf("conformance fixtures = %v (%v), want one per dialect", files, err)
	}
	dialects := map[string]bool{}
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var cf conformanceFile
		if err := json.Unmarshal(b, &cf); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if cf.Source.Dialect == "" || cf.Source.Grounding == "" || len(cf.Cases) == 0 {
			t.Fatalf("%s: missing _source.dialect / grounding or cases", file)
		}
		dialects[cf.Source.Dialect] = true
		for _, c := range cf.Cases {
			t.Run(filepath.Base(file)+"/"+c.Name, func(t *testing.T) {
				a := Attrs{}
				for k, raw := range c.Attrs {
					a[k] = toAnyValue(t, raw)
				}
				got := Read(a)
				for name, raw := range c.Want {
					var val any
					if get, ok := fieldGetters[name]; ok {
						val = get(got)
					} else if aget, ok := attrGetters[name]; ok {
						val = aget(a)
					} else {
						t.Fatalf("want %q names no canonical field", name)
					}
					var want any
					if err := json.Unmarshal(raw, &want); err != nil {
						t.Fatal(err)
					}
					if g := normalize(t, val); !reflect.DeepEqual(g, want) {
						t.Errorf("%s = %v, want %v", name, g, want)
					}
				}
			})
		}
	}
	for _, d := range []Dialect{DialectGenAI, DialectGenAILegacy, DialectOpenInference, DialectTraceloop, DialectLangfuse} {
		if !dialects[string(d)] {
			t.Errorf("no conformance fixture for dialect %q", d)
		}
	}
}

// loadCapture reads a real OTLP/HTTP capture from testdata/connectors.
func loadCapture(t *testing.T, name string) *coltracepb.ExportTraceServiceRequest {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "connectors", name))
	if err != nil {
		t.Fatal(err)
	}
	req := &coltracepb.ExportTraceServiceRequest{}
	if err := proto.Unmarshal(b, req); err != nil {
		t.Fatal(err)
	}
	return req
}

// TestRealCaptureOpenInference reads the live LangChain/LangGraph capture
// (openinference-instrumentation-langchain 0.1.70, provenance in
// testdata/connectors/langchain/README.md) through Read: the reported total
// is kept (not derived), reasoning stays a subset of output, the finish
// reason and the indexed tool call resolve, and every AGENT / CHAIN / TOOL
// span keeps its input and output (finding F19).
func TestRealCaptureOpenInference(t *testing.T) {
	req := loadCapture(t, "langchain/otlp-export-002.bin")
	seen := map[string]bool{}
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			for _, sp := range ss.GetSpans() {
				a := Index(sp.GetAttributes())
				f := Read(a)
				kind := a.Str("openinference.span.kind")
				seen[kind] = true
				switch kind {
				case "LLM":
					if f.Usage.Input != nil && *f.Usage.Input != 286 {
						continue // the capture's second, final-answer LLM call
					}
					seen["LLM-toolcall"] = true
					u := f.Usage
					if u.Total == nil || *u.Total != 449 || u.TotalDerived {
						t.Errorf("llm total = %v derived=%v, want reported 449", u.Total, u.TotalDerived)
					}
					if u.Input == nil || *u.Input != 286 || u.Output == nil || *u.Output != 163 {
						t.Errorf("llm in/out = %v/%v", u.Input, u.Output)
					}
					if u.Reasoning == nil || *u.Reasoning > *u.Output {
						t.Errorf("reasoning %v must be a subset of output %v", u.Reasoning, u.Output)
					}
					if !reflect.DeepEqual(f.FinishReasons, []string{"tool_calls"}) {
						t.Errorf("finish reasons = %v", f.FinishReasons)
					}
					if !strings.Contains(f.OutputMessages, `"name":"get_word_length"`) {
						t.Errorf("output messages lost the tool call: %s", f.OutputMessages)
					}
					if strings.Contains(f.RequestParams, "messages") {
						t.Errorf("request params leaked content: %s", f.RequestParams)
					}
				case "AGENT", "CHAIN":
					if f.InputValue == "" || f.OutputValue == "" {
						t.Errorf("%s span %q lost input/output", kind, sp.GetName())
					}
				case "TOOL":
					if f.ToolName != "get_word_length" || f.ToolArguments != "superbased" || f.ToolResult == "" {
						t.Errorf("tool span = %q %q %q", f.ToolName, f.ToolArguments, f.ToolResult)
					}
				}
			}
		}
	}
	for _, k := range []string{"LLM", "LLM-toolcall", "AGENT", "CHAIN", "TOOL"} {
		if !seen[k] {
			t.Errorf("capture has no %s span", k)
		}
	}
}
