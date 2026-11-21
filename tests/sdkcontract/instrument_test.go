package sdkcontract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	"github.com/marmutapp/superbased-observer/internal/genaiattr"
)

// instrumentFixture is one sdk/contract/fixtures/instrument/<target>.json: the
// spans an upstream instrumentor emitted in the SDK's offline scenario (recorded
// by sdk/python/tests/test_instrument.py), each with the normalized fields
// ("want") the Go vocabulary must read from its attributes.
type instrumentFixture struct {
	Source struct {
		Target       string `json:"target"`
		Instrumentor string `json:"instrumentor"`
		Grounding    string `json:"grounding"`
	} `json:"_source"`
	Target string `json:"target"`
	Spans  []struct {
		Name   string                     `json:"name"`
		Parent *string                    `json:"parent"`
		Attrs  map[string]json.RawMessage `json:"attrs"`
		Want   map[string]json.RawMessage `json:"want"`
	} `json:"spans"`
}

// wantGetters is the closed table of fixture "want" names (genaiattr field
// names): each returns one normalized value in a JSON-comparable form.
var wantGetters = map[string]func(genaiattr.Attrs, genaiattr.Fields) any{
	"span_kind": func(a genaiattr.Attrs, _ genaiattr.Fields) any {
		return a.First(genaiattr.Keys(genaiattr.FieldSpanKindOI))
	},
	"model":              func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Model },
	"request_model":      func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.RequestModel },
	"provider":           func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Provider },
	"operation":          func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Operation },
	"input_tokens":       func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Usage.Input },
	"output_tokens":      func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Usage.Output },
	"total_tokens":       func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Usage.Total },
	"total_derived":      func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Usage.TotalDerived },
	"cache_read_tokens":  func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Usage.CacheRead },
	"cache_write_tokens": func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Usage.CacheWrite },
	"reasoning_tokens":   func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.Usage.Reasoning },
	"response_id":        func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.ResponseID },
	"tool_name":          func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.ToolName },
	"tool_arguments":     func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.ToolArguments) },
	"tool_result":        func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.ToolResult) },
	"input_messages":     func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.InputMessages) },
	"output_messages":    func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.OutputMessages) },
	"input_value":        func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.InputValue) },
	"output_value":       func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.OutputValue) },
	"finish_reasons":     func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.FinishReasons },
	"request_params":     func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.RequestParams) },
	"error_type":         func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.ErrorType },
	// Added for the Wave 5 frameworks (agents and tool calls).
	"response_model":      func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.ResponseModel },
	"request_id":          func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.RequestID },
	"tool_call_id":        func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.ToolCallID },
	"agent_name":          func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.AgentName },
	"agent_id":            func(_ genaiattr.Attrs, f genaiattr.Fields) any { return f.AgentID },
	"system_instructions": func(_ genaiattr.Attrs, f genaiattr.Fields) any { return jsonOrText(f.SystemInstructions) },
}

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

func roundTrip(t *testing.T, v any) any {
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

// anyValue builds an OTLP value from a recorded attribute: a string, an
// integer (no fraction or exponent), a double, a bool or an array (the only
// shapes an OTel SDK attribute can take).
func anyValue(t *testing.T, raw json.RawMessage) *commonpb.AnyValue {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode attr %s: %v", raw, err)
	}
	return fromGo(t, v)
}

func fromGo(t *testing.T, v any) *commonpb.AnyValue {
	t.Helper()
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
			arr.Values = append(arr.Values, fromGo(t, e))
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: arr}}
	}
	t.Fatalf("unsupported recorded attribute value %T", v)
	return nil
}

// pythonTargets is every instrument() target of the Python SDK
// (sdk/python/superbased_sdk/_instrument.py TARGETS); each must have its
// <target>.json fixture. A TS lane adds <target>-ts.json files, which are
// checked but not required here.
var pythonTargets = []string{
	"openai", "anthropic", "langchain", "mcp",
	"gemini", "bedrock", "llama-index", "crewai", "pydantic-ai", "openai-agents",
}

// TestInstrumentFixturesNormalize: every span an instrumentor emitted in the
// SDK scenario normalizes, through internal/genaiattr, to the fields the
// fixture states (plan W2-3: a conformance fixture per instrumentation).
func TestInstrumentFixturesNormalize(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "sdk", "contract", "fixtures", "instrument", "*.json"))
	if err != nil || len(files) < len(pythonTargets) {
		t.Fatalf("instrument fixtures = %v (%v), want one per Python target %v", files, err, pythonTargets)
	}
	targets := map[string]bool{}
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		var fx instrumentFixture
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if fx.Target == "" || fx.Source.Instrumentor == "" || fx.Source.Grounding == "" || len(fx.Spans) == 0 {
			t.Fatalf("%s: missing target, _source.instrumentor / grounding or spans", file)
		}
		targets[fx.Target] = true
		asserted := 0
		names := map[string]bool{}
		for _, sp := range fx.Spans {
			names[sp.Name] = true
		}
		for _, sp := range fx.Spans {
			if sp.Parent != nil && !names[*sp.Parent] {
				t.Errorf("%s/%s: parent %q is not a span of the fixture", fx.Target, sp.Name, *sp.Parent)
			}
			t.Run(fx.Target+"/"+sp.Name, func(t *testing.T) {
				a := genaiattr.Attrs{}
				for k, v := range sp.Attrs {
					a[k] = anyValue(t, v)
				}
				got := genaiattr.Read(a)
				keys := make([]string, 0, len(sp.Want))
				for k := range sp.Want {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, name := range keys {
					get, ok := wantGetters[name]
					if !ok {
						t.Fatalf("want %q names no normalized field", name)
					}
					var want any
					if err := json.Unmarshal(sp.Want[name], &want); err != nil {
						t.Fatal(err)
					}
					if g := roundTrip(t, get(a, got)); !reflect.DeepEqual(g, want) {
						gb, _ := json.Marshal(g)
						t.Errorf("%s = %s, want %s", name, gb, sp.Want[name])
					}
				}
			})
			asserted += len(sp.Want)
		}
		if asserted == 0 {
			t.Errorf("%s: no span states a normalized field", fx.Target)
		}
	}
	for _, want := range pythonTargets {
		if !targets[want] {
			t.Errorf("no instrument fixture for %s", want)
		}
	}
}
