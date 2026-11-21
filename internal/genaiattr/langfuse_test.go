package genaiattr

import (
	"reflect"
	"sort"
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

func strVal(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

// TestObservationTypesPinned: the closed observation-type vocabulary is the
// SDKs' (langfuse 5.2.0 constants.py, @langfuse/tracing 6.1.1), and only
// span and event name no kind class.
func TestObservationTypesPinned(t *testing.T) {
	var got []string
	for k := range ObservationTypes {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"agent", "chain", "embedding", "evaluator", "event", "generation", "guardrail", "retriever", "span", "tool"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ObservationTypes = %v, want %v", got, want)
	}
	for typ, kind := range ObservationTypes {
		if (kind == "") != (typ == "span" || typ == "event") {
			t.Errorf("%s -> %q", typ, kind)
		}
	}
	if k := ObservationKind(Attrs{LangfuseObservationType: strVal(" Generation ")}); k != "llm" {
		t.Errorf("ObservationKind normalises case/space: %q", k)
	}
	if k := ObservationKind(Attrs{LangfuseObservationType: strVal("bogus")}); k != "" {
		t.Errorf("unknown type -> %q, want empty", k)
	}
}

// TestMetadataValueText: a JSON string literal under langfuse.trace.metadata.
// decodes (Python 5.x / JS 6.x encode every value); numbers, objects and other
// prefixes stay as rendered.
func TestMetadataValueText(t *testing.T) {
	for _, tc := range []struct {
		key, in, want string
	}{
		{"langfuse.trace.metadata.plan", `"pro"`, "pro"},
		{"langfuse.trace.metadata.q", `"say \"hi\""`, `say "hi"`},
		{"langfuse.trace.metadata.n", `12`, "12"},
		{"langfuse.trace.metadata.o", `{"a":1}`, `{"a":1}`},
		{"langfuse.trace.metadata.bad", `"unterminated`, `"unterminated`},
		{"langfuse.trace.metadata.plain", `pro`, "pro"},
		{"sbo.metadata.plan", `"pro"`, `"pro"`},
	} {
		if got := MetadataValueText(tc.key, strVal(tc.in)); got != tc.want {
			t.Errorf("MetadataValueText(%s, %s) = %q, want %q", tc.key, tc.in, got, tc.want)
		}
	}
}

// TestUsageDetailsBounds: an oversized or non-object blob, negative or
// fractional counts and nested members never become a count.
func TestUsageDetailsBounds(t *testing.T) {
	big := `{"input": 1, "pad": "` + string(make([]byte, maxDetailsBytes)) + `"}`
	if u := usageFromDetails(big); !u.empty() {
		t.Errorf("oversized blob decoded: %+v", u)
	}
	u := usageFromDetails(`{"input": -3, "output": 2.5, "input_audio": 4, "total": 7.0}`)
	if u.Input == nil || *u.Input != 4 || u.Output != nil || u.Total == nil || *u.Total != 7 {
		t.Errorf("usage = in %v out %v total %v", u.Input, u.Output, u.Total)
	}
	if u := usageFromDetails(`{"foo": 1}`); !u.empty() {
		t.Errorf("unknown shape decoded: %+v", u)
	}
}

// TestParamBlobPrecedence: a GenAI request param beats every blob, an
// earlier blob beats Langfuse's model parameters, content members never
// merge.
func TestParamBlobPrecedence(t *testing.T) {
	a := Attrs{
		"gen_ai.request.temperature": {Value: &commonpb.AnyValue_DoubleValue{DoubleValue: 0.1}},
		InvocationParamsKey:          strVal(`{"top_p": 0.9, "messages": []}`),
		LangfuseModelParameters:      strVal(`{"top_p": 0.5, "temperature": 0.7, "max_tokens": "64", "tools": "x"}`),
	}
	want := `{"max_tokens":"64","temperature":0.1,"top_p":0.9}`
	if got := RequestParams(a); got != want {
		t.Errorf("RequestParams = %s, want %s", got, want)
	}
}
