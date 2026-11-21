package genaiattr

import (
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
)

func sv(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

func iv(n int64) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: n}}
}

func arr(vs ...*commonpb.AnyValue) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: vs}}}
}

func kvl(kvs ...*commonpb.KeyValue) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: kvs}}}
}

// TestText renders every value type; arrays and kvlists never flatten to
// empty (F19/F20) and render canonically (sorted kvlist keys).
func TestText(t *testing.T) {
	cases := []struct {
		name string
		v    *commonpb.AnyValue
		want string
	}{
		{"nil", nil, ""},
		{"string", sv("a"), "a"},
		{"int", iv(7), "7"},
		{"double", &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: 0.5}}, "0.5"},
		{"bool", &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: true}}, "true"},
		{"bytes", &commonpb.AnyValue{Value: &commonpb.AnyValue_BytesValue{BytesValue: []byte("hi")}}, "aGk="},
		{"array", arr(sv("stop"), iv(1)), `["stop",1]`},
		{"kvlist", kvl(&commonpb.KeyValue{Key: "b", Value: iv(2)}, &commonpb.KeyValue{Key: "a", Value: sv("x")}), `{"a":"x","b":2}`},
		{"empty_array", arr(), `[]`},
	}
	for _, c := range cases {
		if got := Text(c.v); got != c.want {
			t.Errorf("%s: Text = %q, want %q", c.name, got, c.want)
		}
	}
}

// TestTextDepthBounded: a pathologically deep value renders without
// recursing past the bound.
func TestTextDepthBounded(t *testing.T) {
	v := sv("leaf")
	for i := 0; i < maxValueDepth+10; i++ {
		v = arr(v)
	}
	if Text(v) == "" {
		t.Fatal("deep value rendered empty")
	}
}

// TestStrings reads arrays, scalars and JSON-array strings.
func TestStrings(t *testing.T) {
	if got := Strings(arr(sv("stop"), sv(""), sv("length"))); len(got) != 2 || got[1] != "length" {
		t.Errorf("array = %v", got)
	}
	if got := Strings(sv(`["a","b"]`)); len(got) != 2 {
		t.Errorf("json string = %v", got)
	}
	if got := Strings(sv("stop")); len(got) != 1 || got[0] != "stop" {
		t.Errorf("scalar = %v", got)
	}
}

// TestIntFloat parses ints, doubles and decimal strings; absence is nil.
func TestIntFloat(t *testing.T) {
	a := Attrs{"i": iv(3), "s": sv(" 4 "), "bad": sv("x")}
	if n := a.Int([]string{"bad", "s"}); n == nil || *n != 4 {
		t.Errorf("Int = %v", n)
	}
	if n := a.Int([]string{"missing"}); n != nil {
		t.Errorf("absent Int = %v", *n)
	}
	if f := a.Float([]string{"i"}); f == nil || *f != 3 {
		t.Errorf("Float = %v", f)
	}
}
