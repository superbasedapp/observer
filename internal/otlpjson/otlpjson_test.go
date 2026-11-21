package otlpjson

import (
	"bytes"
	"errors"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func TestEncodingTable(t *testing.T) {
	cases := []struct {
		ct   string
		want Kind
		err  bool
	}{
		{"", Protobuf, false},
		{"application/x-protobuf", Protobuf, false},
		{"application/protobuf", Protobuf, false},
		{"application/json", JSON, false},
		{"Application/JSON; charset=utf-8", JSON, false},
		{"text/plain", Protobuf, true},
		{"application/x-www-form-urlencoded", Protobuf, true},
		{";;;", Protobuf, true},
	}
	for _, c := range cases {
		got, err := Encoding(c.ct)
		if c.err != (err != nil) || (!c.err && got != c.want) {
			t.Errorf("Encoding(%q) = %v, %v; want %v, err=%v", c.ct, got, err, c.want, c.err)
		}
		if c.err && !errors.Is(err, ErrUnsupportedMediaType) {
			t.Errorf("Encoding(%q) error %v is not ErrUnsupportedMediaType", c.ct, err)
		}
	}
}

func TestUnmarshalJSONHexIDs(t *testing.T) {
	body := []byte(`{"resourceSpans":[{"scopeSpans":[{"spans":[{
		"traceId":"5b8efff798038103d269b633813fc60c","spanId":"eee19b7ec3c1b174",
		"parentSpanId":"eee19b7ec3c1b173","name":"chat","unknownField":1}]}]}]}`)
	var req coltracepb.ExportTraceServiceRequest
	if err := Decode(JSON, body, &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	sp := req.GetResourceSpans()[0].GetScopeSpans()[0].GetSpans()[0]
	if !bytes.Equal(sp.GetTraceId(), []byte{0x5b, 0x8e, 0xff, 0xf7, 0x98, 0x03, 0x81, 0x03, 0xd2, 0x69, 0xb6, 0x33, 0x81, 0x3f, 0xc6, 0x0c}) {
		t.Errorf("trace id = %x", sp.GetTraceId())
	}
	if sp.GetName() != "chat" || len(sp.GetParentSpanId()) != 8 {
		t.Errorf("span = %v", sp)
	}
	if err := Decode(JSON, []byte(`{not json`), &req); err == nil {
		t.Error("bad JSON decoded")
	}
}

func TestRoundTripBothEncodings(t *testing.T) {
	in := &coltracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{TraceId: []byte{1, 2}, SpanId: []byte{3}, Name: "x"}}}},
	}}}
	for _, k := range []Kind{Protobuf, JSON} {
		raw, ct, err := Encode(k, in)
		if err != nil {
			t.Fatalf("encode %v: %v", k, err)
		}
		if (k == JSON) != (ct == ContentTypeJSON) {
			t.Errorf("kind %v content type %q", k, ct)
		}
		if k == Protobuf {
			var out coltracepb.ExportTraceServiceRequest
			if err := Decode(k, raw, &out); err != nil || !proto.Equal(in, &out) {
				t.Errorf("protobuf round trip: %v", err)
			}
		}
	}
}

// TestUnmarshalJSONKeepsLargeIntegers pins review finding E-57: an int64
// above 2^53 written as a bare JSON number (a nanosecond timestamp, an
// intValue) decodes exactly, not rounded through float64.
func TestUnmarshalJSONKeepsLargeIntegers(t *testing.T) {
	body := `{"resourceSpans":[{"scopeSpans":[{"spans":[{
		"traceId":"0102030405060708090a0b0c0d0e0f10","spanId":"0102030405060708",
		"startTimeUnixNano":1800000000123456789,"endTimeUnixNano":1800000000123456791,
		"attributes":[{"key":"n","value":{"intValue":9007199254740993}}]}]}]}]}`
	var req coltracepb.ExportTraceServiceRequest
	if err := UnmarshalJSON([]byte(body), &req); err != nil {
		t.Fatal(err)
	}
	sp := req.GetResourceSpans()[0].GetScopeSpans()[0].GetSpans()[0]
	if sp.GetStartTimeUnixNano() != 1800000000123456789 || sp.GetEndTimeUnixNano() != 1800000000123456791 {
		t.Errorf("times = %d / %d, want exact", sp.GetStartTimeUnixNano(), sp.GetEndTimeUnixNano())
	}
	if got := sp.GetAttributes()[0].GetValue().GetIntValue(); got != 9007199254740993 {
		t.Errorf("intValue = %d, want 9007199254740993", got)
	}
	if err := UnmarshalJSON([]byte(`{} {}`), &req); err == nil {
		t.Error("trailing data accepted")
	}
}
