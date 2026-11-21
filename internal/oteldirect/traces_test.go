package oteldirect

import (
	"errors"
	"reflect"
	"testing"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func traceExport(services map[string]int) *coltracepb.ExportTraceServiceRequest {
	req := &coltracepb.ExportTraceServiceRequest{}
	for svc, n := range services {
		res := &resourcepb.Resource{}
		if svc != "" {
			res.Attributes = []*commonpb.KeyValue{{Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: svc}}}}
		}
		ss := &tracepb.ScopeSpans{}
		for i := 0; i < n; i++ {
			ss.Spans = append(ss.Spans, &tracepb.Span{Name: "s", TraceId: make([]byte, 16), SpanId: make([]byte, 8)})
		}
		req.ResourceSpans = append(req.ResourceSpans, &tracepb.ResourceSpans{Resource: res, ScopeSpans: []*tracepb.ScopeSpans{ss}})
	}
	return req
}

// TestClassifyTraceSpans pins the F09 split: Claude Code's own spans are
// coding-tool spans; an LLM app's (any other service, or none) are foreign.
func TestClassifyTraceSpans(t *testing.T) {
	tests := []struct {
		name     string
		services map[string]int
		want     TraceCount
	}{
		{"claude code only", map[string]int{"claude-code": 3}, TraceCount{Spans: 3}},
		{"plane A app only", map[string]int{"support-bot": 2}, TraceCount{Spans: 2, Foreign: 2, ForeignServices: []string{"support-bot"}}},
		{"mixed", map[string]int{"claude-code": 1, "rag-api": 4, "": 1}, TraceCount{Spans: 6, Foreign: 5, ForeignServices: []string{"", "rag-api"}}},
		{"empty resource is not foreign", map[string]int{"support-bot": 0}, TraceCount{}},
		{"services capped", map[string]int{"a": 1, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1}, TraceCount{Spans: 6, Foreign: 6, ForeignServices: []string{"a", "b", "c", "d", "e"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := proto.Marshal(traceExport(tc.services))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ClassifyTraceSpans(raw, ContentTypeProtobuf, "", 0)
			if err != nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ClassifyTraceSpans = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
	js, err := protojson.Marshal(traceExport(map[string]int{"support-bot": 1}))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ClassifyTraceSpans(js, ContentTypeJSON, "", 0); err != nil || got.Foreign != 1 {
		t.Fatalf("JSON export = %+v, %v", got, err)
	}
	if _, err := ClassifyTraceSpans([]byte("not otlp"), ContentTypeProtobuf, "", 0); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed err = %v", err)
	}
}

// TestEncodeTracesResponse pins partial_success: set only on a rejection,
// in the request's encoding.
func TestEncodeTracesResponse(t *testing.T) {
	body, ct, err := EncodeTracesResponse(ContentTypeProtobuf, 2, "use the gateway")
	if err != nil || ct != ContentTypeProtobuf {
		t.Fatalf("encode: %v %s", err, ct)
	}
	var resp coltracepb.ExportTraceServiceResponse
	if err := proto.Unmarshal(body, &resp); err != nil || resp.GetPartialSuccess().GetRejectedSpans() != 2 || resp.GetPartialSuccess().GetErrorMessage() != "use the gateway" {
		t.Fatalf("decoded = %+v, %v", &resp, err)
	}
	body, ct, err = EncodeTracesResponse(ContentTypeJSON, 0, "")
	if err != nil || ct != ContentTypeJSON || string(body) != "{}" {
		t.Fatalf("empty JSON = %q %s %v", body, ct, err)
	}
}
