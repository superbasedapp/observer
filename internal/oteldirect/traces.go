package oteldirect

import (
	"fmt"
	"sort"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// TraceCount is what the OTel-direct receiver learns from a traces export
// without mapping it (traces are not mapped in phase 1): how many spans it
// holds and how many of them came from a resource no tool row claims.
//
// A span whose resource service.name selects a tool row (Claude Code today)
// is a coding-tool span: accepted and dropped, as phase 1 documents. Any
// other span is FOREIGN: an LLM app's Plane A trace sent to the coding-tool
// endpoint by mistake. The receiver rejects it loudly (partial_success, or a
// refusal when the whole export is foreign) and names the Plane A gateway, so
// it is never a silent drop (F09).
type TraceCount struct {
	// Spans is every span in the export.
	Spans int
	// Foreign is the spans whose resource no tool row claims.
	Foreign int
	// ForeignServices are the distinct service.name values of the foreign
	// resources, sorted, at most MaxForeignServices ("" for a resource
	// without one).
	ForeignServices []string
}

// MaxForeignServices caps TraceCount.ForeignServices so a hostile export
// cannot grow the error message.
const MaxForeignServices = 5

// serviceNameKeys is the resource attribute that selects a tool row.
var serviceNameKeys = []string{"service.name"}

// ClassifyTraceSpans decodes an OTLP/HTTP traces export body (same rules as
// DecodeLogs) and counts its spans, split by whether a tool row claims their
// resource. Errors wrap ErrTooLarge, ErrMalformed, ErrUnsupportedMediaType or
// ErrUnsupportedEncoding.
func ClassifyTraceSpans(raw []byte, contentType, contentEncoding string, maxInflated int64) (TraceCount, error) {
	req := &coltracepb.ExportTraceServiceRequest{}
	if err := decode(raw, contentType, contentEncoding, maxInflated, req); err != nil {
		return TraceCount{}, fmt.Errorf("oteldirect.ClassifyTraceSpans: %w", err)
	}
	var out TraceCount
	seen := map[string]bool{}
	for _, rs := range req.GetResourceSpans() {
		n := 0
		for _, ss := range rs.GetScopeSpans() {
			n += len(ss.GetSpans())
		}
		out.Spans += n
		service := indexAttrs(rs.GetResource().GetAttributes()).str(serviceNameKeys)
		if _, ok := ToolForService(service); ok || n == 0 {
			continue
		}
		out.Foreign += n
		if !seen[service] {
			seen[service] = true
			out.ForeignServices = append(out.ForeignServices, service)
		}
	}
	sort.Strings(out.ForeignServices)
	if len(out.ForeignServices) > MaxForeignServices {
		out.ForeignServices = out.ForeignServices[:MaxForeignServices]
	}
	return out, nil
}

// EncodeTracesResponse builds the ExportTraceServiceResponse for a traces
// export, the EncodeLogsResponse rules with rejected_spans.
func EncodeTracesResponse(requestContentType string, rejected int64, msg string) (body []byte, contentType string, err error) {
	resp := &coltracepb.ExportTraceServiceResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &coltracepb.ExportTracePartialSuccess{RejectedSpans: rejected, ErrorMessage: msg}
	}
	return encodeResponse(requestContentType, resp)
}
