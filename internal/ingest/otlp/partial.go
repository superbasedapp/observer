package otlp

import (
	"fmt"
	"strings"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// PartialTraces is the error a TraceHandler returns when it kept part of an
// export and refused the rest for a reason a resend cannot fix, for example
// spans for a subsystem that is off or not in this build (review E-29). The
// receiver answers success with an OTLP partial success naming the rejected
// span count and the message, so the exporter does not resend and its user
// can see the spans were not kept, instead of a plain 200 that hides the loss.
//
// It may be returned alone, or joined (errors.Join) only with other
// *PartialTraces, whose counts and messages are then added up. Joined with
// any other error, that error decides the answer (review FR-M17): a retry
// later is a resend, anything else a failed export, never a partial success
// that hides it.
type PartialTraces struct {
	// RejectedSpans is the number of spans of the export not kept.
	RejectedSpans int64
	// Message says why, in plain words, for the exporter's user.
	Message string
}

// Error implements error.
func (p *PartialTraces) Error() string {
	return fmt.Sprintf("ingest/otlp: %d span(s) rejected: %s", p.RejectedSpans, p.Message)
}

// traceResponse is the export response for a handler's result: empty on
// success, a partial success when the error is made of *PartialTraces only,
// ok=false for anything else (the caller maps that error by its class).
func traceResponse(err error) (*coltracepb.ExportTraceServiceResponse, bool) {
	if err == nil {
		return &coltracepb.ExportTraceServiceResponse{}, true
	}
	parts, only := partialsOnly(err)
	if !only || len(parts) == 0 {
		return nil, false
	}
	ps := &coltracepb.ExportTracePartialSuccess{}
	var msgs []string
	for _, p := range parts {
		ps.RejectedSpans += p.RejectedSpans
		if m := strings.TrimSpace(p.Message); m != "" {
			msgs = append(msgs, m)
		}
	}
	ps.ErrorMessage = strings.Join(msgs, "; ")
	return &coltracepb.ExportTraceServiceResponse{PartialSuccess: ps}, true
}

// partialsOnly walks err's tree: only is true when every error in it is a
// *PartialTraces (alone, joined, or wrapped with words), and parts lists
// them. Any other error in the tree (a retry later, over capacity, a write
// that failed) makes only false.
func partialsOnly(err error) (parts []*PartialTraces, only bool) {
	switch e := err.(type) { //nolint:errorlint // walks the wrap tree itself, one level at a time
	case nil:
		return nil, true
	case *PartialTraces:
		if e == nil {
			return nil, false
		}
		return []*PartialTraces{e}, true
	case interface{ Unwrap() []error }:
		for _, x := range e.Unwrap() {
			sub, ok := partialsOnly(x)
			if !ok {
				return nil, false
			}
			parts = append(parts, sub...)
		}
		return parts, true
	case interface{ Unwrap() error }:
		// A wrapper around one error adds words, not another error.
		inner := e.Unwrap()
		if inner == nil {
			return nil, false
		}
		return partialsOnly(inner)
	}
	return nil, false
}
