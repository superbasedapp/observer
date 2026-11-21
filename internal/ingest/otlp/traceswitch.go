package otlp

import (
	"context"
	"sync/atomic"

	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
)

// TraceSwitch is a trace handler whose target can be set while the
// receiver serves (first-run plan 3.8, hot-enable): a receiver built with
// Handle keeps its listener and its registered /v1/traces route, and
// turning AI Apps on in a running daemon only installs the target.
//
// While no target is set it answers every export with a PartialTraces that
// names offMessage, the same answer a receiver gives today when the plane
// that would keep the spans is off, so the exporter's user sees why.
//
// Safe for concurrent use: Set is one atomic store, Handle one load.
type TraceSwitch struct {
	target     atomic.Pointer[TraceHandler]
	offMessage string
}

// NewTraceSwitch returns a switch with no target.
func NewTraceSwitch(offMessage string) *TraceSwitch {
	if offMessage == "" {
		offMessage = "app observability is off on this machine"
	}
	return &TraceSwitch{offMessage: offMessage}
}

// Set installs h; nil turns the switch off again.
func (s *TraceSwitch) Set(h TraceHandler) {
	if h == nil {
		s.target.Store(nil)
		return
	}
	s.target.Store(&h)
}

// On reports whether a target is installed.
func (s *TraceSwitch) On() bool { return s.target.Load() != nil }

// Handle is the TraceHandler to give the receiver.
func (s *TraceSwitch) Handle(ctx context.Context, req *coltracepb.ExportTraceServiceRequest) error {
	if h := s.target.Load(); h != nil {
		return (*h)(ctx, req)
	}
	var n int64
	for _, rs := range req.GetResourceSpans() {
		for _, ss := range rs.GetScopeSpans() {
			n += int64(len(ss.GetSpans()))
		}
	}
	if n == 0 {
		return nil
	}
	return &PartialTraces{RejectedSpans: n, Message: s.offMessage}
}
