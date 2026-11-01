package otlpvendor

import (
	"testing"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

// checkGenTimings asserts a result's generation timings exactly: want maps
// each expected per-call key to its duration (nil = none), all in session.
func checkGenTimings(t *testing.T, res Result, want map[string]int64, session string) {
	t.Helper()
	if len(res.GenTimings) != len(want) {
		t.Fatalf("gen timings = %+v, want %v", res.GenTimings, want)
	}
	for _, gt := range res.GenTimings {
		ms, ok := want[gt.KeyValue]
		if !ok || gt.DurationMS != ms || gt.SessionID != session || gt.Key != TimingKeyMessageID || gt.Timestamp.IsZero() {
			t.Errorf("gen timing %+v, want key in %v (session %s, message_id)", gt, want, session)
		}
	}
}

// TestGenTimingFromSpan is one case per rule of the KindGenTiming span
// mapping (the CodeBuddy row's model_stream rule): the duration is rebuilt
// from the first-token event and its TTFT to the span end, and a record
// missing any piece of the join or the rebuild yields nothing (never the
// stream-only span).
func TestGenTimingFromSpan(t *testing.T) {
	const (
		start = uint64(1_000_000_000)
		ms    = uint64(1_000_000)
	)
	stream := func(attrs []*commonpb.KeyValue, events ...*tracepb.Span_Event) *tracepb.Span {
		return &tracepb.Span{
			Name: "codebuddy_code.model_stream", SpanId: []byte{9, 1, 2, 3, 4, 5, 6, 7}, TraceId: make([]byte, 16),
			StartTimeUnixNano: start, EndTimeUnixNano: start + 30*ms, Attributes: attrs, Events: events,
		}
	}
	firstToken := func(at uint64, attrs []*commonpb.KeyValue) *tracepb.Span_Event {
		return &tracepb.Span_Event{Name: "first_token_received", TimeUnixNano: at, Attributes: attrs}
	}
	full := kvs("gen_ai.session.id", s("sess-1"), "request.id", s("msg-1"))
	cases := []struct {
		name string
		span *tracepb.Span
		want map[string]int64
	}{
		{"event ttft rebuilds the request start", stream(full, firstToken(start+10*ms, kvs("ttft_ms", i(40)))), map[string]int64{"msg-1": 60}},
		{"ttft on the span when the event has none", stream(kvs("gen_ai.session.id", s("sess-1"), "request.id", s("msg-1"), "first_token_ms", i(25)), firstToken(start+10*ms, nil)), map[string]int64{"msg-1": 45}},
		{"session from the resource-style codebuddy.session_id", stream(kvs("codebuddy.session_id", s("sess-1"), "request.id", s("msg-1")), firstToken(start+20*ms, kvs("ttft_ms", i(5)))), map[string]int64{"msg-1": 15}},
		{"no first-token event: no timing, not the stream span", stream(full), nil},
		{"zero ttft: no timing", stream(full, firstToken(start+10*ms, kvs("ttft_ms", i(0)))), nil},
		{"event after the span end: no timing", stream(full, firstToken(start+31*ms, kvs("ttft_ms", i(40)))), nil},
		{"no session: no timing (default semconv)", stream(kvs("request.id", s("msg-1")), firstToken(start+10*ms, kvs("ttft_ms", i(40)))), nil},
		{"no per-call key: no timing", stream(kvs("gen_ai.session.id", s("sess-1")), firstToken(start+10*ms, kvs("ttft_ms", i(40)))), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ParseSpans(spansExport("CodeBuddy-CLI-9.9.9", tc.span))
			checkGenTimings(t, res, tc.want, "sess-1")
			if len(res.Turns) != 0 {
				t.Errorf("a span without usage became a turn: %+v", res.Turns)
			}
		})
	}
}

// TestTimingRowsDeclareJoin pins the capability column against the rules: a
// row with a KindGenTiming rule declares which transcript column its key
// equals (and the column is in the closed set), the rule names the session
// and the key, and a row declaring a join has a rule that can produce it.
func TestTimingRowsDeclareJoin(t *testing.T) {
	known := map[TimingKey]bool{}
	for _, k := range TimingKeys() {
		known[k] = true
	}
	for _, v := range Vendors() {
		rules := 0
		for _, r := range v.Rules {
			if r.Kind != KindGenTiming {
				continue
			}
			rules++
			if len(r.F.Session) == 0 || len(r.F.Request) == 0 {
				t.Errorf("%s: a timing rule must name the session and the per-call key", v.Tool)
			}
			if r.Signal == SignalLogs && len(r.F.Duration) == 0 {
				t.Errorf("%s: a log timing rule needs a duration attribute", v.Tool)
			}
		}
		switch {
		case rules > 0 && v.TranscriptTiming == "":
			t.Errorf("%s: timing rule without a declared transcript join", v.Tool)
		case rules == 0 && v.TranscriptTiming != "":
			t.Errorf("%s: declares a transcript timing join but has no timing rule", v.Tool)
		case v.TranscriptTiming != "" && !known[v.TranscriptTiming]:
			t.Errorf("%s: transcript timing key %q is not in TimingKeys", v.Tool, v.TranscriptTiming)
		}
		if v.TranscriptTiming != "" && v.Grain != GrainUser {
			t.Errorf("%s: a team-grain export never reaches a node's transcript rows", v.Tool)
		}
	}
}
