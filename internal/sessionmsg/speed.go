package sessionmsg

import "time"

// Speed is a message row's output-throughput accumulator: the ONE place the
// node's Messages tab, the node cockpit, the server-side sort and the org's
// message-metrics drawer get a tokens-per-second figure from (S10-SPEED,
// 2026-09-23 - it replaced a node-only three-tier heuristic whose "elapsed"
// tier divided a message's output by the gap to the NEXT timeline row and
// showed 500-37,000 tok/s across 13 adapters).
//
// Definition: sum(generated tokens of TIMED contributions) / sum(duration of
// those same contributions). A contribution (one raw proxy or token row
// folded into this Row) is TIMED only when the CAPTURE recorded a duration
// for that model call - a proxy/OTel request duration (ProxyRow.TotalMs) or
// an adapter-stamped per-call duration (TokenRow.GenMs). A row timestamp, a
// turn span or a gap to a neighbour row is never a duration. A contribution
// without a duration contributes to NEITHER side of the ratio, and a
// contribution with zero generated tokens (an error / 404 attempt) is
// excluded from both sides so it cannot dilute the rate.
//
// Every basis includes time to first token (prefill + queueing), so the
// figure is END-TO-END OUTPUT THROUGHPUT, never a decode speed.
type Speed struct {
	// GenTokens is the generated tokens (output, plus reasoning when the
	// adapter's two counts are disjoint) of the TIMED contributions only.
	GenTokens int64
	// GenMs is the summed duration of the same timed contributions.
	GenMs int64
	// Basis is the WEAKEST basis among the timed contributions (see
	// basisRank), so a "measured" label never covers a weaker estimate.
	// Empty when nothing was timed.
	Basis string
	// TimedCalls / Calls count the contributions with generated tokens
	// that carried a duration / all contributions with generated tokens.
	// TimedCalls < Calls means the rate covers a subset of the row.
	TimedCalls int
	Calls      int
}

// Basis values, strongest first. BasisMeasured is a capture-recorded
// request duration (the proxy's total_response_ms, or Claude Code OTel's
// duration_ms, which also lands in api_turns.total_response_ms); BasisNative
// is a per-call duration the tool's own store recorded; BasisTranscript is
// a span an adapter derived from its transcript's record order.
const (
	BasisMeasured   = "measured"
	BasisNative     = "native"
	BasisTranscript = "transcript"
)

// basisRank orders the bases strongest (0) to weakest. An unknown basis
// ranks weakest of all, so an unexpected value can only ever lower the
// label, never raise it.
var basisRank = map[string]int{
	BasisMeasured:   0,
	BasisNative:     1,
	BasisTranscript: 2,
}

func rankOf(basis string) int {
	if r, ok := basisRank[basis]; ok {
		return r
	}
	return len(basisRank)
}

// Suppression reasons Rate reports when a row has generated tokens but no
// trustworthy rate. Serialized verbatim (tps_suppressed) so every surface
// renders a visible reason instead of a silently clamped number.
const (
	SuppressNotMeasured  = "not_measured"
	SuppressTooFewTokens = "too_few_tokens"
	SuppressTooShort     = "too_short"
	SuppressImplausible  = "implausible"
)

// Plausibility thresholds. MinGenTokens: below it, time to first token
// dominates the span and the figure says nothing about the model.
// MinGenMs: a duration this short cannot contain a real model call.
// MaxRate: no production model sustains this end-to-end; a figure above it
// is a capture/unit error (the muse-microseconds / crush-seconds /
// hermes-float-seconds class), shown as suppressed, never clamped.
const (
	MinGenTokens = 64
	MinGenMs     = 250
	MaxRate      = 1000.0
)

// rateRules is the ordered suppression table Rate walks top-down; the first
// rule that fires names the reason. One test case per row
// (speed_test.go).
var rateRules = []struct {
	reason string
	fires  func(s Speed, rate float64) bool
}{
	{SuppressNotMeasured, func(s Speed, _ float64) bool { return s.TimedCalls == 0 || s.GenMs <= 0 || s.GenTokens <= 0 }},
	{SuppressTooFewTokens, func(s Speed, _ float64) bool { return s.GenTokens < MinGenTokens }},
	{SuppressTooShort, func(s Speed, _ float64) bool { return s.GenMs < MinGenMs }},
	{SuppressImplausible, func(_ Speed, rate float64) bool { return rate > MaxRate }},
}

// Rate returns the row's output throughput in tokens per second. ok is
// false when there is no rate to show; reason then names why ("" when the
// row generated nothing at all - a user row - so there is nothing to
// explain).
func (s Speed) Rate() (rate float64, reason string, ok bool) {
	if s.Calls == 0 {
		return 0, "", false
	}
	if s.GenMs > 0 {
		rate = float64(s.GenTokens) / (float64(s.GenMs) / 1000)
	}
	for _, r := range rateRules {
		if r.fires(s, rate) {
			return 0, r.reason, false
		}
	}
	return rate, "", true
}

// add folds one contribution into the accumulator. genTokens is the
// contribution's generated-token count, ms its captured duration (0 = none)
// and basis the duration's basis.
func (s *Speed) add(genTokens, ms int64, basis string) {
	if genTokens <= 0 {
		return
	}
	s.Calls++
	if ms <= 0 {
		return
	}
	s.TimedCalls++
	s.GenTokens += genTokens
	s.GenMs += ms
	if s.Basis == "" || rankOf(basis) > rankOf(s.Basis) {
		s.Basis = basis
	}
}

// tokenGenTokens is a token_usage contribution's generated-token count:
// output, plus reasoning only when the adapter's two counts are disjoint
// (internal/integration TokenTier.ReasoningDisjoint, resolved by the caller
// into DeriveInput.ReasoningDisjoint). An unaudited adapter counts output
// only, so an adapter whose output already INCLUDES reasoning is never
// double-counted.
func tokenGenTokens(t TokenRow, reasoningDisjoint bool) int64 {
	if reasoningDisjoint {
		return t.Output + t.Reasoning
	}
	return t.Output
}

// stampGapToNext sets GapToNextMs on every row but the last: the wall-clock
// gap from this row's timestamp to the next row's, in Derive's final order.
// It is a timeline figure (shown as "Elapsed"), NEVER a Tok/s denominator.
func stampGapToNext(out []*Row) {
	for i := 0; i < len(out)-1; i++ {
		t1, err1 := time.Parse(time.RFC3339Nano, out[i].Timestamp)
		t2, err2 := time.Parse(time.RFC3339Nano, out[i+1].Timestamp)
		if err1 != nil || err2 != nil {
			continue
		}
		ms := t2.Sub(t1).Milliseconds()
		if ms < 0 {
			continue
		}
		out[i].GapToNextMs = &ms
	}
}

// TimingWire is the ONE wire projection of a Row's timing figures, embedded
// verbatim by both the node's Messages row and the org's MessageMetricRow so
// the field names, the omission rules and the suppression reasons cannot
// drift between the two drawers. Rendered by shared/lib/speed.ts.
type TimingWire struct {
	// ElapsedMs is Row.GapToNextMs - the wall-clock gap to the next row
	// ("Elapsed" column). Never a Tok/s denominator.
	ElapsedMs *int64 `json:"elapsed_ms,omitempty"`
	// ResponseMs is the summed capture-recorded request duration
	// (api_turns.total_response_ms) of the row's proxy/OTel calls
	// ("Response" column); absent for a transcript-only row.
	ResponseMs *int64 `json:"response_ms,omitempty"`
	// TpsTokens / TpsMs are Speed.GenTokens / Speed.GenMs, present when at
	// least one generating call was timed (even if the rate is suppressed,
	// so the tooltip can show the raw figures).
	TpsTokens *int64 `json:"tps_tokens,omitempty"`
	TpsMs     *int64 `json:"tps_ms,omitempty"`
	// TpsBasis is Speed.Basis; TpsTimedCalls / TpsCalls Speed's counters.
	TpsBasis      string `json:"tps_basis,omitempty"`
	TpsTimedCalls int    `json:"tps_timed_calls,omitempty"`
	TpsCalls      int    `json:"tps_calls,omitempty"`
	// TpsSuppressed is Rate()'s reason when the row generated tokens but
	// shows no rate. The client divides TpsTokens by TpsMs only when this
	// is empty.
	TpsSuppressed string `json:"tps_suppressed,omitempty"`
}

// Timing returns this row's TimingWire.
func (r *Row) Timing() TimingWire {
	w := TimingWire{
		ElapsedMs:     r.GapToNextMs,
		TpsBasis:      r.Speed.Basis,
		TpsTimedCalls: r.Speed.TimedCalls,
		TpsCalls:      r.Speed.Calls,
	}
	if r.TotalMs > 0 {
		v := r.TotalMs
		w.ResponseMs = &v
	}
	if r.Speed.TimedCalls > 0 {
		tok, ms := r.Speed.GenTokens, r.Speed.GenMs
		w.TpsTokens, w.TpsMs = &tok, &ms
	}
	if _, reason, ok := r.Speed.Rate(); !ok {
		w.TpsSuppressed = reason
	}
	return w
}
