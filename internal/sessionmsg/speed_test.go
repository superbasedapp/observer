package sessionmsg

import (
	"math"
	"testing"
)

// TestSpeedRateRules pins rateRules one row at a time, top-down.
func TestSpeedRateRules(t *testing.T) {
	cases := []struct {
		name       string
		s          Speed
		wantOK     bool
		wantReason string
		wantRate   float64
	}{
		{"no generated tokens at all (user row) -> nothing to explain", Speed{}, false, "", 0},
		{"generated but untimed -> not_measured", Speed{Calls: 1}, false, SuppressNotMeasured, 0},
		{"too few tokens -> prefill dominates", Speed{GenTokens: 63, GenMs: 2000, TimedCalls: 1, Calls: 1, Basis: BasisMeasured}, false, SuppressTooFewTokens, 0},
		{"too short a duration", Speed{GenTokens: 100, GenMs: 249, TimedCalls: 1, Calls: 1, Basis: BasisMeasured}, false, SuppressTooShort, 0},
		{"implausible rate > MaxRate", Speed{GenTokens: 5000, GenMs: 4000, TimedCalls: 1, Calls: 1, Basis: BasisMeasured}, false, SuppressImplausible, 0},
		{"exactly at the ceiling is allowed", Speed{GenTokens: 1000, GenMs: 1000, TimedCalls: 1, Calls: 1, Basis: BasisMeasured}, true, "", 1000},
		{"ordinary measured rate", Speed{GenTokens: 1200, GenMs: 20000, TimedCalls: 1, Calls: 1, Basis: BasisMeasured}, true, "", 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rate, reason, ok := c.s.Rate()
			if ok != c.wantOK || reason != c.wantReason || math.Abs(rate-c.wantRate) > 1e-9 {
				t.Fatalf("Rate() = (%v, %q, %v), want (%v, %q, %v)", rate, reason, ok, c.wantRate, c.wantReason, c.wantOK)
			}
		})
	}
}

// TestDerive_Speed is the table of contribution shapes -> Row.Speed. It
// includes the live reproductions of the S10-SPEED defect (session
// 9d926c5c-5dc7-4107-9057-b6d4d42ee22b, claude-code, NOT proxied): the old
// node "elapsed" tier divided a message's output by the gap to the NEXT
// timeline row and showed 526 tok/s (msg 23) and 2,644 tok/s (msg 74).
func TestDerive_Speed(t *testing.T) {
	type want struct {
		key       string
		ok        bool
		reason    string
		rate      float64
		basis     string
		timed     int
		calls     int
		gapToNext int64 // -1 = nil
		genTokens int64
		genMs     int64
	}
	cases := []struct {
		name string
		in   DeriveInput
		want want
	}{
		{
			name: "repro msg 23: 18,023 out, no proxy, next row 34.2s later -> not measured (was 526/s)",
			in: DeriveInput{TokenRows: []TokenRow{
				{SourceEventID: "msg_011CfK9Lw5Y1f1keTnewWkAm", MessageID: "msg_011CfK9Lw5Y1f1keTnewWkAm", Timestamp: "2026-09-22T20:58:14.234Z", Output: 18023},
				{SourceEventID: "msg_011CfK9bT9C1TTk8WSbwPn17", MessageID: "msg_011CfK9bT9C1TTk8WSbwPn17", Timestamp: "2026-09-22T20:58:48.468Z", Output: 220},
			}},
			want: want{key: "msg_011CfK9Lw5Y1f1keTnewWkAm", reason: SuppressNotMeasured, calls: 1, gapToNext: 34234},
		},
		{
			name: "repro msg 74: 156 out, next row is a task_complete action 59ms later -> not measured (was 2,644/s)",
			in: DeriveInput{
				TokenRows:  []TokenRow{{SourceEventID: "msg_011CfKBE4eF52MD4vQB4y9Hf", MessageID: "msg_011CfKBE4eF52MD4vQB4y9Hf", Timestamp: "2026-09-22T21:20:11.01Z", Output: 156}},
				ActionRows: []ActionRow{{SourceEventID: "9d926c5c:turn_duration:1", ActionType: "task_complete", Timestamp: "2026-09-22T21:20:11.069021605Z"}},
			},
			want: want{key: "msg_011CfKBE4eF52MD4vQB4y9Hf", reason: SuppressNotMeasured, calls: 1, gapToNext: 59},
		},
		{
			name: "repro msg 23 with a W2 transcript span (20:55:28.018 -> 20:58:14.234) -> 108/s",
			in: DeriveInput{TokenRows: []TokenRow{
				{SourceEventID: "msg_011CfK9Lw5Y1f1keTnewWkAm", MessageID: "msg_011CfK9Lw5Y1f1keTnewWkAm", Timestamp: "2026-09-22T20:58:14.234Z", Output: 18023, GenMs: 166216, GenBasis: BasisTranscript},
			}},
			want: want{key: "msg_011CfK9Lw5Y1f1keTnewWkAm", ok: true, rate: 18023 / 166.216, basis: BasisTranscript, timed: 1, calls: 1, gapToNext: -1, genTokens: 18023, genMs: 166216},
		},
		{
			name: "proxy-only call: gross output over the request duration",
			in: DeriveInput{ProxyRows: []ProxyRow{
				{RequestID: "msg_a", Timestamp: "2026-09-22T10:00:00Z", Output: 1200, TotalMs: 20000},
			}},
			want: want{key: "msg_a", ok: true, rate: 60, basis: BasisMeasured, timed: 1, calls: 1, gapToNext: -1, genTokens: 1200, genMs: 20000},
		},
		{
			name: "proxy + JSONL twin (codex): numerator is the proxy's GROSS output, reasoning re-included; twin adds no duration",
			in: DeriveInput{
				ProxyRows: []ProxyRow{{RequestID: "resp_1", Timestamp: "2026-09-22T10:00:00Z", Model: "gpt-5.5", Input: 100, Output: 1500, TotalMs: 30000}},
				TokenRows: []TokenRow{{SourceEventID: "tk:f:L1", TurnID: "trn_1", Timestamp: "2026-09-22T10:00:30Z", Model: "gpt-5.5", Input: 100, Output: 1000, Reasoning: 500, GenMs: 99999, GenBasis: BasisTranscript}},
			},
			want: want{key: "trn_1", ok: true, rate: 50, basis: BasisMeasured, timed: 1, calls: 1, gapToNext: -1, genTokens: 1500, genMs: 30000},
		},
		{
			name: "claude-code id-matched JSONL row adds neither tokens nor duration to the proxy's",
			in: DeriveInput{
				ProxyRows: []ProxyRow{{RequestID: "msg_x", Timestamp: "2026-09-22T10:00:00Z", Output: 600, TotalMs: 10000}},
				TokenRows: []TokenRow{{SourceEventID: "msg_x", MessageID: "msg_x", Timestamp: "2026-09-22T10:00:10Z", Output: 600, GenMs: 12000, GenBasis: BasisTranscript}},
			},
			want: want{key: "msg_x", ok: true, rate: 60, basis: BasisMeasured, timed: 1, calls: 1, gapToNext: -1, genTokens: 600, genMs: 10000},
		},
		{
			name: "turn rollup: 2 proxied calls + 1 unproxied call -> ratio over the timed subset only, 2 of 3",
			in: DeriveInput{
				ProxyRows: []ProxyRow{
					{RequestID: "resp_1", Timestamp: "2026-09-22T10:00:00Z", Model: "m", Input: 10, Output: 400, TotalMs: 10000},
					{RequestID: "resp_2", Timestamp: "2026-09-22T10:01:00Z", Model: "m", Input: 20, Output: 800, TotalMs: 10000},
				},
				TokenRows: []TokenRow{
					{SourceEventID: "tk:1", TurnID: "trn", Timestamp: "2026-09-22T10:00:10Z", Model: "m", Input: 10, Output: 400},
					{SourceEventID: "tk:2", TurnID: "trn", Timestamp: "2026-09-22T10:01:10Z", Model: "m", Input: 20, Output: 800},
					{SourceEventID: "tk:3", TurnID: "trn", Timestamp: "2026-09-22T10:02:10Z", Model: "m", Input: 30, Output: 5000},
				},
			},
			want: want{key: "trn", ok: true, rate: 60, basis: BasisMeasured, timed: 2, calls: 3, gapToNext: -1, genTokens: 1200, genMs: 20000},
		},
		{
			name: "zero-output proxy attempt (error/404) is excluded from BOTH sides",
			in: DeriveInput{
				ProxyRows: []ProxyRow{
					{RequestID: "resp_err", Timestamp: "2026-09-22T10:00:00Z", Model: "m", Input: 10, Output: 0, TotalMs: 60000},
					{RequestID: "resp_ok", Timestamp: "2026-09-22T10:01:00Z", Model: "m", Input: 20, Output: 600, TotalMs: 10000},
				},
				TokenRows: []TokenRow{
					{SourceEventID: "tk:e", TurnID: "trn", Timestamp: "2026-09-22T10:00:01Z", Model: "m", Input: 10, Output: 0},
					{SourceEventID: "tk:o", TurnID: "trn", Timestamp: "2026-09-22T10:01:10Z", Model: "m", Input: 20, Output: 600},
				},
			},
			want: want{key: "trn", ok: true, rate: 60, basis: BasisMeasured, timed: 1, calls: 1, gapToNext: -1, genTokens: 600, genMs: 10000},
		},
		{
			name: "mixed bases -> the WEAKEST basis labels the row",
			in: DeriveInput{
				ProxyRows: []ProxyRow{{RequestID: "resp_1", Timestamp: "2026-09-22T10:00:00Z", Model: "m", Input: 1, Output: 600, TotalMs: 10000}},
				TokenRows: []TokenRow{
					{SourceEventID: "tk:1", TurnID: "trn", Timestamp: "2026-09-22T10:00:10Z", Model: "m", Input: 1, Output: 600},
					{SourceEventID: "tk:2", TurnID: "trn", Timestamp: "2026-09-22T10:01:10Z", Model: "m", Input: 2, Output: 600, GenMs: 10000, GenBasis: BasisNative},
				},
			},
			want: want{key: "trn", ok: true, rate: 60, basis: BasisNative, timed: 2, calls: 2, gapToNext: -1, genTokens: 1200, genMs: 20000},
		},
		{
			name: "reasoning counted only when the adapter is ReasoningDisjoint",
			in: DeriveInput{
				ReasoningDisjoint: true,
				TokenRows:         []TokenRow{{SourceEventID: "e1", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Output: 400, Reasoning: 200, GenMs: 10000, GenBasis: BasisNative}},
			},
			want: want{key: "m1", ok: true, rate: 60, basis: BasisNative, timed: 1, calls: 1, gapToNext: -1, genTokens: 600, genMs: 10000},
		},
		{
			name: "unaudited adapter: reasoning NOT added (output may already include it)",
			in: DeriveInput{
				TokenRows: []TokenRow{{SourceEventID: "e1", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Output: 400, Reasoning: 200, GenMs: 10000, GenBasis: BasisNative}},
			},
			want: want{key: "m1", ok: true, rate: 40, basis: BasisNative, timed: 1, calls: 1, gapToNext: -1, genTokens: 400, genMs: 10000},
		},
		{
			name: "session-cumulative single row (droid/goose shape) -> not measured, whatever the neighbours",
			in: DeriveInput{
				TokenRows:  []TokenRow{{SourceEventID: "tokens:sess", MessageID: "tokens:sess", Timestamp: "2026-09-22T10:00:00.000Z", Output: 281466}},
				ActionRows: []ActionRow{{SourceEventID: "u1", ActionType: "user_prompt", Timestamp: "2026-09-22T10:00:00.500Z"}},
			},
			want: want{key: "tokens:sess", reason: SuppressNotMeasured, calls: 1, gapToNext: 500},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows := Derive(c.in)
			var r *Row
			for _, x := range rows {
				if x.Key == c.want.key {
					r = x
				}
			}
			if r == nil {
				t.Fatalf("row %q not found in %v", c.want.key, keys(rows))
			}
			rate, reason, ok := r.Speed.Rate()
			if ok != c.want.ok || reason != c.want.reason || math.Abs(rate-c.want.rate) > 1e-6 {
				t.Errorf("Rate() = (%v, %q, %v), want (%v, %q, %v); speed=%+v", rate, reason, ok, c.want.rate, c.want.reason, c.want.ok, r.Speed)
			}
			if r.Speed.Basis != c.want.basis || r.Speed.TimedCalls != c.want.timed || r.Speed.Calls != c.want.calls {
				t.Errorf("speed = %+v, want basis=%q timed=%d calls=%d", r.Speed, c.want.basis, c.want.timed, c.want.calls)
			}
			if r.Speed.GenTokens != c.want.genTokens || r.Speed.GenMs != c.want.genMs {
				t.Errorf("gen = %d tok / %d ms, want %d / %d", r.Speed.GenTokens, r.Speed.GenMs, c.want.genTokens, c.want.genMs)
			}
			switch {
			case c.want.gapToNext < 0 && r.GapToNextMs != nil:
				t.Errorf("GapToNextMs = %d, want nil", *r.GapToNextMs)
			case c.want.gapToNext >= 0 && (r.GapToNextMs == nil || *r.GapToNextMs != c.want.gapToNext):
				t.Errorf("GapToNextMs = %v, want %d", r.GapToNextMs, c.want.gapToNext)
			}
		})
	}
}
