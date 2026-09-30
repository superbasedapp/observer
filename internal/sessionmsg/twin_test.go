package sessionmsg

import "testing"

// TestShapeMatches_OutputClamp is the twin-identity table for defect D2
// (demo node-1, session ses_f1b18bbc7ffeJJcbQTqgJdmTsZ, an OpenRouter free
// nemotron model under OpenCode): the provider reported MORE reasoning than
// the completion count it billed, the transcript floored its visible output
// at zero, and the exact p.Output == t.Output + t.Reasoning check left both
// copies of the turn counted (49,554 tokens shown for ~24.8K real). A twin is
// the same model, input and cache figures, with an output the transcript
// derives as max(0, gross - reasoning) - nothing looser.
func TestShapeMatches_OutputClamp(t *testing.T) {
	prx := func(in, out, cr int64) ProxyRow {
		return ProxyRow{RequestID: "gen-1", Timestamp: "2026-09-27T10:00:00Z", Model: "nvidia/nemotron:free", Input: in, Output: out, CacheRead: cr}
	}
	tok := func(in, out, reason, cr int64) TokenRow {
		return TokenRow{SourceEventID: "msg_1", Timestamp: "2026-09-27T10:00:03Z", Model: "nvidia/nemotron:free", Input: in, Output: out, Reasoning: reason, CacheRead: cr}
	}
	cases := []struct {
		name           string
		p              ProxyRow
		t              TokenRow
		want           bool
		wantOut, wantR int64 // the folded proxy contribution's output / reasoning
	}{
		{"live D2 turn 1: completion 59, reasoning 65, visible clamped to 0", prx(12000, 59, 0), tok(12000, 0, 65, 0), true, 0, 59},
		{"live D2 turn 2: completion 55, reasoning 58, visible clamped to 0", prx(12400, 55, 0), tok(12400, 0, 58, 0), true, 0, 55},
		{"earlier live session: 95 = 30 visible + 65 reasoning", prx(9000, 95, 800), tok(9000, 30, 65, 800), true, 30, 65},
		{"no reasoning: exact output", prx(100, 40, 0), tok(100, 40, 0, 0), true, 40, 0},
		{"near miss: visible 0 but the reasoning does not cover the gross output", prx(12000, 59, 0), tok(12000, 0, 50, 0), false, 0, 0},
		{"near miss: a positive visible output must sum exactly", prx(12000, 59, 0), tok(12000, 3, 65, 0), false, 0, 0},
		{"near miss: same output, different input", prx(12000, 59, 0), tok(12001, 0, 65, 0), false, 0, 0},
		{"near miss: same output, different cache read", prx(12000, 59, 100), tok(12000, 0, 65, 0), false, 0, 0},
		{"near miss: different model", prx(12000, 59, 0), TokenRow{Model: "other", Input: 12000, Reasoning: 65, Timestamp: "2026-09-27T10:00:03Z"}, false, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shapeMatches(c.p, c.t); got != c.want {
				t.Fatalf("shapeMatches = %v, want %v", got, c.want)
			}
			in := DeriveInput{ProxyRows: []ProxyRow{c.p}, TokenRows: []TokenRow{c.t}}
			v := DeriveVerdicts(in)
			if v.TokenCounted[0] == c.want {
				t.Fatalf("TokenCounted = %v, want %v (a twin is not counted a second time)", v.TokenCounted[0], !c.want)
			}
			totals := SumContributions(Derive(in), "")
			if c.want {
				if totals.Turns != 1 || totals.Bundle.Output != c.wantOut || totals.Bundle.Reasoning != c.wantR {
					t.Fatalf("folded turn: turns=%d output=%d reasoning=%d, want 1 / %d / %d",
						totals.Turns, totals.Bundle.Output, totals.Bundle.Reasoning, c.wantOut, c.wantR)
				}
				if v.ProxyOutput[0] != c.wantOut || v.ProxyReasoning[0] != c.wantR {
					t.Fatalf("verdict output/reasoning = %d/%d, want %d/%d", v.ProxyOutput[0], v.ProxyReasoning[0], c.wantOut, c.wantR)
				}
			} else if totals.Turns != 2 {
				t.Fatalf("distinct turns folded: turns=%d, want 2", totals.Turns)
			}
		})
	}
}

// TestAssignTwins_ClampKeepsOneToOneClosest pins that the clamp case does not
// loosen the claim: two proxy turns with the same prompt shape, each with its
// own clamped transcript copy, pair one-to-one by closest timestamp, and a
// third transcript turn that no proxy row explains stays counted.
func TestAssignTwins_ClampKeepsOneToOneClosest(t *testing.T) {
	in := DeriveInput{
		ProxyRows: []ProxyRow{
			{RequestID: "gen-a", Timestamp: "2026-09-27T10:00:00Z", Model: "m", Input: 500, Output: 59},
			{RequestID: "gen-b", Timestamp: "2026-09-27T10:05:00Z", Model: "m", Input: 500, Output: 55},
		},
		TokenRows: []TokenRow{
			{SourceEventID: "msg_b", Timestamp: "2026-09-27T10:05:02Z", Model: "m", Input: 500, Reasoning: 58},
			{SourceEventID: "msg_a", Timestamp: "2026-09-27T10:00:02Z", Model: "m", Input: 500, Reasoning: 65},
			{SourceEventID: "msg_c", Timestamp: "2026-09-27T10:09:00Z", Model: "m", Input: 500, Output: 12, Reasoning: 4},
		},
	}
	v := DeriveVerdicts(in)
	if v.TokenCounted[0] || v.TokenCounted[1] || !v.TokenCounted[2] {
		t.Fatalf("TokenCounted = %v, want [false false true]", v.TokenCounted)
	}
	if v.ProxyPartner[0] != 1 || v.ProxyPartner[1] != 0 {
		t.Fatalf("ProxyPartner = %v, want [1 0] (closest in time, one-to-one)", v.ProxyPartner)
	}
}
