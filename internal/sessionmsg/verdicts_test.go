package sessionmsg

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// sumVerdicts totals a session the way a verdict-applying surface does:
// every proxy row with its verdict's output/reasoning, every counted token
// row as stored.
func sumVerdicts(in DeriveInput, v Verdicts) (TokenBundle, float64, int64) {
	var b TokenBundle
	var cost float64
	var turns int64
	for i, p := range in.ProxyRows {
		if !v.ProxyCounted[i] {
			continue
		}
		b.Input += p.Input
		b.Output += v.ProxyOutput[i]
		b.Reasoning += v.ProxyReasoning[i]
		b.CacheRead += p.CacheRead
		b.CacheCreation += p.CacheCreation
		b.CacheCreation1h += p.CacheCreation1h
		b.WebSearchRequests += p.WebSearchRequests
		cost += p.CostUSD
		turns++
	}
	for i, t := range in.TokenRows {
		if !v.TokenCounted[i] {
			continue
		}
		b.Input += t.Input
		b.Output += t.Output
		b.Reasoning += t.Reasoning
		b.CacheRead += t.CacheRead
		b.CacheCreation += t.CacheCreation
		b.CacheCreation1h += t.CacheCreation1h
		b.WebSearchRequests += t.WebSearchRequests
		cost += t.CostUSD
		turns++
	}
	return b, cost, turns
}

// randomSession builds a session that exercises every dedup class at once:
// proxy/transcript twins with and without a reasoning split, direct
// request-id matches (claude-code), mismatched ids (codex/opencode), an
// identical-shape turn only the transcript saw, keyless rows, duplicate
// shapes far apart in time, and Copilot-style output-only shadow rows.
func randomSession(r *rand.Rand) DeriveInput {
	base := time.Date(2026, 9, 27, 9, 0, 0, 0, time.UTC)
	ts := func(sec int) string { return base.Add(time.Duration(sec) * time.Second).Format(time.RFC3339Nano) }
	models := []string{"m-a", "m-b"}
	var in DeriveInput
	n := 1 + r.Intn(12)
	for k := 0; k < n; k++ {
		model := models[r.Intn(len(models))]
		input := int64(10 * (1 + r.Intn(3))) // few distinct values: shapes collide
		out := int64(5 * (1 + r.Intn(3)))
		reason := int64(0)
		if r.Intn(2) == 0 {
			reason = int64(r.Intn(3)) * 2
		}
		cr := int64(r.Intn(2) * 100)
		cc := int64(r.Intn(2) * 7)
		at := r.Intn(3600 * 3)
		reqID := ""
		if r.Intn(6) != 0 {
			reqID = fmt.Sprintf("resp_%d", k)
		}
		proxied := r.Intn(3) != 0
		transcribed := !proxied || r.Intn(4) != 0
		if proxied {
			in.ProxyRows = append(in.ProxyRows, ProxyRow{
				RequestID: reqID, Timestamp: ts(at), Model: model,
				Input: input, Output: out + reason, CacheRead: cr, CacheCreation: cc,
				CacheCreation1h: int64(r.Intn(2)), CostUSD: float64(1+r.Intn(9)) / 100,
			})
		}
		if transcribed {
			sid := fmt.Sprintf("tk:f:L%d", k)
			switch r.Intn(4) {
			case 0:
				sid = reqID // claude-code: ids agree
			case 1:
				sid = "" // legacy keyless
			}
			tOut, tReason := out, reason
			if r.Intn(5) == 0 {
				tOut, tReason = out+reason, 0 // a split the proxy cannot see
			}
			in.TokenRows = append(in.TokenRows, TokenRow{
				SourceEventID: sid, Timestamp: ts(at + r.Intn(20)), Model: model,
				Input: input, Output: tOut, Reasoning: tReason, CacheRead: cr, CacheCreation: cc,
				CacheCreation1h: int64(r.Intn(2)), CostUSD: float64(1+r.Intn(9)) / 100,
				TurnID: map[bool]string{true: fmt.Sprintf("trn_%d", k/2)}[r.Intn(2) == 0],
			})
		}
		if r.Intn(4) == 0 { // an output-only shadow sibling
			in.TokenRows = append(in.TokenRows, TokenRow{
				SourceEventID: fmt.Sprintf("shadow:%d", k), Timestamp: ts(at + r.Intn(40)),
				Model: model, Output: out, CostUSD: 0.001,
			})
		}
	}
	in.ShadowCapable = r.Intn(2) == 0
	// A session-cumulative running total (droid / goose / crush / vibe) that
	// sometimes out-covers the per-turn capture and sometimes does not, plus
	// an aider-style per-exchange "tokens:" row the flag must NOT treat as
	// cumulative when the capability is off.
	if r.Intn(3) == 0 {
		in.SessionCumulative = r.Intn(4) != 0
		in.TokenRows = append(in.TokenRows, TokenRow{
			SourceEventID: "tokens:sess", Timestamp: ts(r.Intn(3600 * 3)), Model: models[r.Intn(len(models))],
			Input: int64(r.Intn(3) * 150), Output: int64(r.Intn(3) * 40), CacheRead: int64(r.Intn(2) * 300),
			CostUSD: float64(r.Intn(9)) / 100,
		})
	}
	// Hand the rows over in a scrambled order: verdicts must come back
	// against the CALLER's indexes, whatever order that is.
	r.Shuffle(len(in.ProxyRows), func(i, j int) { in.ProxyRows[i], in.ProxyRows[j] = in.ProxyRows[j], in.ProxyRows[i] })
	r.Shuffle(len(in.TokenRows), func(i, j int) { in.TokenRows[i], in.TokenRows[j] = in.TokenRows[j], in.TokenRows[i] })
	return in
}

// TestDeriveVerdicts_SumEqualsDerive pins the contract every verdict-applying
// surface relies on: summing rows under DeriveVerdicts gives exactly
// SumContributions(Derive(...)) - tokens, reasoning, cost and turn count.
func TestDeriveVerdicts_SumEqualsDerive(t *testing.T) {
	r := rand.New(rand.NewSource(20260927))
	for iter := 0; iter < 5000; iter++ {
		in := randomSession(r)
		want := SumContributions(Derive(in), "")
		gotB, gotCost, gotTurns := sumVerdicts(in, DeriveVerdicts(in))
		wantB := want.Bundle
		wantB.Fast, gotB.Fast = false, false
		if gotB != wantB || gotTurns != want.Turns || !closeUSD(gotCost, want.RecordedCostUSD) {
			t.Fatalf("iter %d: verdict sum %+v cost %v turns %d != Derive %+v cost %v turns %d\ninput %+v",
				iter, gotB, gotCost, gotTurns, wantB, want.RecordedCostUSD, want.Turns, in)
		}
	}
}

// TestDeriveVerdicts_CallerIndexAligned pins that a verdict names the
// caller's own row: the same rows handed over in two different orders get
// the same per-row decisions.
func TestDeriveVerdicts_CallerIndexAligned(t *testing.T) {
	in := DeriveInput{
		ProxyRows: []ProxyRow{
			{RequestID: "resp_2", Timestamp: "2026-09-27T10:05:00Z", Model: "m", Input: 1, Output: 9},
			{RequestID: "resp_1", Timestamp: "2026-09-27T10:00:00Z", Model: "m", Input: 1, Output: 30},
		},
		TokenRows: []TokenRow{
			{SourceEventID: "own", Timestamp: "2026-09-27T11:00:00Z", Model: "m", Input: 5, Output: 5},
			{SourceEventID: "tk:1", Timestamp: "2026-09-27T10:00:04Z", Model: "m", Input: 1, Output: 20, Reasoning: 10},
		},
	}
	v := DeriveVerdicts(in)
	if !v.TokenCounted[0] || v.TokenCounted[1] {
		t.Fatalf("TokenCounted = %v, want [true false]", v.TokenCounted)
	}
	if v.ProxyOutput[1] != 20 || v.ProxyReasoning[1] != 10 || v.ProxyOutput[0] != 9 || v.ProxyReasoning[0] != 0 {
		t.Fatalf("proxy verdicts out=%v reasoning=%v, want [9 20] / [0 10]", v.ProxyOutput, v.ProxyReasoning)
	}
	if !v.ProxyAdjusted(1, 30) || v.ProxyAdjusted(0, 9) {
		t.Fatal("ProxyAdjusted must flag only the twinned row")
	}
}

func closeUSD(a, b float64) bool {
	d := a - b
	return d < 1e-9 && d > -1e-9
}

// assignTwinsQuadratic is the pre-bucketing assignTwins, kept as the oracle
// for the shape-bucketed one: every proxy row scans every token row.
func assignTwinsQuadratic(proxies []ProxyRow, tokens []TokenRow) (twinOf []int, claimed []bool) {
	twinOf = make([]int, len(proxies))
	for i := range twinOf {
		twinOf[i] = -1
	}
	claimed = make([]bool, len(tokens))
	for pi, p := range proxies {
		best := -1
		var bestDelta time.Duration
		pt, pErr := time.Parse(time.RFC3339Nano, p.Timestamp)
		for ti, t := range tokens {
			if claimed[ti] || !shapeMatches(p, t) {
				continue
			}
			var delta time.Duration
			if pErr == nil {
				if tt, tErr := time.Parse(time.RFC3339Nano, t.Timestamp); tErr == nil {
					delta = absDuration(pt.Sub(tt))
				}
			}
			switch {
			case best == -1, delta < bestDelta:
				best, bestDelta = ti, delta
			case delta == bestDelta && lessTokenCandidate(t, tokens[best]):
				best, bestDelta = ti, delta
			}
		}
		if best >= 0 {
			twinOf[pi] = best
			claimed[best] = true
		}
	}
	return twinOf, claimed
}

// TestAssignTwins_BucketedEqualsQuadratic pins that looking candidates up by
// twinShape picks exactly the twins the full scan picks.
func TestAssignTwins_BucketedEqualsQuadratic(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for iter := 0; iter < 5000; iter++ {
		in := randomSession(r)
		plan := planDedup(in)
		wantOf, wantClaimed := assignTwinsQuadratic(plan.proxies, plan.tokens)
		gotOf, gotClaimed := assignTwins(plan.proxies, plan.tokens)
		if fmt.Sprint(gotOf, gotClaimed) != fmt.Sprint(wantOf, wantClaimed) {
			t.Fatalf("iter %d: bucketed %v %v != quadratic %v %v", iter, gotOf, gotClaimed, wantOf, wantClaimed)
		}
		for _, p := range plan.proxies {
			for _, tk := range plan.tokens {
				if shapeMatches(p, tk) && proxyTwinShape(&p) != tokenTwinShape(&tk) {
					t.Fatalf("shapeMatches across two twinShape buckets for %+v / %+v", p, tk)
				}
			}
		}
	}
}
