package store

import (
	"context"
	"reflect"
	"sync/atomic"
	"testing"
)

// TestProveGuardAnchorRow: one row's outcome, the window that proved it and
// the reason it stayed unproven, per search shape.
func TestProveGuardAnchorRow(t *testing.T) {
	t.Parallel()
	base := guardAnchorShapes()["v1"]
	hints := func(ids ...int64) []guardAnchorHint {
		names := []string{GuardAnchorHintContent, GuardAnchorHintSession, GuardAnchorHintPrevious}
		out := make([]guardAnchorHint, len(ids))
		for i, id := range ids {
			out[i] = guardAnchorHint{rule: names[i], id: id}
		}
		return out
	}
	cases := []struct {
		name            string
		anchor          int64
		hints           []guardAnchorHint
		radius, ceiling int64
		wantAnchor      int64
		wantRule        string
		wantTries       int64
		wantReason      string
		wantWindows     int
	}{
		{"near the first hint", 1_005, hints(1_000), 100, 10_000, 1_005, GuardAnchorHintContent, 10, "", 0},
		{"whole range, far from the hint", 9_000, hints(1), 0, 10_000, 9_000, GuardAnchorHintContent, 9_000, "", 0},
		{"second window proves it", 5_003, hints(1_000, 5_000), 100, 10_000, 5_003, GuardAnchorHintSession, 201 + 6, "", 0},
		{"third window proves it below its hint", 7_998, hints(1_000, 5_000, 8_000), 10, 10_000, 7_998, GuardAnchorHintPrevious, 21 + 21 + 5, "", 0},
		{"outside every window", 1_500, hints(1_000, 2_000), 100, 10_000, 0, "", 402, GuardAnchorOutsideRadius, 2},
		{"overlapping windows try each id once", 1_120, hints(1_000, 1_050), 100, 10_000, 1_120, GuardAnchorHintSession, 201 + 20, "", 0},
		{"overlapping windows, unproven", 5_000, hints(1_000, 1_050), 100, 10_000, 0, "", 201 + 50, GuardAnchorOutsideRadius, 2},
		{"windows that together cover the range", 100, hints(5, 40), 30, 60, 0, "", 60, GuardAnchorNoID, 2},
		{"radius covers the whole range: one window", 20_000, hints(5, 40), 100, 50, 0, "", 50, GuardAnchorNoID, 1},
		{"above the ceiling, whole range", 20_000, hints(1, 3), 0, 10_000, 0, "", 10_000, GuardAnchorNoID, 1},
		{"no actions ever issued", 3, hints(1), 0, 0, 0, "", 0, GuardAnchorNoID, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := sealedGuardRow(base, "", tc.anchor)
			p, why := newGuardAnchorPreimage(&r)
			if p == nil {
				t.Fatal(why)
			}
			var hashed atomic.Int64
			s := guardAnchorSearcher{radius: tc.radius, ceiling: tc.ceiling, workers: 2, hashed: &hashed, memo: newGuardAnchorHints()}
			out, err := s.prove(context.Background(), &r, p, tc.hints)
			if err != nil {
				t.Fatal(err)
			}
			if out.anchor != tc.wantAnchor || out.rule != tc.wantRule || out.tries != tc.wantTries {
				t.Fatalf("outcome = anchor %d rule %q tries %d, want %d %q %d", out.anchor, out.rule, out.tries, tc.wantAnchor, tc.wantRule, tc.wantTries)
			}
			reason, windows := "", 0
			if out.miss != nil {
				reason, windows = out.miss.Reason, out.miss.Windows
			}
			if reason != tc.wantReason || windows != tc.wantWindows {
				t.Fatalf("miss = %+v, want reason %q windows %d", out.miss, tc.wantReason, tc.wantWindows)
			}
			if out.miss == nil && out.dist != absInt64(tc.wantAnchor-hintID(tc.hints, tc.wantRule)) {
				t.Fatalf("dist = %d", out.dist)
			}
			if r.actionAnchor != nil {
				t.Fatal("the row was left with an anchor set")
			}
		})
	}
}

func hintID(hints []guardAnchorHint, rule string) int64 {
	for _, h := range hints {
		if h.rule == rule {
			return h.id
		}
	}
	return 0
}

// TestGuardAnchorHints: the hint table, rule by rule: distinct hints in
// rule order, the first action id only when no rule yields one.
func TestGuardAnchorHints(t *testing.T) {
	t.Parallel()
	type seen struct {
		session string
		id      int64
		proven  bool
		key     byte
	}
	cases := []struct {
		name    string
		observe []seen
		session string
		key     byte
		next    int64
		want    []guardAnchorHint
	}{
		{
			name: "nothing seen: the first action id", session: "a",
			want: []guardAnchorHint{{GuardAnchorHintFirst, 1}},
		},
		{
			name: "only a later anchored row", session: "a", next: 700,
			want: []guardAnchorHint{{GuardAnchorHintNext, 700}},
		},
		{
			name: "another session seen", observe: []seen{{"b", 500, false, 0}, {"c", 900, false, 0}}, session: "a", next: 950,
			want: []guardAnchorHint{{GuardAnchorHintPrevious, 900}, {GuardAnchorHintNext, 950}},
		},
		{
			name: "own session seen", observe: []seen{{"a", 100, false, 0}, {"b", 500, false, 0}, {"a", 120, false, 0}, {"c", 900, false, 0}}, session: "a",
			want: []guardAnchorHint{{GuardAnchorHintSession, 120}, {GuardAnchorHintPrevious, 900}},
		},
		{
			name: "a proven row with the same content", observe: []seen{{"a", 300, true, 7}, {"a", 301, true, 8}, {"b", 900, false, 0}}, session: "a", key: 7, next: 901,
			want: []guardAnchorHint{{GuardAnchorHintContent, 300}, {GuardAnchorHintSession, 301}, {GuardAnchorHintPrevious, 900}, {GuardAnchorHintNext, 901}},
		},
		{
			name: "equal hints collapse to the first rule", observe: []seen{{"a", 300, true, 7}}, session: "a", key: 7, next: 300,
			want: []guardAnchorHint{{GuardAnchorHintContent, 300}},
		},
		{
			name: "a known anchor never feeds the content rule", observe: []seen{{"a", 300, false, 7}}, session: "a", key: 7,
			want: []guardAnchorHint{{GuardAnchorHintSession, 300}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newGuardAnchorHints()
			for _, o := range tc.observe {
				r := &GuardEventRow{SessionID: o.session}
				if o.proven {
					h.observeProven(r, [32]byte{o.key}, o.id)
				} else {
					h.observe(r, o.id)
				}
			}
			got := h.hintsFor(guardAnchorHintInput{row: &GuardEventRow{SessionID: tc.session}, key: [32]byte{tc.key}, next: tc.next})
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("hintsFor = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestGuardAnchorSearcherSkipsMissedWindow: a bounded window an identical
// earlier row came up empty in is skipped (no hash), a whole-range search
// never is.
func TestGuardAnchorSearcherSkipsMissedWindow(t *testing.T) {
	t.Parallel()
	base := guardAnchorShapes()["v1"]
	for _, tc := range []struct {
		name        string
		radius      int64
		wantSkipped int
		wantReason  string
	}{
		{"bounded: skipped", 100, 1, GuardAnchorRepeatMissed},
		{"whole range: searched again", 0, 0, GuardAnchorNoID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var hashed atomic.Int64
			s := guardAnchorSearcher{radius: tc.radius, ceiling: 1_000, workers: 1, hashed: &hashed, memo: newGuardAnchorHints()}
			hint := []guardAnchorHint{{GuardAnchorHintNext, 500}}
			first := sealedGuardRow(base, "", 9_000) // above the ceiling: never found
			second := sealedGuardRow(base, first.ChainHash, 9_000)
			p1, _ := newGuardAnchorPreimage(&first)
			p2, _ := newGuardAnchorPreimage(&second)
			if p1.key != p2.key {
				t.Fatal("repeats must share a content key")
			}
			if _, err := s.prove(context.Background(), &first, p1, hint); err != nil {
				t.Fatal(err)
			}
			before := hashed.Load()
			out, err := s.prove(context.Background(), &second, p2, hint)
			if err != nil {
				t.Fatal(err)
			}
			if out.miss == nil || out.miss.Skipped != tc.wantSkipped || out.miss.Reason != tc.wantReason {
				t.Fatalf("second = %+v, want skipped %d reason %q", out.miss, tc.wantSkipped, tc.wantReason)
			}
			if skippedHashes := hashed.Load() - before; (tc.wantSkipped == 1) != (skippedHashes == 0) {
				t.Fatalf("second hashed %d", skippedHashes)
			}
		})
	}
}
