package main

import (
	"strings"
	"testing"
	"time"
)

func TestTraceTailPrintsEachTraceOnceOldestFirst(t *testing.T) {
	tl := traceTail{seen: map[string]bool{}}
	got := tl.fresh([]obsTraceLine{{TraceID: "c"}, {TraceID: "b"}, {TraceID: "a"}})
	if len(got) != 3 || got[0].TraceID != "a" || got[2].TraceID != "c" {
		t.Fatalf("first poll = %+v", got)
	}
	// The next poll re-reads the window: only the new trace prints.
	got = tl.fresh([]obsTraceLine{{TraceID: "d"}, {TraceID: "c"}, {TraceID: "b"}})
	if len(got) != 1 || got[0].TraceID != "d" {
		t.Fatalf("second poll = %+v", got)
	}
}

func TestSpanTreeOrder(t *testing.T) {
	spans := []obsSpanLine{
		{SpanID: "root"},
		{SpanID: "c1", ParentSpanID: "root"},
		{SpanID: "g1", ParentSpanID: "c1"},
		{SpanID: "c2", ParentSpanID: "root"},
		{SpanID: "orphan", ParentSpanID: "missing"},
		{SpanID: "x", ParentSpanID: "y"}, // a two-span cycle: both listed flat
		{SpanID: "y", ParentSpanID: "x"},
	}
	var got []string
	for _, s := range spanTreeOrder(spans) {
		got = append(got, strings.Repeat(">", s.depth)+s.span.SpanID)
	}
	want := "root >c1 >>g1 >c2 orphan x y"
	if strings.Join(got, " ") != want {
		t.Fatalf("order = %q, want %q", strings.Join(got, " "), want)
	}
}

func TestTraceFlagRules(t *testing.T) {
	now := time.Date(2026, 11, 19, 15, 0, 0, 0, time.UTC)
	cases := []struct {
		days int
		want time.Time
	}{
		{0, time.Time{}},
		{1, time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)},
		{7, time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)},
	}
	for _, c := range cases {
		if got := sinceDays(now, c.days); !got.Equal(c.want) {
			t.Errorf("sinceDays(%d) = %v, want %v", c.days, got, c.want)
		}
	}
	for s, ok := range map[string]bool{"": true, "error": true, "ok": true, "bogus": false} {
		if (validTraceStatus(s) == nil) != ok {
			t.Errorf("validTraceStatus(%q) ok=%v", s, !ok)
		}
	}
	if err := requireAppObs(false); err == nil || !strings.Contains(err.Error(), "this machine") {
		t.Errorf("requireAppObs(false) = %v", err)
	}
	if requireAppObs(true) != nil {
		t.Error("requireAppObs(true) refused")
	}
}

func TestTraceTextFormats(t *testing.T) {
	if traceClip("abcdef", 4) != "abc…" || traceClip("abc", 4) != "abc" {
		t.Error("traceClip")
	}
	if traceTokens(1500) != "1.5k" || traceTokens(2_500_000) != "2.5M" || traceTokens(12) != "12" {
		t.Error("traceTokens")
	}
	one := 1.5
	if traceTotalCost(nil) != "unpriced" || traceTotalCost(&one) != "$1.50" {
		t.Errorf("traceTotalCost: an unpriced trace must read unpriced (L-06)")
	}
	if traceCost(0) != "$0" || traceCost(0.0012) != "$0.0012" || traceCost(1.5) != "$1.50" {
		t.Error("traceCost")
	}
	if traceDur(850) != "850ms" || traceDur(2400) != "2.4s" {
		t.Error("traceDur")
	}
	line := traceLineText(obsTraceLine{TraceID: "t1", Status: "ok", ErrorCount: 2})
	if !strings.Contains(line, "ok+2err") || !strings.Contains(line, "(unnamed)") {
		t.Errorf("line = %q", line)
	}
}
