// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package cost

import (
	"bytes"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
)

// TestTokensForBytesMatchesTheRepoEstimate pins the byte-count estimate to
// the repo's tokenizer estimate (cachetrack.EstimateTokens), so a stored
// result_tokens_est and a schema estimate come from ONE heuristic.
func TestTokensForBytesMatchesTheRepoEstimate(t *testing.T) {
	for _, n := range []int{0, 1, 3, 4, 5, 7, 8, 1023, 1024, 4097} {
		b := bytes.Repeat([]byte("x"), n)
		want := int64(cachetrack.EstimateTokens("text", b))
		if got := TokensForBytes(int64(n)); got != want {
			t.Errorf("TokensForBytes(%d) = %d, cachetrack = %d", n, got, want)
		}
		if got := EstimateTokens(b); got != want {
			t.Errorf("EstimateTokens(%d bytes) = %d, cachetrack = %d", n, got, want)
		}
	}
	if TokensForBytes(-5) != 0 {
		t.Error("a negative size must estimate 0")
	}
}

func TestCatalogFromToolsJSON(t *testing.T) {
	raw := []byte(`[
	  {"name":"read_file","description":"Read a file","inputSchema":{"type":"object",  "properties":{"path":{"type":"string"}}},"annotations":{"readOnlyHint":true}},
	  {"name":"write_file","description":"Write a file with a much longer description so it weighs more","inputSchema":{"type":"object"}},
	  {"description":"nameless is skipped"}
	]`)
	c, err := CatalogFromToolsJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 2 || c["read_file"] <= 0 || c["write_file"] <= 0 {
		t.Fatalf("catalog = %v", c)
	}
	// The model-facing projection only: annotations are not counted, and the
	// input schema is compacted (whitespace never inflates the estimate).
	want := EstimateTokens([]byte(`{"name":"read_file","description":"Read a file","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}}}`))
	if c["read_file"] != want {
		t.Fatalf("read_file = %d, want %d", c["read_file"], want)
	}
	if c.Total() != c["read_file"]+c["write_file"] {
		t.Fatal("Total must sum the catalogue")
	}
	if e, err := CatalogFromToolsJSON(nil); err != nil || len(e) != 0 {
		t.Fatalf("empty input = %v, %v", e, err)
	}
	if _, err := CatalogFromToolsJSON([]byte(`{"not":"an array"}`)); err == nil {
		t.Fatal("a malformed tools_json must be an error, never a guessed catalogue")
	}
}

// TestAttributionTable is one case per row of attributionRules, in order.
func TestAttributionTable(t *testing.T) {
	w := map[string]int64{"s1/read": 40, "s1/write": 60}
	cases := []struct {
		name       string
		in         AttributeInput
		row        string
		method     string
		confidence string
		schema     int64
		reserve    int64
	}{
		{
			"described tool call",
			AttributeInput{Kind: KindToolCall, Tool: "s1/write", Weights: w},
			"tool_call_described", MethodDirect, ConfidenceExact, 60, 60,
		},
		{
			"catalogue listing",
			AttributeInput{Kind: KindCatalogue, Weights: w},
			"catalogue_allocated", MethodAllocated, ConfidenceInferred, 0, 100,
		},
		{
			"undescribed tool call",
			AttributeInput{Kind: KindToolCall, Tool: "s1/missing", Weights: w},
			"tool_call_undescribed", MethodInferred, ConfidenceInferred, 50, 50,
		},
		{
			"tool call without a snapshot",
			AttributeInput{Kind: KindToolCall, Tool: "s1/read"},
			"tool_call_no_catalogue", MethodInferred, ConfidenceNone, 0, 0,
		},
		{
			"resource read",
			AttributeInput{Kind: KindOther, Weights: w},
			"own_result", MethodDirect, ConfidenceExact, 0, 0,
		},
		{
			"catalogue without a snapshot",
			AttributeInput{Kind: KindCatalogue},
			"own_result", MethodDirect, ConfidenceExact, 0, 0,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, row := attribute(c.in)
			if row != c.row || a.Method != c.method || a.Confidence != c.confidence || a.SchemaTokens != c.schema || a.ReserveTokens != c.reserve {
				t.Fatalf("got row=%s %+v, want row=%s %s/%s schema=%d reserve=%d", row, a, c.row, c.method, c.confidence, c.schema, c.reserve)
			}
			if a.TokenizerVersion != TokenizerVersion {
				t.Fatalf("tokenizer version not stamped: %q", a.TokenizerVersion)
			}
			if !oneOf(a.Method, Methods) || !oneOf(a.Confidence, Confidences) {
				t.Fatalf("attribution outside the CHECK vocabulary: %+v", a)
			}
		})
	}
	// Every row is reachable.
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.row] = true
	}
	for _, r := range attributionRules {
		if !seen[r.name] {
			t.Errorf("rule %q has no test case", r.name)
		}
	}
}

// TestSettleIsLabelledEstimated: a settled estimate is always labelled
// estimated, names its tokenizer and adds the result half.
func TestSettleIsLabelledEstimated(t *testing.T) {
	a := Attribute(AttributeInput{Kind: KindToolCall, Tool: "s/t", Weights: map[string]int64{"s/t": 25}})
	e := Settle(a, 401)
	if !e.Estimated || e.TokenizerVersion != TokenizerVersion {
		t.Fatalf("estimate not labelled: %+v", e)
	}
	if e.SchemaTokens != 25 || e.ResultTokens != 101 || e.TotalTokens != 126 || e.ResultBytes != 401 {
		t.Fatalf("settle = %+v", e)
	}
	if e.Shares != nil {
		t.Fatal("a direct call carries no allocation shares")
	}
	if z := Settle(Attribution{}, -1); z.ResultBytes != 0 || z.TokenizerVersion != TokenizerVersion || !z.Estimated {
		t.Fatalf("zero settle = %+v", z)
	}
}

// TestMultiToolAllocation: a catalogue listing's result is split across the
// listed tools by descriptor weight, summing exactly to the total.
func TestMultiToolAllocation(t *testing.T) {
	w := map[string]int64{"s/a": 10, "s/b": 30, "s/c": 60}
	a := Attribute(AttributeInput{Kind: KindCatalogue, Weights: w})
	e := Settle(a, 400) // 100 result tokens
	if e.Method != MethodAllocated || e.TotalTokens != 100 {
		t.Fatalf("estimate = %+v", e)
	}
	if e.Shares["s/a"] != 10 || e.Shares["s/b"] != 30 || e.Shares["s/c"] != 60 {
		t.Fatalf("shares = %v", e.Shares)
	}
	// The attribution holds a COPY of the weights (a later edit of the
	// caller's map cannot move a stored split).
	w["s/a"] = 1000
	if a.Weights["s/a"] != 10 {
		t.Fatal("the attribution must copy its weights")
	}
}

func TestAllocateLargestRemainder(t *testing.T) {
	cases := []struct {
		name    string
		total   int64
		weights map[string]int64
		want    map[string]int64
	}{
		{"exact", 6, map[string]int64{"a": 1, "b": 2}, map[string]int64{"a": 2, "b": 4}},
		{"remainder to the largest fraction", 10, map[string]int64{"a": 1, "b": 1, "c": 1}, map[string]int64{"a": 4, "b": 3, "c": 3}},
		{"tie broken by key", 1, map[string]int64{"b": 1, "a": 1}, map[string]int64{"a": 1, "b": 0}},
		{"zero weight takes nothing", 7, map[string]int64{"a": 0, "b": 5}, map[string]int64{"a": 0, "b": 7}},
		{"all-zero weights split evenly", 5, map[string]int64{"a": 0, "b": 0}, map[string]int64{"a": 3, "b": 2}},
		{"zero total", 0, map[string]int64{"a": 3}, map[string]int64{"a": 0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Allocate(c.total, c.weights)
			var sum int64
			for k, v := range c.want {
				if got[k] != v {
					t.Fatalf("Allocate = %v, want %v", got, c.want)
				}
			}
			for _, v := range got {
				sum += v
			}
			if c.total > 0 && sum != c.total {
				t.Fatalf("shares sum %d != total %d", sum, c.total)
			}
		})
	}
	if Allocate(10, nil) != nil {
		t.Fatal("no weights, no shares")
	}
	// Property: shares always sum to the total across awkward weights.
	for total := int64(1); total < 200; total += 7 {
		got := Allocate(total, map[string]int64{"x": 3, "y": 7, "z": 11, "w": 13})
		var sum int64
		for _, v := range got {
			sum += v
		}
		if sum != total {
			t.Fatalf("total %d: shares %v sum %d", total, got, sum)
		}
	}
}

func oneOf(v string, set []string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}
