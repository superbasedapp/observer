package requestclass

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestNormalizeTable(t *testing.T) {
	cases := []struct{ in, want string }{
		{"main", "main"},
		{"subagent", "subagent"},
		{"workflow", "workflow"},
		{"compaction", "compaction"},
		{"auxiliary", "auxiliary"},
		{"  main\t", "main"},
		{"", ""},
		{"Main", ""},
		{"sub-agent", ""},
		{"future-class", ""},
		{"main,subagent", ""},
	}
	for _, c := range cases {
		if got := Normalize(c.in); got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValuesMatchModels(t *testing.T) {
	want := []string{
		models.APIRequestClassMain, models.APIRequestClassSubagent, models.APIRequestClassWorkflow,
		models.APIRequestClassCompaction, models.APIRequestClassAuxiliary,
	}
	if !reflect.DeepEqual(Values, want) {
		t.Fatalf("Values = %v, want %v", Values, want)
	}
	for _, v := range Values {
		if !Valid(v) || Normalize(v) != v {
			t.Errorf("%q must be valid and normalize to itself", v)
		}
	}
}

func TestSummarizeTable(t *testing.T) {
	cases := []struct {
		name string
		rows []Row
		want *Split
	}{
		{name: "no rows is nil", rows: nil, want: nil},
		{
			name: "rows but none classified: Classified false, empty classes",
			rows: []Row{{InputTokens: 10, OutputTokens: 5, CostUSD: 0.5}, {Class: "Main", InputTokens: 1, CostUSD: 0.25}},
			want: &Split{Classes: []Bucket{}, Unclassified: Bucket{Turns: 2, InputTokens: 11, OutputTokens: 5, CostUSD: 0.75}, TotalTurns: 2},
		},
		{
			name: "classes in vocabulary order, unknown spelling unclassified",
			rows: []Row{
				{Class: "auxiliary", InputTokens: 3, OutputTokens: 1, CostUSD: 0.125},
				{Class: "main", InputTokens: 100, OutputTokens: 50, CacheReadTokens: 1000, CacheCreationTokens: 20, CostUSD: 1},
				{Class: "subagent", InputTokens: 40, OutputTokens: 10, CostUSD: 0.5},
				{Class: "main", InputTokens: 200, OutputTokens: 70, CacheReadTokens: 2000, CostUSD: 2},
				{Class: "bogus", InputTokens: 7, CostUSD: 0.25},
				{Class: "", InputTokens: 1, CostUSD: 0.25},
			},
			want: &Split{
				Classified: true,
				Classes: []Bucket{
					{Class: "main", Turns: 2, InputTokens: 300, OutputTokens: 120, CacheReadTokens: 3000, CacheCreationTokens: 20, CostUSD: 3},
					{Class: "subagent", Turns: 1, InputTokens: 40, OutputTokens: 10, CostUSD: 0.5},
					{Class: "auxiliary", Turns: 1, InputTokens: 3, OutputTokens: 1, CostUSD: 0.125},
				},
				Unclassified: Bucket{Turns: 2, InputTokens: 8, CostUSD: 0.5},
				TotalTurns:   6,
			},
		},
		{
			name: "all classified: unclassified bucket is zero",
			rows: []Row{{Class: "compaction", InputTokens: 9, CostUSD: 0.5}},
			want: &Split{Classified: true, Classes: []Bucket{{Class: "compaction", Turns: 1, InputTokens: 9, CostUSD: 0.5}}, TotalTurns: 1},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Summarize(c.rows)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Summarize = %s\nwant       %s", js(got), js(c.want))
			}
		})
	}
}

// TestSummarizeOrderIndependent pins bit-identical float sums whatever order
// the caller loaded the rows in (the node and the org order differently).
func TestSummarizeOrderIndependent(t *testing.T) {
	rows := []Row{
		{Class: "main", CostUSD: 0.1},
		{Class: "main", CostUSD: 0.2},
		{Class: "main", CostUSD: 0.3},
		{Class: "main", CostUSD: 1e-17},
		{Class: "subagent", CostUSD: 0.7},
		{CostUSD: 0.05},
	}
	want := Summarize(rows)
	rev := make([]Row, len(rows))
	for i := range rows {
		rev[len(rows)-1-i] = rows[i]
	}
	if got := Summarize(rev); !reflect.DeepEqual(got, want) {
		t.Fatalf("reversed input changed the split:\n%s\n%s", js(got), js(want))
	}
}

func js(v any) string { b, _ := json.Marshal(v); return string(b) }
