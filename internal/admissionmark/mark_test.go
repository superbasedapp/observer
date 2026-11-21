package admissionmark

import "testing"

func TestFold(t *testing.T) {
	cases := []struct {
		name string
		in   []Verdict
		want *Mark
	}{
		{"none", nil, nil},
		{"single allow", []Verdict{{"allow", "", "enforce"}}, &Mark{Decision: "allow", Mode: "enforce", Count: 1}},
		{"deny beats allow", []Verdict{{"allow", "", "enforce"}, {"deny", "topics", "enforce"}}, &Mark{Decision: "deny", CriterionID: "topics", Mode: "enforce", Count: 2}},
		{"ask beats flag", []Verdict{{"flag", "a", "observe"}, {"ask", "b", "observe"}}, &Mark{Decision: "ask", CriterionID: "b", Mode: "observe", Count: 2}},
		{"tie keeps first", []Verdict{{"deny", "new", "enforce"}, {"deny", "old", "enforce"}}, &Mark{Decision: "deny", CriterionID: "new", Mode: "enforce", Count: 2}},
		{"known beats unknown", []Verdict{{"weird", "x", ""}, {"allow", "", "observe"}}, &Mark{Decision: "allow", Mode: "observe", Count: 2}},
		{"only unknown kept", []Verdict{{"weird", "x", ""}}, &Mark{Decision: "weird", CriterionID: "x", Count: 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Fold(c.in)
			if (got == nil) != (c.want == nil) || (got != nil && *got != *c.want) {
				t.Fatalf("Fold = %+v, want %+v", got, c.want)
			}
		})
	}
}

func TestRank(t *testing.T) {
	order := []string{"", "allow", "flag", "ask", "deny"}
	for i := 1; i < len(order); i++ {
		if Rank(order[i]) <= Rank(order[i-1]) {
			t.Fatalf("Rank(%q)=%d not above Rank(%q)=%d", order[i], Rank(order[i]), order[i-1], Rank(order[i-1]))
		}
	}
}

func TestFoldByTrace(t *testing.T) {
	ids := []string{"t1", "", "t1", "t2"}
	vs := []Verdict{{"allow", "", "enforce"}, {"deny", "x", "enforce"}, {"deny", "c", "enforce"}, {"flag", "f", "observe"}}
	got := FoldByTrace(ids, vs)
	if len(got) != 2 {
		t.Fatalf("got %d traces, want 2", len(got))
	}
	if got["t1"].Decision != "deny" || got["t1"].CriterionID != "c" || got["t1"].Count != 2 {
		t.Fatalf("t1 = %+v", got["t1"])
	}
	if got["t2"].Decision != "flag" {
		t.Fatalf("t2 = %+v", got["t2"])
	}
}
