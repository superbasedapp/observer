package orgcontract

import "testing"

// TestMergeBudgetAppCapLimits is the one merge rule's table (review finding
// E-48): rank wins outright, equal ranks merge unit by unit, and the result
// does not depend on argument order.
func TestMergeBudgetAppCapLimits(t *testing.T) {
	usd := BudgetAppCapLimit{Rank: 2, CapUSD: 5}
	tok := BudgetAppCapLimit{Rank: 2, CapTokens: 1000}
	cases := []struct {
		name   string
		a, b   BudgetAppCapLimit
		want   BudgetAppCapLimit
		winner int
	}{
		{"dollar-only and token-only merge", usd, tok, BudgetAppCapLimit{Rank: 2, CapUSD: 5, CapTokens: 1000}, -1},
		{"the lower of each unit", BudgetAppCapLimit{Rank: 1, CapUSD: 5, CapTokens: 900}, BudgetAppCapLimit{Rank: 1, CapUSD: 3, CapTokens: 1000}, BudgetAppCapLimit{Rank: 1, CapUSD: 3, CapTokens: 900}, 1},
		{"tokens decide when dollars tie", BudgetAppCapLimit{Rank: 1, CapUSD: 3, CapTokens: 5}, BudgetAppCapLimit{Rank: 1, CapUSD: 3}, BudgetAppCapLimit{Rank: 1, CapUSD: 3, CapTokens: 5}, -1},
		{"identical caps tie", usd, usd, usd, 0},
		{"hard beats soft whatever the caps", BudgetAppCapLimit{Rank: 1, CapUSD: 1}, usd, usd, 1},
		{"soft beats report", BudgetAppCapLimit{Rank: 1, CapTokens: 9}, BudgetAppCapLimit{CapUSD: 1}, BudgetAppCapLimit{Rank: 1, CapTokens: 9}, -1},
	}
	for _, c := range cases {
		got, w := MergeBudgetAppCapLimits(c.a, c.b)
		if got != c.want || w != c.winner {
			t.Errorf("%s: got %+v winner %d, want %+v winner %d", c.name, got, w, c.want, c.winner)
		}
		rev, rw := MergeBudgetAppCapLimits(c.b, c.a)
		if rev != got || rw != -w {
			t.Errorf("%s: order-dependent: %+v/%d vs %+v/%d", c.name, got, w, rev, rw)
		}
	}
	for _, e := range []struct {
		in   string
		want int
	}{{"hard", 2}, {"soft", 1}, {"report", 0}, {"", 0}} {
		if got := BudgetAppEnforcementRank(e.in); got != e.want {
			t.Errorf("rank(%q) = %d, want %d", e.in, got, e.want)
		}
	}
}
