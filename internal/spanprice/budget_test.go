package spanprice_test

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/spanprice"
)

// TestBudgetRuleSQLMatchesGo pins the SQL spelling of the budget measure to
// the Go rule, row by row (A-02, E-27): a reported cost is never charged, a
// container span counts nothing, and tokens are uncached input plus output.
func TestBudgetRuleSQLMatchesGo(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE sp (kind TEXT, cost_source TEXT, cost_usd REAL,
		input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER, cache_write_tokens INTEGER)`); err != nil {
		t.Fatal(err)
	}
	type row struct {
		name            string
		kind, source    string
		cost            float64
		in, out, cr, cw int64
		wantCost        float64
		wantTokens      int64
	}
	rows := []row{
		{"computed llm, Anthropic cached prompt", "llm", "computed", 0.5, 8325, 57, 8298, 0, 0.5, 27 + 57},
		{"gateway exact", "llm", "gateway_exact", 0.25, 100, 10, 0, 0, 0.25, 110},
		{"proxy exact embedding", "embedding", "proxy_exact", 0.1, 50, 0, 0, 0, 0.1, 50},
		{"reported cost is not charged", "llm", "reported", 9, 10, 10, 0, 0, 0, 20},
		{"unpriced span", "llm", "", 0, 10, 5, 0, 0, 0, 15},
		{"cache write and read larger than input floors at 0", "llm", "computed", 0.01, 10, 4, 8, 8, 0.01, 4},
		{"agent span restating usage counts nothing", "agent", "computed", 3, 1000, 100, 0, 0, 0, 0},
		{"unstated kind keeps the kind-blind rule", "", "computed", 0.2, 30, 3, 10, 0, 0.2, 23},
	}
	for _, r := range rows {
		if _, err := db.Exec(`DELETE FROM sp`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO sp VALUES (?,?,?,?,?,?,?)`, r.kind, r.source, r.cost, r.in, r.out, r.cr, r.cw); err != nil {
			t.Fatal(err)
		}
		var cost float64
		var tokens int64
		if err := db.QueryRow(`SELECT SUM(`+spanprice.BudgetCostSQL("s")+`), SUM(`+spanprice.BudgetTokensSQL("s")+`) FROM sp s`).Scan(&cost, &tokens); err != nil {
			t.Fatalf("%s: %v", r.name, err)
		}
		if cost != r.wantCost || tokens != r.wantTokens {
			t.Errorf("%s: SQL = (%v, %d), want (%v, %d)", r.name, cost, tokens, r.wantCost, r.wantTokens)
		}
		goCost := 0.0
		if spanprice.BudgetCounts(r.kind, spanprice.Source(r.source)) {
			goCost = r.cost
		}
		if goTok := spanprice.BudgetTokens(r.kind, r.in, r.out, r.cr, r.cw); goCost != r.wantCost || goTok != r.wantTokens {
			t.Errorf("%s: Go = (%v, %d), want (%v, %d)", r.name, goCost, goTok, r.wantCost, r.wantTokens)
		}
	}
}
