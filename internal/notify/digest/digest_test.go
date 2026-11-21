package digest

import (
	"strings"
	"testing"
)

func baseData() Data {
	return Data{
		Title:         "Weekly cost digest",
		PeriodLabel:   "Jun 29 - Jul 5, 2026",
		TotalUSD:      123.45,
		PriorTotalUSD: 100.00,
		HasPrior:      true,
		Breakdowns: []Breakdown{
			{Title: "Spend by model", Items: []LineItem{
				{Label: "claude-opus-4-8", CostUSD: 80.00},
				{Label: "claude-sonnet-4", CostUSD: 43.45},
			}},
			{Title: "Spend by tool", Items: []LineItem{
				{Label: "claude-code", CostUSD: 123.45},
			}},
		},
		Movers: []Mover{
			{Label: "claude-opus-4-8", CurrentUSD: 80, PriorUSD: 50},
		},
		AlertCount:    2,
		HasAlertCount: true,
		Version:       "v1.19.0",
	}
}

func TestComposeContainsKeyLines(t *testing.T) {
	m := Compose(baseData())

	if !strings.Contains(m.Subject, "Weekly cost digest") || !strings.Contains(m.Subject, "Jun 29") {
		t.Errorf("subject missing title/period: %q", m.Subject)
	}
	wantText := []string{
		"Observed spend for Jun 29 - Jul 5, 2026: $123.45",
		"Observed spend: $123.45",
		"Prior period: $100.00",
		"Change: +$23.45 (+23%)",
		"Alerts fired: 2",
		"Spend by model",
		"claude-opus-4-8: $80.00",
		"Spend by tool",
		"Top movers vs prior period",
		"claude-opus-4-8: $80.00 (was $50.00, +$30.00 (+60%))",
		"Sent by superbased Observer v1.19.0",
	}
	for _, w := range wantText {
		if !strings.Contains(m.Text, w) {
			t.Errorf("text body missing %q\n---\n%s", w, m.Text)
		}
	}
	// HTML must carry the section titles + totals too.
	for _, w := range []string{"Spend by model", "$123.45", "Top movers vs prior period"} {
		if !strings.Contains(m.HTML, w) {
			t.Errorf("html body missing %q", w)
		}
	}
	// Honesty: never cite compression savings.
	for _, banned := range []string{"compression", "saved", "savings"} {
		if strings.Contains(strings.ToLower(m.Text), banned) {
			t.Errorf("digest body must not mention %q", banned)
		}
	}
}

func TestComposeNoPrior(t *testing.T) {
	d := baseData()
	d.HasPrior = false
	d.Movers = nil
	m := Compose(d)
	if strings.Contains(m.Text, "Prior period") {
		t.Errorf("no-prior digest must not render a prior line:\n%s", m.Text)
	}
	if strings.Contains(m.Text, "vs the prior period") {
		t.Errorf("no-prior heading must not mention prior period")
	}
}

func TestComposeOrgSubject(t *testing.T) {
	d := baseData()
	d.OrgName = "Acme"
	d.Title = "Monthly org spend digest"
	m := Compose(d)
	if !strings.HasPrefix(m.Subject, "[Observer] Acme: Monthly org spend digest") {
		t.Errorf("org subject = %q", m.Subject)
	}
}

func TestComposeUnattributedLabel(t *testing.T) {
	d := Data{
		Title:       "Weekly cost digest",
		PeriodLabel: "wk",
		TotalUSD:    5,
		Breakdowns:  []Breakdown{{Title: "Spend by model", Items: []LineItem{{Label: "", CostUSD: 5}}}},
	}
	m := Compose(d)
	if !strings.Contains(m.Text, "(unattributed): $5.00") {
		t.Errorf("blank label should render placeholder:\n%s", m.Text)
	}
}

func TestRankMovers(t *testing.T) {
	current := []LineItem{
		{Label: "opus", CostUSD: 100},
		{Label: "sonnet", CostUSD: 20},
		{Label: "haiku", CostUSD: 5},
	}
	prior := []LineItem{
		{Label: "opus", CostUSD: 40},   // +60
		{Label: "sonnet", CostUSD: 90}, // -70
		{Label: "gpt", CostUSD: 10},    // -10 (dropped out)
	}
	got := RankMovers(current, prior, 2)
	if len(got) != 2 {
		t.Fatalf("want 2 movers, got %d", len(got))
	}
	// sonnet has the largest |delta| (70), then opus (60).
	if got[0].Label != "sonnet" || got[1].Label != "opus" {
		t.Fatalf("ranking = %s,%s; want sonnet,opus", got[0].Label, got[1].Label)
	}
	if got[0].Delta() != -70 {
		t.Errorf("sonnet delta = %v, want -70", got[0].Delta())
	}
}

func TestSignedDelta(t *testing.T) {
	tests := []struct {
		cur, prior float64
		want       string
	}{
		{120, 100, "+$20.00 (+20%)"},
		{80, 100, "-$20.00 (-20%)"},
		{50, 0, "+$50.00 (new)"},
		{0, 0, "no change"},
	}
	for _, tt := range tests {
		if got := signedDelta(tt.cur, tt.prior); got != tt.want {
			t.Errorf("signedDelta(%v,%v) = %q, want %q", tt.cur, tt.prior, got, tt.want)
		}
	}
}

// TestComposeTokenDisplay pins T-204: the node digest under the token-usage
// developer cost display renders every figure as the token usage behind it,
// leaves out the dollar-only movers section and carries no dollar sign; the
// zero value (the org digest, an admin surface) stays dollars.
func TestComposeTokenDisplay(t *testing.T) {
	d := baseData()
	d.Title = "Weekly usage digest"
	d.CostDisplay = "tokens"
	d.TotalTokens, d.PriorTotalTokens = 1_260_000, 1_000_000
	d.Breakdowns[0].Items[0].Tokens = 800_000
	d.Breakdowns[0].Items[1].Tokens = 450_000
	d.Breakdowns[1].Items[0].Tokens = 1_260_000
	m := Compose(d)
	for _, w := range []string{
		"Observed usage for Jun 29 - Jul 5, 2026: 1.3M tok",
		"Prior period: 1M tok",
		"Change: +260K tok (+26%)",
		"claude-opus-4-8: 800K tok",
	} {
		if !strings.Contains(m.Text, w) {
			t.Errorf("token digest missing %q\n---\n%s", w, m.Text)
		}
	}
	for _, body := range []string{m.Subject, m.Text, m.HTML} {
		if strings.Contains(body, "$") || strings.Contains(body, "Top movers") {
			t.Errorf("token digest carries a dollar figure or the movers section:\n%s", body)
		}
	}
	if !strings.Contains(Compose(baseData()).Text, "$123.45") {
		t.Error("the zero-value display is no longer dollars")
	}
}
