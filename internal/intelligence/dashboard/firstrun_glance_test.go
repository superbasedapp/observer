package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestFirstRunGlanceSpendStates pins the spend rule table, one case per row,
// and the honesty rules: an unpriced turn adds tokens but never dollars,
// and "estimated" holds when any priced turn was priced from the table.
func TestFirstRunGlanceSpendStates(t *testing.T) {
	tok := cost.TokenBundle{Input: 100, Output: 50, CacheRead: 10, CacheCreation: 5, Reasoning: 2}
	cases := []struct {
		name      string
		turns     []dashapi.SpendTurn
		state     string
		usd       float64
		tokens    int64
		priced    int
		unpriced  int
		estimated bool
	}{
		{name: "no turns", state: "none"},
		{
			name:     "only an unpriced model",
			turns:    []dashapi.SpendTurn{{Model: "mystery", Bundle: tok}},
			state:    "unpriced",
			tokens:   167,
			unpriced: 1,
		},
		{
			name: "table-priced and unpriced",
			turns: []dashapi.SpendTurn{
				{Model: "a", Bundle: tok, Priced: true, CostUSD: 1.5},
				{Model: "mystery", Bundle: tok},
			},
			state: "priced", usd: 1.5, tokens: 334, priced: 1, unpriced: 1, estimated: true,
		},
		{
			name:  "recorded cost only",
			turns: []dashapi.SpendTurn{{Model: "a", Bundle: tok, Priced: true, Recorded: 0.4, CostUSD: 0.4}},
			state: "priced", usd: 0.4, tokens: 167, priced: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sp := firstRunGlanceSpendOf(tc.turns)
			if sp.State != tc.state || sp.USD != tc.usd || sp.Tokens != tc.tokens ||
				sp.PricedTurns != tc.priced || sp.UnpricedTurns != tc.unpriced || sp.Estimated != tc.estimated {
				t.Fatalf("got %+v", sp)
			}
		})
	}
}

// TestFirstRunGlanceTopModel: most turns wins, a tie goes to the name first
// in order, a turn with no model is not counted, and none at all is nil.
func TestFirstRunGlanceTopModel(t *testing.T) {
	if got := firstRunGlanceTopModel(nil); got != nil {
		t.Fatalf("no turns: got %+v", got)
	}
	if got := firstRunGlanceTopModel([]dashapi.SpendTurn{{Model: ""}}); got != nil {
		t.Fatalf("no model: got %+v", got)
	}
	got := firstRunGlanceTopModel([]dashapi.SpendTurn{
		{Model: "b"}, {Model: "a"}, {Model: "c"}, {Model: "c"}, {Model: ""},
	})
	if got == nil || got.Model != "c" || got.Turns != 2 || got.Models != 3 || got.Share != 0.5 {
		t.Fatalf("got %+v", got)
	}
	tie := firstRunGlanceTopModel([]dashapi.SpendTurn{{Model: "b"}, {Model: "a"}})
	if tie == nil || tie.Model != "a" {
		t.Fatalf("tie: got %+v", tie)
	}
}

// TestFirstRunGlanceRoute: the route reads the real database: totals, tools
// most first, the busiest project, recent sessions, no spend on a database
// without token rows, and the agent working right now from a fresh action.
func TestFirstRunGlanceRoute(t *testing.T) {
	f := newFirstRunFixture(t, true)
	f.seedSession(t, "s1", "tool-done", "/work/alpha")
	f.seedSession(t, "s2", "tool-done", "/work/alpha")
	f.seedSession(t, "s3", "tool-scanning", "/work/beta")

	var out firstRunGlanceResponse
	getModelJSON(t, f.server, "/api/firstrun/glance", &out)
	if out.WindowDays != 30 || out.Sessions != 3 || out.ProjectCount != 2 || out.RecentSessions != 3 {
		t.Fatalf("totals: %+v", out)
	}
	if len(out.Tools) != 2 || out.Tools[0].Tool != "tool-done" || out.Tools[0].Sessions != 2 {
		t.Fatalf("tools: %+v", out.Tools)
	}
	if out.BusiestProject == nil || out.BusiestProject.Name != "alpha" || out.BusiestProject.Sessions != 2 {
		t.Fatalf("busiest: %+v", out.BusiestProject)
	}
	if out.Spend.State != "none" || out.TopModel != nil {
		t.Fatalf("spend on an empty substrate: %+v top=%+v", out.Spend, out.TopModel)
	}
	if out.ActiveNow != nil {
		t.Fatalf("nothing is working, got %+v", out.ActiveNow)
	}
	if out.Rereads == nil || *out.Rereads != 0 {
		t.Fatalf("rereads: %v", out.Rereads)
	}

	ctx := context.Background()
	pid, err := f.store.UpsertProject(ctx, "/work/beta", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.InsertActions(ctx, []models.Action{{
		Tool: "tool-scanning", SessionID: "s3", ProjectID: pid,
		ActionType: "read_file", Target: "main.go",
		Timestamp:  time.Now().UTC(),
		SourceFile: "f", SourceEventID: "e1",
	}}); err != nil {
		t.Fatal(err)
	}
	out = firstRunGlanceResponse{}
	getModelJSON(t, f.server, "/api/firstrun/glance", &out)
	if out.ActiveNow == nil || out.ActiveNow.Tool != "tool-scanning" || out.ActiveNow.Project != "beta" {
		t.Fatalf("active now: %+v", out.ActiveNow)
	}
}
