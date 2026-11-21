package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestBudgetPricingCoverageLineNamesInvalidRows pins demo bug #5's wording:
// invalid rows are named by reason and tool with a plain sentence, never
// "none-named(invalid-rows)", and the line says which read it measured.
func TestBudgetPricingCoverageLineNamesInvalidRows(t *testing.T) {
	cases := []struct {
		name    string
		cov     budgetPricingCoverage
		want    []string
		notWant []string
	}{
		{
			name: "unverified transcript rows on a managed read",
			cov: budgetPricingCoverage{
				Coverage: orgcontract.PricingCoveragePartial, UnpricedRows: 17777, Read: "managed",
				InvalidReasons: map[string]int{store.GuardBudgetUnverifiedTokens: 17777}, InvalidTools: []string{"claude-code"},
			},
			want: []string{
				"unpriced_rows=17777", "invalid_rows=unverified_tokens:17777", "invalid_tools=claude-code",
				"managed caps count only provider-verified usage", "pricing_read=managed",
			},
			notWant: []string{"none-named", "unpriced_models="},
		},
		{
			name: "a true miss and an invalid row together",
			cov: budgetPricingCoverage{
				Coverage: orgcontract.PricingCoveragePartial, UnpricedRows: 2, UnpricedModels: []string{"big-pickle"},
				InvalidReasons: map[string]int{store.GuardBudgetInvalidCounters: 1}, InvalidTools: []string{"muse"}, Read: "advisory",
			},
			want: []string{"unpriced_models=big-pickle", "invalid_rows=invalid_counters:1", "a token counter is negative", "pricing_read=advisory"},
		},
		{
			name: "a true miss alone names no invalid rows",
			cov:  budgetPricingCoverage{Coverage: orgcontract.PricingCoveragePartial, UnpricedRows: 1, UnpricedModels: []string{"x"}},
			want: []string{"unpriced_models=x"}, notWant: []string{"invalid_rows", "pricing_read"},
		},
	}
	for _, c := range cases {
		line := budgetPricingCoverageLine(c.cov)
		for _, w := range c.want {
			if !strings.Contains(line, w) {
				t.Errorf("%s: line %q lacks %q", c.name, line, w)
			}
		}
		for _, w := range c.notWant {
			if strings.Contains(line, w) {
				t.Errorf("%s: line %q has %q", c.name, line, w)
			}
		}
	}
}

// TestCLIBudgetPricingCoverageReadsLikeTheDaemon: on a node without budget
// enforcement authority the daemon prices caps with the ADVISORY read, so
// the status line measures that read - Claude Code transcript rows are priced,
// not reported invalid. The managed read of the same corpus still names them.
func TestCLIBudgetPricingCoverageReadsLikeTheDaemon(t *testing.T) {
	ctx := context.Background()
	path := t.TempDir() + "/observer.db"
	database, err := dbtemplate.Open(ctx, db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = database.Close() }()
	if _, err := store.New(database).IngestBudgetUsage(ctx, nil, []models.TokenEvent{{
		SessionID: "cc", SourceEventID: "cc-1", Tool: models.ToolClaudeCode, Model: "claude-sonnet-4-5",
		ProjectRoot: t.TempDir(), SourceFile: "fixture", Timestamp: time.Now().UTC(),
		InputTokens: 1_000, OutputTokens: 100, Source: models.TokenSourceJSONL, Reliability: models.ReliabilityUnreliable,
	}}, nil); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Observer.DBPath = path

	advisory := cliBudgetPricingCoverage(ctx, cfg, database, false)
	if advisory.Read != "advisory" || advisory.UnpricedRows != 0 || len(advisory.InvalidReasons) != 0 {
		t.Fatalf("advisory read = %+v, want the transcript row priced", advisory)
	}
	managed := cliBudgetPricingCoverage(ctx, cfg, database, true)
	if managed.Read != "managed" || managed.InvalidReasons[store.GuardBudgetUnverifiedTokens] != 1 {
		t.Fatalf("managed read = %+v, want the transcript row named unverified", managed)
	}
}
