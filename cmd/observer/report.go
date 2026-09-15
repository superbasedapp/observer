package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	notifydigest "github.com/marmutapp/superbased-observer/internal/notify/digest"
	"github.com/marmutapp/superbased-observer/internal/notify/sharecard"
)

// report.go wires `observer report share` — a PURE LOCAL artifact generator
// (gap-register G24). It composes a copy-pasteable Markdown block and a
// 1200×630 social card (SVG) summarizing the developer's observed agent spend
// for a completed period, framed around spend VISIBILITY / model mix / cache
// economics (never compression dollar-savings). No network at all: it only
// reads the local cost engine and writes a file / stdout.

const (
	shareTopModels = 3 // models shown on the card + markdown
	shareTopTools  = 5 // tools shown in the mix
)

// newReportCmd is the `observer report` group.
func newReportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate shareable spend reports (local artifacts, no network)",
	}
	cmd.AddCommand(newReportShareCmd())
	return cmd
}

func newReportShareCmd() *cobra.Command {
	var (
		configPath string
		period     string
		outPath    string
		markdown   bool
	)
	cmd := &cobra.Command{
		Use:   "share",
		Short: "Compose a shareable cost card (SVG) + Markdown for a completed period",
		Long: "Compose a beautiful, copy-pasteable summary of your observed agent\n" +
			"spend for the most-recently-COMPLETED period — period total, top 3\n" +
			"models, cache-read share, and tool mix. Writes a 1200×630 social card\n" +
			"(SVG, default ./observer-report.svg) and/or prints the Markdown block\n" +
			"with --markdown. Entirely local: no network, and the card carries only\n" +
			"aggregates — never project names, paths, or session titles.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, db, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			freq := notifydigest.Weekly
			kind := "week"
			switch strings.ToLower(strings.TrimSpace(period)) {
			case "", "week", "weekly":
			case "month", "monthly":
				freq = notifydigest.Monthly
				kind = "month"
			default:
				return fmt.Errorf("report share: --period %q not in {week, month}", period)
			}

			p, _ := notifydigest.DuePeriod(freq, 0, time.Now().UTC())
			engine := acquireProcessCostEngine(cmd.Context(), cfg, db, slog.Default())
			data, err := assembleShareData(cmd.Context(), engine, db, p, kind)
			if err != nil {
				return err
			}
			data.Version = version

			if markdown {
				fmt.Fprint(cmd.OutOrStdout(), data.Markdown())
			}

			// The SVG is written unless the user asked ONLY for markdown by
			// passing --markdown with an explicit empty --out.
			if outPath != "" {
				if err := os.WriteFile(outPath, []byte(data.SVG()), 0o600); err != nil {
					return fmt.Errorf("report share: write %s: %w", outPath, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "wrote %s (%s — %s)\n", outPath, p.Label, moneyLine(data.TotalUSD))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().StringVar(&period, "period", "week", "reporting window: week | month")
	cmd.Flags().StringVar(&outPath, "out", "observer-report.svg", "SVG output path (empty string to skip the SVG)")
	cmd.Flags().BoolVar(&markdown, "markdown", false, "print the Markdown block to stdout")
	return cmd
}

// assembleShareData builds the content-free sharecard.Data for a period from
// the cost engine: total spend, top models, tool mix, and the cache-read share.
func assembleShareData(ctx context.Context, engine *cost.Engine, db *sql.DB, p notifydigest.Period, kind string) (sharecard.Data, error) {
	modelSum, err := engine.Summary(ctx, db, cost.Options{
		Since: p.Start, Until: p.End, GroupBy: cost.GroupByModel, Source: cost.SourceAuto, Limit: 200,
	})
	if err != nil {
		return sharecard.Data{}, fmt.Errorf("report.assemble models: %w", err)
	}
	toolSum, err := engine.Summary(ctx, db, cost.Options{
		Since: p.Start, Until: p.End, GroupBy: cost.GroupByTool, Source: cost.SourceAuto, Limit: 200,
	})
	if err != nil {
		return sharecard.Data{}, fmt.Errorf("report.assemble tools: %w", err)
	}

	data := sharecard.Data{
		PeriodKind:  kind,
		PeriodLabel: p.Label,
		TotalUSD:    modelSum.TotalCost,
		TurnCount:   modelSum.TurnCount,
		TopModels:   topItems(modelSum.Rows, shareTopModels),
		Tools:       topItems(toolSum.Rows, shareTopTools),
	}

	// Cache-read share = cache_read / (net input + cache_read + cache_creation).
	// The denominator is total input-side tokens; the share is what fraction hit
	// prefix cache. Only meaningful when there is input-side activity.
	tb := modelSum.TotalTokens
	denom := tb.Input + tb.CacheRead + tb.CacheCreation + tb.CacheCreation1h
	if denom > 0 {
		data.HasCacheShare = true
		data.CacheReadShare = float64(tb.CacheRead) / float64(denom)
	}
	return data, nil
}

// topItems converts the top-N cost rows into sharecard line items. Rows arrive
// already sorted by cost desc from the engine.
func topItems(rows []cost.Row, n int) []sharecard.LineItem {
	if n > 0 && len(rows) > n {
		rows = rows[:n]
	}
	items := make([]sharecard.LineItem, 0, len(rows))
	for _, r := range rows {
		items = append(items, sharecard.LineItem{Label: r.Key, CostUSD: r.CostUSD})
	}
	return items
}

// moneyLine formats a total for the CLI confirmation line.
func moneyLine(v float64) string { return fmt.Sprintf("$%.2f", v) }
