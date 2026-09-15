package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
)

// newCostCmd wires `observer cost`, the CLI companion to the MCP
// get_cost_summary tool. Uses the shared cost engine so both entry points
// return identical numbers.
func newCostCmd() *cobra.Command {
	var (
		configPath  string
		days        int
		groupByRaw  string
		sourceRaw   string
		projectRoot string
		limit       int
		jsonOut     bool
		filters     []string
	)
	cmd := &cobra.Command{
		Use:   "cost",
		Short: "Token & USD cost rollup from api_turns (proxy) and token_usage (logs)",
		Long: "Groups observed token usage into a cost-per-key table and prints it.\n" +
			"Proxy data is accurate (spec §24); JSONL data is approximate or unreliable\n" +
			"and tagged as such. When both sources cover the same session, proxy wins.\n\n" +
			"Group keys: model | session | day | project | tool | none\n\n" +
			"V4-2: --filter narrows the rollup by Row.Key substring match.\n" +
			"Repeatable; multiple filters are OR-combined.\n" +
			"  observer cost --group-by model --filter 'claude' --filter 'gpt-5'",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			groupBy, err := parseGroupBy(groupByRaw)
			if err != nil {
				return err
			}
			source, err := parseSource(sourceRaw)
			if err != nil {
				return err
			}
			engine := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
			summary, err := engine.Summary(cmd.Context(), database, cost.Options{
				Days:        days,
				GroupBy:     groupBy,
				Source:      source,
				ProjectRoot: projectRoot,
				Limit:       limit,
			})
			if err != nil {
				return err
			}
			summary = applyCostFilters(summary, filters)
			if jsonOut {
				body, _ := json.MarshalIndent(summary, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			printCostSummary(cmd.OutOrStdout(), summary)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().IntVar(&days, "days", 30, "Restrict to the last N days (0 disables)")
	cmd.Flags().StringVar(&groupByRaw, "group-by", "model", "Rollup key: model, session, day, project, tool, none")
	cmd.Flags().StringVar(&sourceRaw, "source", "auto", "Token source: auto, proxy, jsonl")
	cmd.Flags().StringVar(&projectRoot, "project", "", "Filter to a project root path")
	cmd.Flags().IntVar(&limit, "limit", 50, "Cap returned rows")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON")
	cmd.Flags().StringSliceVar(&filters, "filter", nil, "Filter rows by Key substring (repeatable; OR-combined). V4-2 restore.")
	return cmd
}

// applyCostFilters narrows summary.Rows to those whose Key contains
// ANY of the filter substrings (OR semantics). Empty filters list is
// a no-op. Totals are NOT recomputed — they represent the original
// window's full activity. Operators wanting filtered totals can take
// the rollup --group-by none with the same --filter.
func applyCostFilters(summary cost.Summary, filters []string) cost.Summary {
	if len(filters) == 0 {
		return summary
	}
	var kept []cost.Row
	for _, r := range summary.Rows {
		for _, f := range filters {
			if strings.Contains(strings.ToLower(r.Key), strings.ToLower(f)) {
				kept = append(kept, r)
				break
			}
		}
	}
	summary.Rows = kept
	return summary
}

func parseGroupBy(s string) (cost.GroupBy, error) {
	switch strings.ToLower(s) {
	case "", "model":
		return cost.GroupByModel, nil
	case "session":
		return cost.GroupBySession, nil
	case "day":
		return cost.GroupByDay, nil
	case "project":
		return cost.GroupByProject, nil
	case "tool":
		return cost.GroupByTool, nil
	case "none":
		return cost.GroupByNone, nil
	default:
		return "", fmt.Errorf("--group-by %q not in {model, session, day, project, tool, none}", s)
	}
}

func parseSource(s string) (cost.Source, error) {
	switch strings.ToLower(s) {
	case "", "auto":
		return cost.SourceAuto, nil
	case "proxy":
		return cost.SourceProxy, nil
	case "jsonl":
		return cost.SourceJSONL, nil
	default:
		return "", fmt.Errorf("--source %q not in {auto, proxy, jsonl}", s)
	}
}

// printCostSummary renders a human-friendly table. Two sections: rows sorted
// by cost desc, then a totals footer. Tokens are shown in thousands (k) with
// no decimal when >= 10k; otherwise raw. USD is always 4 decimals.
//
// When any row carries conversation compression stats, a savings column is
// appended — bytes saved with the percent reduction. Groups with no
// compression data show a blank cell.
func printCostSummary(w io.Writer, s cost.Summary) {
	if len(s.Rows) == 0 {
		fmt.Fprintln(w, "no cost data in range")
		return
	}
	showSavings := s.TotalCompression.OriginalBytes > 0
	// V3-5: surface mean proxy-observed latency as the LATENCY column
	// when at least one row in the summary has it populated.
	showLatency := false
	for _, r := range s.Rows {
		if r.AvgLatencyMS > 0 {
			showLatency = true
			break
		}
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := "KEY\tIN\tOUT\tCACHE_R\tCACHE_W\tTURNS\tSRC\tRELIAB\tCOST_USD"
	if showLatency {
		header += "\tLATENCY_MS"
	}
	if showSavings {
		header += "\tSAVED"
	}
	fmt.Fprintln(tw, header)
	for _, r := range s.Rows {
		line := fmt.Sprintf(
			"%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t$%.4f",
			truncate(r.Key, 42),
			formatTokens(r.Tokens.Input),
			formatTokens(r.Tokens.Output),
			formatTokens(r.Tokens.CacheRead),
			formatTokens(r.Tokens.CacheCreation),
			r.TurnCount,
			r.Source,
			r.Reliability,
			r.CostUSD,
		)
		if showLatency {
			if r.AvgLatencyMS > 0 {
				line += fmt.Sprintf("\t%d", r.AvgLatencyMS)
			} else {
				line += "\t-"
			}
		}
		if showSavings {
			line += "\t" + formatSavings(r.Compression)
		}
		fmt.Fprintln(tw, line)
	}
	total := fmt.Sprintf(
		"TOTAL\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t$%.4f",
		formatTokens(s.TotalTokens.Input),
		formatTokens(s.TotalTokens.Output),
		formatTokens(s.TotalTokens.CacheRead),
		formatTokens(s.TotalTokens.CacheCreation),
		s.TurnCount,
		"",
		s.Reliability,
		s.TotalCost,
	)
	if showLatency {
		// TOTAL row leaves latency blank — it's a per-bucket mean,
		// not a sum that would aggregate sensibly across buckets.
		total += "\t-"
	}
	if showSavings {
		total += "\t" + formatSavings(s.TotalCompression)
	}
	fmt.Fprintln(tw, total)
	_ = tw.Flush()
	if s.UnknownModelCount > 0 {
		fmt.Fprintf(w, "\n%d model(s) without pricing — their rows report 0 cost. Add entries under [intelligence.pricing.models] in config.toml.\n", s.UnknownModelCount)
	}
	if s.Days > 0 {
		fmt.Fprintf(w, "window: last %d day(s); group_by=%s source=%s\n", s.Days, s.GroupBy, s.Source)
	} else {
		fmt.Fprintf(w, "group_by=%s source=%s\n", s.GroupBy, s.Source)
	}
}

// formatSavings renders a savings cell like "1.2MB (35%)" or "—" when no
// compression data is present in this group.
func formatSavings(c cost.CompressionStats) string {
	if c.OriginalBytes <= 0 {
		return "—"
	}
	saved := c.SavedBytes()
	pct := int(c.SavedRatio() * 100)
	return fmt.Sprintf("%s (%d%%)", formatBytes(saved), pct)
}

// formatBytes renders n as a compact human-readable size.
func formatBytes(n int64) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%dB", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(n)/1024)
	case n < 1024*1024*1024:
		return fmt.Sprintf("%.1fMB", float64(n)/(1024*1024))
	default:
		return fmt.Sprintf("%.2fGB", float64(n)/(1024*1024*1024))
	}
}

func formatTokens(n int64) string {
	if n < 10_000 {
		return fmt.Sprintf("%d", n)
	}
	if n < 1_000_000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%.2fM", float64(n)/1_000_000)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
