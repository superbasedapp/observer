package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/verbosity"
)

// newVerbosityCmd is the CLI surface for the Output Composition (Verbosity)
// feature (docs/plans/output-composition-verbosity-plan-2026-06-30.md).
// Read-only: it shows how much of a session's assistant output is narrative
// explanation vs shown (fenced) display artifacts vs authored code (file
// writes + shell commands), by language. Pure read-side over NODE-LOCAL
// rows — no proxy required.
func newVerbosityCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		by         string
		sinceDays  int
		unknownExt bool
	)
	cmd := &cobra.Command{
		Use:   "verbosity [session-id]",
		Short: "Show output composition: explanation vs code, by language",
		Long: "Breaks an assistant's output into narrative prose, shown (fenced) display\n" +
			"artifacts, and authored code — file writes and shell commands — resolved\n" +
			"by language. Shell/CLI counts as code. Byte counts are exact; the\n" +
			"code:explanation ratio answers \"am I getting code or explanation?\".\n\n" +
			"Pass a session id for one session, or --by model|project|day for an\n" +
			"aggregate across recent sessions.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if !unknownExt && by == "" && len(args) == 0 {
				return fmt.Errorf("provide a session id, or --by model|project|day, or --unknown-ext")
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			if unknownExt {
				led, err := st.LoadUnknownLedger(cmd.Context(), sinceDays)
				if err != nil {
					return err
				}
				if jsonOut {
					enc := json.NewEncoder(cmd.OutOrStdout())
					enc.SetIndent("", "  ")
					return enc.Encode(led)
				}
				printUnknownLedger(cmd, led)
				return nil
			}

			if by != "" {
				groups, err := st.LoadVerbosityAggregate(cmd.Context(), by, sinceDays)
				if err != nil {
					return err
				}
				if jsonOut {
					return printVerbosityAggregateJSON(cmd, by, groups)
				}
				printVerbosityAggregateText(cmd, by, sinceDays, groups)
				return nil
			}

			sessionID := args[0]
			b, err := st.LoadSessionVerbosity(cmd.Context(), sessionID)
			if err != nil {
				return fmt.Errorf("load verbosity for %q: %w", sessionID, err)
			}
			vc := loadVerbosityCost(cmd.Context(), st, acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default()), sessionID, b)
			if jsonOut {
				return printVerbosityJSON(cmd, b, vc)
			}
			printVerbosityText(cmd, sessionID, b, vc)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml (default: ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON instead of a table")
	cmd.Flags().StringVar(&by, "by", "", "aggregate dimension: model | project | day")
	cmd.Flags().IntVar(&sinceDays, "since-days", 30, "aggregate window in days (0 = all history)")
	cmd.Flags().BoolVar(&unknownExt, "unknown-ext", false, "list file extensions + fence tags the language table can't resolve (the §4 close-out ledger)")
	return cmd
}

// printUnknownLedger renders the §4 close-out ledger: which write/edit
// extensions and fence tags the verbosity language table fails to resolve,
// so they can be added to the table from real misses.
func printUnknownLedger(cmd *cobra.Command, led store.UnknownLedger) {
	out := cmd.OutOrStdout()
	rate := 0.0
	if led.TotalWrites > 0 {
		rate = 100 * float64(led.TotalWrites-led.ResolvedWrites) / float64(led.TotalWrites)
	}
	fmt.Fprintf(out, "Unknown-ext ledger\n\n")
	fmt.Fprintf(out, "  write/edit actions: %d total, %d resolved → %.2f%% unresolved (§4 target ≤ 1%%)\n\n",
		led.TotalWrites, led.ResolvedWrites, rate)

	if len(led.Extensions) == 0 {
		fmt.Fprintln(out, "  UNKNOWN EXTENSIONS: none ✓")
	} else {
		fmt.Fprintln(out, "  UNKNOWN EXTENSIONS (ext → write/edit count):")
		printSortedLangs(out, led.Extensions)
	}
	fmt.Fprintln(out)
	if len(led.FenceTags) == 0 {
		fmt.Fprintln(out, "  UNKNOWN FENCE TAGS: none ✓")
	} else {
		fmt.Fprintln(out, "  UNKNOWN FENCE TAGS (tag → bytes):")
		printSortedLangs(out, led.FenceTags)
	}
}

// printVerbosityAggregateText renders the aggregate rollup, sorted by code
// bytes descending.
func printVerbosityAggregateText(cmd *cobra.Command, by string, sinceDays int, groups []store.VerbosityGroup) {
	out := cmd.OutOrStdout()
	window := "all history"
	if sinceDays > 0 {
		window = fmt.Sprintf("last %d days", sinceDays)
	}
	fmt.Fprintf(out, "Output composition by %s (%s)\n\n", by, window)
	if len(groups) == 0 {
		fmt.Fprintln(out, "  (no assistant output captured in window)")
		return
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Breakdown.CodeBytes() > groups[j].Breakdown.CodeBytes()
	})
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "  %s\tCODE\tEXPLAIN\tCODE%%\tTOP LANGS\n", upperFirst(by))
	for _, g := range groups {
		b := g.Breakdown
		code, explain := b.CodeBytes(), b.ExplainBytes()
		total := code + explain
		codePct := 0.0
		if total > 0 {
			codePct = 100 * float64(code) / float64(total)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%.0f%%\t%s\n",
			truncMiddle(g.Key, 40), humanBytes(code), humanBytes(explain), codePct, topLangs(b, 3))
	}
	tw.Flush()
}

func printVerbosityAggregateJSON(cmd *cobra.Command, by string, groups []store.VerbosityGroup) error {
	rows := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		b := g.Breakdown
		rows = append(rows, map[string]any{
			"key":              g.Key,
			"code_bytes":       b.CodeBytes(),
			"explain_bytes":    b.ExplainBytes(),
			"code_by_language": b.CodeByLang(),
		})
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{"by": by, "groups": rows})
}

// topLangs renders the top-n code languages by bytes for the aggregate row.
func topLangs(b *verbosity.Breakdown, n int) string {
	type kv struct {
		k string
		v int64
	}
	var ls []kv
	for k, v := range b.CodeByLang() {
		ls = append(ls, kv{k, v})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].v > ls[j].v })
	parts := make([]string, 0, n)
	for i, x := range ls {
		if i >= n {
			break
		}
		parts = append(parts, fmt.Sprintf("%s %s", x.k, humanBytes(x.v)))
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, ", ")
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func truncMiddle(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 5 {
		return s[:n]
	}
	half := (n - 1) / 2
	return s[:half] + "…" + s[len(s)-(n-half-1):]
}

// verbCost is the resolved est token/$ split for a single session's CLI view
// (plan §7). nil when there's no priced model / no token rows — the surface
// then prints bytes only.
type verbCost struct {
	model               string
	output, reasoning   int64
	split               verbosity.TokenSplit
	codeUSD, explainUSD float64
	totalUSD            float64
}

// loadVerbosityCost resolves the est token/$ split for a session: model +
// summed output/reasoning tokens (store seam) → per-token output rate (cost
// engine) → apportioned split (pure verbosity). Returns nil — never an error —
// when any input is missing, so the CLI degrades to bytes-only.
func loadVerbosityCost(ctx context.Context, st *store.Store, engine *cost.Engine, sessionID string, b *verbosity.Breakdown) *verbCost {
	model, output, reasoning, err := st.SessionTokenTotals(ctx, sessionID)
	if err != nil || model == "" || output <= 0 || engine == nil {
		return nil
	}
	p, ok := engine.Lookup(model)
	if !ok || p.Output <= 0 {
		return nil
	}
	rate := p.Output / 1_000_000 // published per-million → per-token
	split := verbosity.EstimateTokens(b, output)
	code, explain, total := split.Cost(rate, reasoning)
	return &verbCost{
		model: model, output: output, reasoning: reasoning, split: split,
		codeUSD: code, explainUSD: explain, totalUSD: total,
	}
}

// humanUSD renders a dollar figure with extra precision for sub-dollar amounts
// (per-session verbosity costs are often cents).
func humanUSD(v float64) string {
	if v >= 1 {
		return fmt.Sprintf("$%.2f", v)
	}
	return fmt.Sprintf("$%.4f", v)
}

func printVerbosityText(cmd *cobra.Command, sessionID string, b *verbosity.Breakdown, vc *verbCost) {
	out := cmd.OutOrStdout()
	code := b.CodeBytes()
	explain := b.ExplainBytes()
	cats := b.ByCategory()
	total := int64(0)
	for _, v := range cats {
		total += v
	}

	fmt.Fprintf(out, "Output composition — session %s\n\n", sessionID)
	if total == 0 {
		fmt.Fprintln(out, "  (no assistant output captured for this session)")
		return
	}

	pct := func(n int64) float64 { return 100 * float64(n) / float64(total) }
	ratio := "n/a"
	if explain > 0 {
		ratio = fmt.Sprintf("%.2f", float64(code)/float64(explain))
	}
	fmt.Fprintf(out, "  HEADLINE   code %s (%.1f%%)  vs  explanation %s (%.1f%%)   code:explain = %s\n",
		humanBytes(code), pct(code), humanBytes(explain), pct(explain), ratio)
	if vc != nil {
		fmt.Fprintf(out, "  EST. COST  code %s  vs  explanation %s   total %s  (%s; est. — output tokens apportioned by content type)\n",
			humanUSD(vc.codeUSD), humanUSD(vc.explainUSD), humanUSD(vc.totalUSD), vc.model)
	}
	fmt.Fprintln(out)

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  CATEGORY\tBYTES\tSHARE")
	for _, c := range []verbosity.Category{verbosity.Code, verbosity.Prose, verbosity.Docs, verbosity.Config, verbosity.Data, verbosity.Unknown} {
		if cats[c] > 0 {
			fmt.Fprintf(tw, "  %s\t%s\t%.1f%%\n", c, humanBytes(cats[c]), pct(cats[c]))
		}
	}
	tw.Flush()

	fmt.Fprintf(out, "\n  CHANNELS\n")
	fmt.Fprintf(out, "    narrative prose        %s\n", humanBytes(b.Visible.NarrativeBytes))
	fmt.Fprintf(out, "    shown artifacts        %s  (%s untagged)\n", humanBytes(b.Visible.ArtifactBytes), humanBytes(b.Visible.ArtifactUntaggedBytes))
	fmt.Fprintf(out, "    code written to files  %s\n", humanBytes(sumMapVerb(b.Written)+sumMapVerb(b.WrittenUnknownExt)))
	fmt.Fprintf(out, "    shell commands         %s\n", humanBytes(sumMapVerb(b.Command)))

	if byLang := b.CodeByLang(); len(byLang) > 0 {
		fmt.Fprintf(out, "\n  CODE BY LANGUAGE\n")
		printSortedLangs(out, byLang)
	}
	if len(b.WrittenUnknownExt) > 0 {
		fmt.Fprintf(out, "\n  UNKNOWN-EXT LEDGER (extend the filetype table from these)\n")
		printSortedLangs(out, b.WrittenUnknownExt)
	}
}

func printSortedLangs(out interface{ Write([]byte) (int, error) }, m map[string]int64) {
	type kv struct {
		k string
		v int64
	}
	var ls []kv
	for k, v := range m {
		ls = append(ls, kv{k, v})
	}
	sort.Slice(ls, func(i, j int) bool { return ls[i].v > ls[j].v })
	for _, x := range ls {
		fmt.Fprintf(out, "    %-16s %s\n", x.k, humanBytes(x.v))
	}
}

func printVerbosityJSON(cmd *cobra.Command, b *verbosity.Breakdown, vc *verbCost) error {
	payload := map[string]any{
		"code_bytes":              b.CodeBytes(),
		"explain_bytes":           b.ExplainBytes(),
		"by_category":             b.ByCategory(),
		"narrative_bytes":         b.Visible.NarrativeBytes,
		"artifact_bytes":          b.Visible.ArtifactBytes,
		"artifact_untagged_bytes": b.Visible.ArtifactUntaggedBytes,
		"code_by_language":        b.CodeByLang(),
		"written_by_language":     b.Written,
		"command_by_shell":        b.Command,
		"unknown_ext":             b.WrittenUnknownExt,
	}
	if vc != nil {
		payload["cost_estimated"] = true
		payload["model"] = vc.model
		payload["est_output_tokens"] = vc.output
		payload["est_reasoning_tokens"] = vc.reasoning
		payload["est_code_tokens"] = vc.split.CodeTokens
		payload["est_explain_tokens"] = vc.split.ExplainTokens
		payload["est_code_usd"] = vc.codeUSD
		payload["est_explain_usd"] = vc.explainUSD
		payload["est_total_usd"] = vc.totalUSD
	} else {
		payload["cost_estimated"] = false
	}
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func sumMapVerb(m map[string]int64) int64 {
	var s int64
	for _, v := range m {
		s += v
	}
	return s
}
