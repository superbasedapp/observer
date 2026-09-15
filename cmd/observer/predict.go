package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newPredictCmd is the CLI surface for the Next-Message Cost & Limit
// Predictor (docs/cost-predictor.md). Read-only: it estimates the next
// message's cost from the session's observed token shape and shows the
// proxy-captured 5h/weekly limit gauge when available.
func newPredictCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "predict <session-id>",
		Short: "Estimate the next message's cost (low/mid/high) + 5h/weekly limit for a session",
		Long: "Estimates what your NEXT message to a session will cost on its current\n" +
			"model, as a low / typical / high band over the message's likely turn\n" +
			"fan-out. Pure read-side math over token_usage — no proxy required for\n" +
			"the cost estimate. The 5-hour / weekly subscription-window gauge needs\n" +
			"the client routed through the observer proxy (those numbers live only\n" +
			"in upstream response headers).",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sessionID := args[0]
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)

			shape, err := st.LoadSessionShape(cmd.Context(), sessionID)
			if err != nil {
				return fmt.Errorf("load session %q: %w", sessionID, err)
			}
			if shape.Model == "" {
				return fmt.Errorf("session %q has no model/token data — route the client through the proxy (observer init) to capture cost", sessionID)
			}

			young := predictIntDefault(cfg.Predict.YoungSessionMessages, 3)
			defaultTurns := predictIntDefault(cfg.Predict.DefaultTurnsPerMessage, 12)
			priorWindow := predictIntDefault(cfg.Predict.PriorWindowDays, 30)

			var prior []int
			if len(shape.TurnsPerMessage) == 0 || shape.ObservedMessages < young {
				prior, _ = st.LoadToolProjectPrior(cmd.Context(), shape.Tool, shape.ProjectID, priorWindow)
			}

			engine := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
			rates, ok := predictRatePair(engine, shape.Model)
			if !ok {
				return fmt.Errorf("model %q has no pricing entry", shape.Model)
			}

			est := predict.Estimate(predict.EstimateInput{
				Model:                shape.Model,
				Rates:                rates,
				PrefixTokens:         shape.PrefixTokens,
				TurnSamples:          shape.TurnSamples,
				TurnsPerMessage:      shape.TurnsPerMessage,
				ObservedMessages:     shape.ObservedMessages,
				YoungThreshold:       young,
				PriorTurnsPerMessage: prior,
				DefaultTurns:         defaultTurns,
			})

			// Attribute the window to the tool that observed it (not a
			// node-wide per-provider read), so a tool with no proxied
			// subscription window doesn't inherit another tool's gauge.
			snap, snapOK, _ := st.LatestLimitSnapshotForTool(cmd.Context(), predictProviderForTool(shape.Tool), shape.Tool)

			// Transcript fallback: providers without subscription-window
			// headers (codex) capture their 5h/weekly state in their own
			// session log (token_count rate_limits → ActionRateLimit
			// rows). Synthesize a snapshot from those when the header path
			// has no usable window, so the same printer renders it.
			if !snapOK || (snap.Window5hUtil == nil && snap.Window7dUtil == nil) {
				if w, found, werr := st.LatestRateLimitWindows(cmd.Context(), shape.Tool, sessionID); werr == nil && found &&
					(w.Window5hUtil != nil || w.Window7dUtil != nil) {
					snap = models.LimitSnapshot{
						Provider:      predictProviderForTool(shape.Tool),
						SessionID:     sessionID,
						ObservedAt:    w.ObservedAt,
						Window5hUtil:  w.Window5hUtil,
						Window5hReset: w.Window5hReset,
						Window7dUtil:  w.Window7dUtil,
						Window7dReset: w.Window7dReset,
						Status:        w.Status,
					}
					snapOK = true
				}
			}

			if jsonOut {
				out := map[string]any{"session_id": sessionID, "estimate": est}
				if snapOK {
					out["limit"] = snap
				}
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			printPredict(cmd, sessionID, shape, est, snap, snapOK)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON instead of a table")
	return cmd
}

func predictIntDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// predictRatePair resolves a model id to predict.RatePair in per-token
// units (cost.Pricing stores $/million; divide by 1e6 — the same
// conversion the dashboard's lookupRates does, see the v1.6.10
// per-token-scale regression note).
func predictRatePair(engine *cost.Engine, model string) (predict.RatePair, bool) {
	p, ok := engine.Lookup(model)
	if !ok {
		return predict.RatePair{}, false
	}
	const perMillion = 1_000_000.0
	return predict.RatePair{
		Input:          p.Input / perMillion,
		Output:         p.Output / perMillion,
		CacheRead:      p.CacheRead / perMillion,
		CacheCreation:  p.CacheCreation / perMillion,
		FastMultiplier: p.FastMultiplier,
	}, true
}

// predictProviderForTool mirrors the dashboard's tool→provider mapping
// for the limit-snapshot lookup.
func predictProviderForTool(tool string) string {
	switch tool {
	case "codex", "copilot", "copilot-cli":
		return "openai"
	default:
		return "anthropic"
	}
}

func printPredict(cmd *cobra.Command, sessionID string, shape store.PredictShape, est predict.EstimateResult, snap models.LimitSnapshot, snapOK bool) {
	w := cmd.OutOrStdout()
	fmt.Fprintf(w, "Next-message cost — session %s\n", sessionID)
	fmt.Fprintf(w, "model %s · cached prefix %s tok · fan-out %s", shape.Model, fmtTokens(est.PrefixTokens), est.TurnsTier)
	if est.TurnsTier == predict.TurnsObserved {
		fmt.Fprintf(w, " (%d messages observed)", est.SampleMessages)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "BAND\tCOST\tTURNS\tOUT/TURN\tBILLED TOK\tOF WHICH NEW")
	predictBandRow(tw, "low (quick)", est.Low, est.PrefixTokens)
	predictBandRow(tw, "mid (typical)", est.Mid, est.PrefixTokens)
	predictBandRow(tw, "high (agentic)", est.High, est.PrefixTokens)
	tw.Flush()
	fmt.Fprintf(w, "\nbilled tok = turns × (cached prefix + fresh input + output) — the same dimensions the cost\n"+
		"charges for, so the cached prefix is counted once per turn. It is throughput, NOT context size,\n"+
		"and it excludes cache-WRITE tokens (not modelled), so it is a lower bound.\n")

	if len(est.Warnings) > 0 {
		fmt.Fprintf(w, "\nnotes: ")
		for i, warn := range est.Warnings {
			if i > 0 {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, "%s", warn)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "\n5-hour / weekly limit:")
	if !snapOK {
		fmt.Fprintln(w, "  unavailable — route this client through the observer proxy (observer init) to capture rate-limit windows.")
		return
	}
	if snap.Window5hUtil == nil && snap.Window7dUtil == nil {
		fmt.Fprintln(w, "  this provider exposes no 5h/weekly subscription window in its headers.")
		return
	}
	fmt.Fprintf(w, "  observed %s ago\n", humanizeCLIAge(time.Since(snap.ObservedAt)))
	if snap.Window5hUtil != nil {
		fmt.Fprintf(w, "  5-hour window:  %d%% left%s\n", 100-int(*snap.Window5hUtil*100), resetSuffix(snap.Window5hReset))
	}
	if snap.Window7dUtil != nil {
		fmt.Fprintf(w, "  weekly cap:     %d%% left%s\n", 100-int(*snap.Window7dUtil*100), resetSuffix(snap.Window7dReset))
	}
}

// predictBandRow prints one band row, including the billed-token figure
// — the token counterpart of the priced formula (per_turn = P·r_cache_read
// + S·r_input + O·r_output; message = T × per_turn). It counts exactly
// what the price counts: the cached prefix P is re-read, and billed at
// the cache-read rate, on EVERY one of the T turns, so it is counted T
// times. The "of which new" column is T × (S + O) — the genuinely-new
// half — so the cached dominance stays visible instead of hiding inside
// one opaque total. Cache-WRITE tokens are not modelled by the
// estimator and so are not counted here either.
func predictBandRow(tw *tabwriter.Writer, label string, b predict.Band, prefix int64) {
	turns := max(0, b.Turns)
	cached := int64(math.Round(turns * float64(max(0, prefix))))
	fresh := int64(math.Round(turns * float64(max(0, b.FreshInput)+max(0, b.Output))))
	fmt.Fprintf(tw, "%s\t$%.2f\t%.1f\t%d\t%s\t%s\n",
		label, b.MessageUSD, b.Turns, b.Output, fmtTokens(cached+fresh), fmtTokens(fresh))
}

func resetSuffix(reset *int64) string {
	if reset == nil {
		return ""
	}
	d := time.Until(time.Unix(*reset, 0))
	if d <= 0 {
		return " (resets now)"
	}
	return fmt.Sprintf(" (resets in %s)", humanizeCLIAge(d))
}

func humanizeCLIAge(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func fmtTokens(n int64) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}
