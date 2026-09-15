package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	adapterdefaults "github.com/marmutapp/superbased-observer/internal/adapter/defaults"
	"github.com/marmutapp/superbased-observer/internal/cachewarmsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/predict"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// handoffRunner assembles the handoffsvc dependency set once and returns
// the run closure every handoff surface shares (CLI here; the dashboard's
// Options.BuildHandoff and the MCP continue_session tool get the same
// closure injected — one seam, no adapter imports past cmd).
func handoffRunner(cfg config.Config, database *sql.DB) func(context.Context, handoffsvc.Request) (handoffsvc.Result, error) {
	deps := handoffDeps(cfg, database)
	return func(ctx context.Context, req handoffsvc.Request) (handoffsvc.Result, error) {
		return handoffsvc.Build(ctx, deps, req)
	}
}

// messageReader assembles the handoffsvc dependency set once and returns
// the get_session_message closure the MCP tool uses — re-read one
// un-excerpted message of a source session on demand. Same deps as the
// handoff runner; no adapter imports leak past cmd.
func messageReader(cfg config.Config, database *sql.DB) func(context.Context, handoffsvc.MessageRequest) (handoffsvc.MessageResult, error) {
	deps := handoffDeps(cfg, database)
	return func(ctx context.Context, req handoffsvc.MessageRequest) (handoffsvc.MessageResult, error) {
		return handoffsvc.ReadMessage(ctx, deps, req)
	}
}

// handoffDeps assembles the shared handoffsvc dependency set (used by the
// CLI run closure, the target-session linker sweep, and — via the same
// closure — the dashboard and MCP surfaces). One seam, no adapter imports
// leaking past cmd.
func handoffDeps(cfg config.Config, database *sql.DB) handoffsvc.Deps {
	engine := acquireProcessCostEngine(context.Background(), cfg, database, slog.Default())
	scrubber := scrub.New()
	return handoffsvc.Deps{
		Store:    store.New(database),
		Cfg:      cfg.Handoff,
		Adapters: adapterdefaults.Adapters(),
		Price: func(model string, tokens int64) float64 {
			p, ok := engine.Lookup(model)
			if !ok {
				return 0
			}
			return float64(tokens) * p.Input / 1_000_000
		},
		Scrub:              scrubber.String,
		Stay:               stayResolver(cfg, database),
		ResolveTargetModel: newHandoffTargetResolver(),
	}
}

// stayResolver composes the plan §9 stay-option: the source session's
// next-message cost band (internal/predict, same 3-tier ladder as
// `observer predict`) plus the live cache value-at-risk a move abandons
// (internal/cachewarmsvc). Each half is grounded independently; ok=false
// only when neither has data.
func stayResolver(cfg config.Config, database *sql.DB) func(context.Context, string) (handoff.StayEstimate, bool) {
	engine := acquireProcessCostEngine(context.Background(), cfg, database, slog.Default())
	st := store.New(database)
	return func(ctx context.Context, sessionID string) (handoff.StayEstimate, bool) {
		var out handoff.StayEstimate
		if shape, err := st.LoadSessionShape(ctx, sessionID); err == nil && shape.Model != "" {
			if rates, ok := predictRatePair(engine, shape.Model); ok {
				young := predictIntDefault(cfg.Predict.YoungSessionMessages, 3)
				var prior []int
				if len(shape.TurnsPerMessage) == 0 || shape.ObservedMessages < young {
					prior, _ = st.LoadToolProjectPrior(ctx, shape.Tool, shape.ProjectID,
						predictIntDefault(cfg.Predict.PriorWindowDays, 30))
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
					DefaultTurns:         predictIntDefault(cfg.Predict.DefaultTurnsPerMessage, 12),
				})
				if est.HasEstimate {
					out.HasBand = true
					out.NextMessageLowUSD = est.Low.MessageUSD
					out.NextMessageMidUSD = est.Mid.MessageUSD
					out.NextMessageHighUSD = est.High.MessageUSD
				}
			}
		}
		if statuses, err := cachewarmsvc.Load(ctx, st, engine.Lookup, cfg.CacheWarm,
			cachewarmsvc.LoadOpts{SessionID: sessionID}); err == nil && len(statuses) > 0 {
			var sum float64
			for _, w := range statuses {
				sum += w.ValueAtRiskUSD
			}
			out.CacheValueAtRiskUSD = sum
			out.HasCacheValue = true
		}
		return out, out.HasBand || out.HasCacheValue
	}
}

// newHandoffCmd is the CLI surface for session handoff / continue-anywhere
// (docs/session-handoff.md). It distills a session from any adapter into a
// scrubbed HANDOFF-*.md the user opens in the target tool, priced per
// carry mode. Fork defaults to the last message; --from-message /
// --from-time cut earlier (snapping backward to a stable boundary).
func newHandoffCmd() *cobra.Command {
	var (
		configPath  string
		targetTool  string
		targetModel string
		fromMessage int
		fromTime    string
		carry       string
		deliver     string
		outPath     string
		dryRun      bool
	)
	cmd := &cobra.Command{
		Use:   "handoff <session-id>",
		Short: "Continue a session in another AI tool (distilled, priced handover)",
		Long: "Re-reads the session's conversation from the source tool's own files,\n" +
			"distills it into a handover document, prices every carry option at the\n" +
			"target model, and writes HANDOFF-<id>.md into the project root for the\n" +
			"target tool to read. The provider cache cannot move with the session —\n" +
			"the estimate shows what rehydration costs instead.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			fork, err := forkFromFlags(fromMessage, fromTime)
			if err != nil {
				return err
			}

			var delivery integration.InjectKind
			switch deliver {
			case "", "file":
				delivery = integration.InjectFile
			case "hook":
				if targetTool == "" {
					return fmt.Errorf("--deliver hook requires --to (the target tool to arm)")
				}
				delivery = integration.InjectHook
			default:
				return fmt.Errorf("--deliver must be file or hook (mcp/prompt are separate surfaces)")
			}

			run := handoffRunner(cfg, database)
			res, err := run(cmd.Context(), handoffsvc.Request{
				SessionID:   args[0],
				TargetTool:  targetTool,
				TargetModel: targetModel,
				Fork:        fork,
				Carry:       handoff.CarryMode(carry),
				Delivery:    delivery,
				OutPath:     outPath,
				DryRun:      dryRun,
			})
			if err != nil {
				return err
			}
			printHandoff(cmd, args[0], res, dryRun)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&targetTool, "to", "", "Target tool (e.g. codex, claude-code, cursor)")
	cmd.Flags().StringVar(&targetModel, "target-model", "", "Model to price the migration at (default: the source session's model)")
	cmd.Flags().IntVar(&fromMessage, "from-message", 0, "Fork after this 1-based message of the normalized transcript (default: last message)")
	cmd.Flags().StringVar(&fromTime, "from-time", "", "Fork after the last message at or before this RFC3339 time")
	cmd.Flags().StringVar(&carry, "carry", "", "Carry mode: metadata|distilled|distilled_tail|full|full_cache (default from [handoff] config)")
	cmd.Flags().StringVar(&deliver, "deliver", "file", "Delivery lane: file (write HANDOFF-*.md) or hook (arm the next --to session in this project)")
	cmd.Flags().StringVar(&outPath, "out", "", "Write the handover doc to this path instead of <project>/HANDOFF-<id>.md")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the estimate only; write nothing")

	cmd.AddCommand(newHandoffListCmd())
	return cmd
}

func newHandoffListCmd() *cobra.Command {
	var (
		configPath string
		limit      int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recorded handoffs (newest first)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			// Best-effort: freshen target-session links before listing, so
			// the TARGET column reflects sessions that booted a handover
			// since the last run. Time-boxed and error-swallowed — a slow or
			// failing sweep must never block `handoff list`.
			if cfg.Handoff.Enabled {
				sweepCtx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
				n, _ := handoffsvc.LinkTargetSessions(sweepCtx, handoffDeps(cfg, database), handoffsvc.DefaultLinkWindow)
				cancel()
				if n > 0 {
					fmt.Fprintf(cmd.OutOrStdout(), "linked %d handoff(s) to their target session\n", n)
				}
			}

			rows, err := store.New(database).ListHandoffs(cmd.Context(), limit)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no handoffs recorded yet — run `observer handoff <session-id> --to <tool>`")
				return nil
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tWHEN\tFROM\tTO\tCARRY\tFORK\tTARGET\tDOC")
			for _, r := range rows {
				forkCol := r.ForkKind
				if r.ForkMessageIndex > 0 {
					forkCol = fmt.Sprintf("msg %d", r.ForkMessageIndex)
				}
				target := "-"
				if r.TargetSessionID != "" {
					target = shortSessionID(r.TargetSessionID)
				}
				fmt.Fprintf(tw, "%d\t%s\t%s (%s)\t%s\t%s\t%s\t%s\t%s\n",
					r.ID, r.CreatedAt.Format("2006-01-02 15:04"),
					shortSessionID(r.SourceSessionID), r.SourceTool,
					r.TargetTool, r.CarryMode, forkCol, target, r.DeliveryRef)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().IntVar(&limit, "limit", 20, "Rows to show")
	return cmd
}

func printHandoff(cmd *cobra.Command, sessionID string, res handoffsvc.Result, dryRun bool) {
	w := cmd.OutOrStdout()
	if res.Fork.Snapped {
		fmt.Fprintf(w, "fork: %s\n", res.Fork.Reason)
	}
	if res.DegradeReason != "" {
		fmt.Fprintf(w, "note: %s\n", res.DegradeReason)
	}

	fmt.Fprintf(w, "carry options priced at %s (fork share %.0f%%):\n", res.TargetModel, res.Estimate.ForkShare*100)
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CARRY\tTOKENS\tCOST\tNOTE")
	for _, r := range res.Estimate.Rows {
		marker := " "
		if r.Mode == res.CarryUsed {
			marker = "*"
		}
		fmt.Fprintf(tw, "%s%s\t%s\t$%.2f\t%s\n", marker, r.Mode, fmtTokens(r.Tokens), r.CostUSD, r.Note)
	}
	tw.Flush()

	if stay := res.Estimate.Stay; stay != nil {
		fmt.Fprint(w, "stay option (source tool):")
		if stay.HasBand {
			fmt.Fprintf(w, " next message ≈ $%.2f / $%.2f / $%.2f (low/typical/high)",
				stay.NextMessageLowUSD, stay.NextMessageMidUSD, stay.NextMessageHighUSD)
		}
		if stay.HasCacheValue {
			if stay.HasBand {
				fmt.Fprint(w, ";")
			}
			fmt.Fprintf(w, " live cache value at risk if you leave: $%.2f", stay.CacheValueAtRiskUSD)
		}
		fmt.Fprintln(w)
	}

	if dryRun {
		fmt.Fprintln(w, "\ndry run — nothing written. Re-run without --dry-run to produce the handover doc.")
		return
	}
	fmt.Fprintf(w, "\nhandover written: %s (%s tokens, carry %s)\n", res.DocPath, fmtTokens(handoff.TokenEstimate(res.Doc)), res.CarryUsed)
	if res.Delivery == integration.InjectHook && !res.HookExpiresAt.IsZero() {
		fmt.Fprintf(w, "hook armed for %s until %s — the next %s session in this project starts with the handover in context (one-shot).\n",
			res.TargetTool, res.HookExpiresAt.Local().Format("2006-01-02 15:04"), res.TargetTool)
	} else {
		fmt.Fprintln(w, "open the target tool in this project and ask it to read that file.")
		if launcher := continueFromLauncher(res.TargetTool); launcher != "" {
			fmt.Fprintf(w, "tip: `%s --continue-from %s` seeds the handover as the first prompt automatically.\n",
				launcher, sessionID)
		}
	}
	if res.GitignoreHint {
		fmt.Fprintln(w, "hint: add `HANDOFF-*.md` to .gitignore — the handover carries conversation excerpts.")
	}
}

func shortSessionID(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}
