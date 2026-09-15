package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cachewarm"
	"github.com/marmutapp/superbased-observer/internal/cachewarmsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newCacheStatusCmd builds the `observer cache-status` subcommand — the
// cache-expiry warning surface (Part A of
// docs/plans/cache-expiry-warning-and-keepwarm-plan-2026-06-25.md). It
// lists the live caches the cachetrack engine is modelling, how soon each
// expires, the dollars at risk if it goes cold, and (when keep-warm is in
// advise/enforce mode) the cheapest content-free lever to keep it warm.
//
// Read-only over node-local cache_entries; never pushed.
func newCacheStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		session    string
		all        bool
	)
	cmd := &cobra.Command{
		Use:   "cache-status",
		Short: "Show live prompt caches, time-to-expiry, value-at-risk, and keep-warm advice",
		Long: "Lists the prompt caches the cachetrack engine believes are live, with\n" +
			"a countdown to expiry and the dollars at risk if each goes cold (you\n" +
			"would pay a full cache re-write instead of a cheap read). When\n" +
			"[cachewarm.keepwarm] is in advise/enforce mode, each row also shows\n" +
			"the cheapest content-free lever to keep it warm (for Anthropic that is\n" +
			"usually 'switch to the 1h TTL tier').\n\n" +
			"By default only caches that are expiring soon or already cold are\n" +
			"shown; pass --all to include warm caches with comfortable headroom.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			if !cfg.CacheWarm.Enabled {
				fmt.Fprintln(cmd.OutOrStdout(), "cache-warm warnings are disabled ([cachewarm].enabled = false)")
				return nil
			}

			engine := acquireProcessCostEngine(cmd.Context(), cfg, database, slog.Default())
			statuses, err := cachewarmsvc.Load(cmd.Context(), store.New(database), engine.Lookup, cfg.CacheWarm, cachewarmsvc.LoadOpts{
				SessionID:   session,
				IncludeCold: true,
				Limit:       100,
			})
			if err != nil {
				return fmt.Errorf("cache-status: %w", err)
			}

			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{
					"enabled":       true,
					"keepwarm_mode": cfg.CacheWarm.Keepwarm.Mode,
					"windows":       statuses,
				})
			}

			printCacheStatus(cmd, statuses, all)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the raw JSON payload")
	cmd.Flags().StringVar(&session, "session", "", "Restrict to one session id")
	cmd.Flags().BoolVar(&all, "all", false, "Include warm caches with comfortable headroom (default: only soon/cold)")
	return cmd
}

// printCacheStatus renders the status table. all=false hides SeverityOK rows.
func printCacheStatus(cmd *cobra.Command, statuses []cachewarmsvc.WindowStatus, all bool) {
	out := cmd.OutOrStdout()
	shown := 0
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tEXPIRES IN\tMODEL\tTOKENS\tAT RISK\tSESSION\tKEEP-WARM")
	for _, st := range statuses {
		if !all && st.Severity == cachewarm.SeverityOK {
			continue
		}
		shown++
		fmt.Fprintf(
			tw, "%s\t%s\t%s\t%d\t$%.3f\t%s\t%s\n",
			st.Severity,
			expiryLabel(st.SecondsToExpiry, st.Estimated),
			st.Window.Model,
			st.Window.PrefixTokens,
			st.ValueAtRiskUSD,
			shortID(st.Window.SessionID),
			keepwarmLabel(st.Recommendation),
		)
	}
	tw.Flush()
	if shown == 0 {
		if all {
			fmt.Fprintln(out, "no live caches modelled — route the client through the proxy (observer init) to capture cache state")
		} else {
			fmt.Fprintln(out, "no caches expiring soon — all modelled caches have comfortable headroom (use --all to list them)")
		}
	}
}

// expiryLabel formats a seconds-to-expiry as a human countdown; a leading
// "~" marks an estimated (non-authoritative) expiry, "cold" for expired.
func expiryLabel(secs int64, estimated bool) string {
	prefix := ""
	if estimated {
		prefix = "~"
	}
	if secs <= 0 {
		return "cold"
	}
	d := time.Duration(secs) * time.Second
	if d >= time.Minute {
		return fmt.Sprintf("%s%dm%02ds", prefix, secs/60, secs%60)
	}
	return fmt.Sprintf("%s%ds", prefix, secs)
}

// keepwarmLabel renders the recommendation column.
func keepwarmLabel(rec cachewarm.Recommendation) string {
	switch rec.Action {
	case cachewarm.ActionUse1hTier:
		return "→ switch to 1h tier"
	case cachewarm.ActionPatchTTL:
		return "→ extend TTL (API)"
	case cachewarm.ActionReplayPing:
		return "→ proxy will refresh"
	default:
		return "—"
	}
}

// shortID truncates a long session id for table display.
func shortID(id string) string {
	if len(id) <= 12 {
		return id
	}
	return id[:12] + "…"
}
