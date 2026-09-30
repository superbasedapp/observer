package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/intelligence/scoring"
)

// newScoreCmd wires `observer score` — computes per-session quality scores
// (spec §15.2) and writes them back into the sessions table.
func newScoreCmd() *cobra.Command {
	var (
		configPath  string
		sessionID   string
		all         bool
		idleMinutes int
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Compute session quality scores and persist into sessions table",
		Long: "Walks sessions (or a single --session id) and writes quality_score,\n" +
			"redundancy_ratio, error_rate, turns_to_first_edit, onboarding_cost,\n" +
			"and retry_cost_tokens. By default only scores sessions that don't\n" +
			"already have a score; pass --all to recompute everything.",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			s := scoring.New(database)
			if sessionID != "" {
				sc, err := s.ScoreSession(cmd.Context(), sessionID)
				if err != nil {
					return err
				}
				if sc.TotalActions == 0 {
					return fmt.Errorf("session %q has no actions", sessionID)
				}
				if err := s.Write(cmd.Context(), sc); err != nil {
					return err
				}
				return emitOne(cmd.OutOrStdout(), sc, jsonOut)
			}

			res, err := s.BatchScore(cmd.Context(), scoring.BatchOptions{
				OnlyUnscored: !all,
				IdleAtLeast:  time.Duration(idleMinutes) * time.Minute,
			})
			if err != nil {
				return err
			}
			return emitBatch(cmd.OutOrStdout(), res, jsonOut)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().StringVar(&sessionID, "session", "", "Score a single session id (overrides --all)")
	cmd.Flags().BoolVar(&all, "all", false, "Re-score every session, not only unscored ones")
	cmd.Flags().IntVar(&idleMinutes, "idle-minutes", 0, "Skip sessions whose latest action is within N minutes of now")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	return cmd
}

func emitOne(w interface{ Write([]byte) (int, error) }, sc scoring.Scores, jsonOut bool) error {
	if jsonOut {
		body, _ := json.MarshalIndent(sc, "", "  ")
		body = append(body, '\n')
		_, err := w.Write(body)
		return err
	}
	if _, err := fmt.Fprintf(w,
		"session %s: quality=%.3f redundancy=%.3f error_rate=%.3f exploration=%.3f continuity=%.3f\n"+
			"  actions=%d failures=%d stale_reads=%d reads=%d edits=%d turns_to_first_edit=%d onboarding_tokens=%d retry_tokens=%d\n",
		sc.SessionID, sc.QualityScore, sc.RedundancyRatio, sc.ErrorRate,
		sc.ExplorationEff, sc.ContinuityScore,
		sc.TotalActions, sc.TotalFailures, sc.StaleReads,
		sc.DistinctFilesRead, sc.DistinctFilesEdit, sc.TurnsToFirstEdit,
		sc.OnboardingCost, sc.RetryCostTokens); err != nil {
		return err
	}
	return nil
}

func emitBatch(w interface{ Write([]byte) (int, error) }, res scoring.BatchResult, jsonOut bool) error {
	if jsonOut {
		body, _ := json.MarshalIndent(res, "", "  ")
		body = append(body, '\n')
		_, err := w.Write(body)
		return err
	}
	if _, err := fmt.Fprintf(w,
		"scored %d session(s) in %dms (considered %d, skipped %d, errors %d)\n",
		res.Scored, res.DurationMs, res.Considered, res.Skipped, res.Errors); err != nil {
		return err
	}
	if res.Errors > 0 {
		return errors.New("some sessions failed to score — rerun with --session <id> for details")
	}
	return nil
}

// sessionScoreLoop is the daemon-lifetime driver for scoring.AutoScorer
// (spec §15.2 "computed when session ends"). Same shape as commitScanLoop:
// open its own config+DB, bail out quietly when [intelligence.scoring].auto is
// off, and run the scorer for the rest of the daemon's life. Fail-soft: a
// failed pass is logged and retried, never cancels proxy/watcher/dashboard.
func sessionScoreLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	sc := cfg.Intelligence.Scoring
	if !sc.Auto {
		return
	}
	scoring.NewAuto(scoring.New(database), scoring.AutoOptions{
		Interval:   sc.Interval(),
		Idle:       sc.Idle(),
		MaxPerTick: sc.PassLimit(),
		Lookback:   scoring.DefaultAutoLookback,
		StartDelay: scoring.DefaultAutoStartDelay,
		Logger:     newLogger(cfg.Observer.LogLevel),
	}).Run(ctx)
}
