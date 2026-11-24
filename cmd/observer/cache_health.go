package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/cachetrack"
)

// newCacheHealthCmd builds the `observer cache-health` subcommand
// that computes the §10 mispredict-rate gate over persisted
// cache_events. The P0 exit gate per spec §20 is "≥95% of turns
// correctly predicted hit-vs-write on live Tier-1 claude-code
// traffic over ≥3 sessions / ≥200 turns" — this command surfaces
// both the rate and the denominator so the operator can decide
// whether the soak qualifies for sign-off.
//
// Denominator EXCLUDES KindBelowMin / KindReanchor /
// KindMispredict / KindCompactionReset per the C4 doc note +
// reconcile.go::bucketOf — they are not predictions in the
// hit-vs-write sense.
func newCacheHealthCmd() *cobra.Command {
	var (
		configPath          string
		jsonOut             bool
		minEvents           int
		maxRate             float64
		maxRewriteReadRatio float64
		maxCauseShare       float64
	)
	cmd := &cobra.Command{
		Use:   "cache-health",
		Short: "Report the §10 cache mispredict-rate gate over persisted cache_events",
		Long: "Computes the cachetrack reconciliation health metric per spec §10:\n" +
			"the fraction of non-skipped cache_events whose kind is 'mispredict'.\n" +
			"Default gate: ≤5% rate over ≥200 graded events.\n" +
			"Exits 0 when the gate passes; non-zero otherwise.\n\n" +
			"Two secondary validations also run (informational; neither\n" +
			"changes pass/fail):\n" +
			"  - read:write consistency - any *_rewrite event with\n" +
			"    tokens_read > N× tokens_written is mechanically\n" +
			"    inconsistent with a real cache invalidation. This\n" +
			"    catches mislabeled causes even when the cause\n" +
			"    isn't dominant.\n" +
			"  - cause concentration - when any single non-suffix_growth\n" +
			"    cause exceeds the share threshold, surface as WARN.\n" +
			"    Catches over-firing rules that the rate gate is blind\n" +
			"    to (when both predicted and observed land in the same\n" +
			"    hit-vs-write bucket).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			report, err := computeCacheHealth(cmd.Context(), database, cacheHealthThresholds{
				MinEvents:           minEvents,
				MaxRate:             maxRate,
				MaxRewriteReadRatio: maxRewriteReadRatio,
				MaxCauseShare:       maxCauseShare,
			})
			if err != nil {
				return err
			}
			if jsonOut {
				body, _ := json.MarshalIndent(report, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
			} else {
				printCacheHealth(cmd.OutOrStdout(), report)
			}
			if !report.GatePassed {
				return errors.New("§10 mispredict-rate gate did not pass")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit machine-readable JSON instead of formatted output")
	cmd.Flags().IntVar(&minEvents, "min-events", 200, "Minimum graded events required for the gate to PASS")
	cmd.Flags().Float64Var(&maxRate, "max-rate", 0.05, "Maximum mispredict rate allowed for the gate to PASS (0.05 = 5%)")
	cmd.Flags().Float64Var(&maxRewriteReadRatio, "max-rewrite-read-ratio", 3.0, "Read:write ratio over which an invalidation/expiry/model-switch/compaction-reset event is flagged as mechanically inconsistent (informational)")
	cmd.Flags().Float64Var(&maxCauseShare, "max-cause-share", 0.80, "Share threshold (0..1) over which any non-suffix_growth cause is flagged as dominating graded events (informational)")
	return cmd
}

// cacheHealthThresholds groups the four operator-tunable inputs to
// computeCacheHealth. Bundled so the call signature stays narrow
// even as more checks land.
type cacheHealthThresholds struct {
	MinEvents           int
	MaxRate             float64
	MaxRewriteReadRatio float64
	MaxCauseShare       float64
}

// CacheHealthReport is the §10 gate result.
type CacheHealthReport struct {
	TotalEvents    int                `json:"total_events"`
	GradedEvents   int                `json:"graded_events"`
	Mispredicts    int                `json:"mispredicts"`
	Rate           float64            `json:"mispredict_rate"`
	MinEvents      int                `json:"min_events_threshold"`
	MaxRate        float64            `json:"max_rate_threshold"`
	GatePassed     bool               `json:"gate_passed"`
	UniqueSessions int                `json:"unique_sessions"`
	PerSession     []SessionHealthRow `json:"per_session,omitempty"`
	// CauseBreakdown is a (cause, count) rollup over all
	// persisted cache_events — lets the operator see whether
	// system_changed / model_changed / ttl_expired etc. are
	// firing at expected frequencies even when the gate passes.
	CauseBreakdown []CauseCount `json:"cause_breakdown,omitempty"`
	// MispredictEvents is the per-event detail for every
	// mispredict the corpus contains. Lets a failing or
	// marginal gate be diagnosed BY CAUSE (e.g. "12 mispredicts
	// all on cause=block_diverged → message canonicalization
	// drift") rather than just a bare rate number.
	MispredictEvents []MispredictEvent `json:"mispredict_events,omitempty"`

	// InconsistentRewriteEvents lists *_rewrite/compaction_reset
	// events whose read:write shape is mechanically inconsistent
	// with a real cache invalidation. A real invalidation rebuilds
	// a cold prefix → tokens_read ≈ 0 and tokens_written ≈ prefix
	// size. Observed tokens_read > MaxRewriteReadRatio ×
	// tokens_written means the provider's cache HIT on the prefix
	// (small tail rewrite), so the kind/cause is mislabeled —
	// e.g. the f81cec3f soak surfaced 198 "system_changed" events
	// with avg read=45,693 / avg write=1,437 (32:1) → really
	// suffix_growth, not system invalidation. The §10 rate gate
	// is blind to this class because both predicted=hit and
	// observed=write fall in the same hit-vs-write bucket. This
	// list is the primary secondary check; emitted regardless
	// of gate pass/fail.
	InconsistentRewriteEvents []InconsistentRewriteEvent `json:"inconsistent_rewrite_events,omitempty"`
	// InconsistentRewriteThreshold echoes the threshold actually
	// used so the operator can interpret the list without
	// reaching for the flag set.
	InconsistentRewriteThreshold float64 `json:"inconsistent_rewrite_threshold,omitempty"`

	// DominantCause is non-nil when one non-suffix_growth cause
	// exceeds the share threshold over GradedEvents. A dominant
	// cause is suspicious — a healthy soak's distribution should
	// be wide; one cause at >80% suggests an over-firing rule
	// (the f81cec3f soak's 198/201 system_changed = 98.5% being
	// the canonical example). Informational WARN; does not change
	// the gate verdict.
	DominantCause *DominantCauseRow `json:"dominant_cause,omitempty"`
	MaxCauseShare float64           `json:"max_cause_share_threshold,omitempty"`

	// BucketMispredicts is the §15.3 (c)-phase-2 G2 instrumentation
	// surface: the count of persisted (predicted_kind, kind) pairs
	// that fold into different non-skipped buckets per
	// cachetrack.BucketMismatch. This is the rate-blind regression
	// surface — a Sonnet growth-turn where the engine predicted Hit
	// but observed Write fires here while §10's MispredictRateGraded
	// (which keys on outcome.Kind == KindMispredict) stays flat.
	// Phase-4 soak gates against this count.
	BucketMispredicts int `json:"bucket_mispredicts"`
	// BucketMispredictsPerSession breaks BucketMispredicts down by
	// session so an operator can identify which sessions are
	// driving any growth-turn regression instead of inferring from
	// the aggregate.
	BucketMispredictsPerSession []SessionBucketRow `json:"bucket_mispredicts_per_session,omitempty"`
}

// SessionBucketRow is the per-session BucketMispredicts row.
type SessionBucketRow struct {
	SessionID         string `json:"session_id"`
	BucketMispredicts int    `json:"bucket_mispredicts"`
}

// SessionHealthRow is per-session breakdown for operator review.
type SessionHealthRow struct {
	SessionID    string  `json:"session_id"`
	GradedEvents int     `json:"graded_events"`
	Mispredicts  int     `json:"mispredicts"`
	Rate         float64 `json:"mispredict_rate"`
}

// CauseCount rolls (cause, count) for the whole corpus —
// surfaces operator-relevant frequencies (system_changed,
// model_changed, ttl_expired) at a glance.
type CauseCount struct {
	Cause string `json:"cause"`
	Count int    `json:"count"`
}

// MispredictEvent is one persisted-mispredict row with the
// fields a diagnostician needs: the actual Kind, the diagnostic
// Cause, the engine's pre-observation PredictedKind, plus the
// session anchor + timestamp for cross-referencing logs.
//
// ZeroUsage flags events that the rate denominator excluded
// because both tokens_read and tokens_written were zero — the
// turn was observationally vacant and can't grade the engine's
// prediction. These stay in the list for diagnostic visibility
// (the operator can see "yes, the row-12 fallthrough fired
// here, but it wasn't counted against the rate"); the
// Mispredicts count above only reflects events where ZeroUsage
// = false.
type MispredictEvent struct {
	SessionID     string `json:"session_id"`
	Timestamp     string `json:"timestamp"`
	Model         string `json:"model"`
	Kind          string `json:"kind"`
	Cause         string `json:"cause"`
	PredictedKind string `json:"predicted_kind"`
	ZeroUsage     bool   `json:"zero_usage,omitempty"`
}

// InconsistentRewriteEvent is one *_rewrite (or compaction_reset)
// event whose read:write shape is mechanically inconsistent with
// a real cache invalidation: tokens_read > N× tokens_written.
// Real invalidations rebuild cold prefixes (read ≈ 0); a read >>
// write shape means the cache HIT on the prefix and only the tail
// was rewritten — the cause is mislabeled (typically suffix_growth
// is the real story).
type InconsistentRewriteEvent struct {
	SessionID     string  `json:"session_id"`
	Timestamp     string  `json:"timestamp"`
	Model         string  `json:"model"`
	Kind          string  `json:"kind"`
	Cause         string  `json:"cause"`
	TokensRead    int64   `json:"tokens_read"`
	TokensWritten int64   `json:"tokens_written"`
	Ratio         float64 `json:"ratio"`
}

// DominantCauseRow names the non-suffix_growth cause that exceeded
// the share threshold over GradedEvents. Count is the absolute
// number of events; Share is Count/GradedEvents (0..1).
type DominantCauseRow struct {
	Cause string  `json:"cause"`
	Count int     `json:"count"`
	Share float64 `json:"share"`
}

// computeCacheHealth reads cache_events from the DB and folds
// per-event Kinds through reconcile.MispredictRate. Aggregate
// + per-session breakdown + the two secondary checks (read:write
// consistency, cause concentration).
func computeCacheHealth(ctx context.Context, database *sql.DB, thr cacheHealthThresholds) (CacheHealthReport, error) {
	report := CacheHealthReport{
		MinEvents:                    thr.MinEvents,
		MaxRate:                      thr.MaxRate,
		InconsistentRewriteThreshold: thr.MaxRewriteReadRatio,
		MaxCauseShare:                thr.MaxCauseShare,
	}

	const q = `SELECT session_id, timestamp, model, kind,
	           COALESCE(cause, ''), COALESCE(predicted_kind, ''),
	           COALESCE(tokens_read, 0), COALESCE(tokens_written, 0)
	           FROM cache_events ORDER BY id ASC`
	rows, err := database.QueryContext(ctx, q)
	if err != nil {
		return report, fmt.Errorf("cache-health: query cache_events: %w", err)
	}
	defer rows.Close()

	perSession := map[string][]cachetrack.Kind{}
	perSessionTokensRead := map[string][]int64{}
	perSessionTokensWritten := map[string][]int64{}
	perSessionBucketMispredicts := map[string]int{}
	causeRollup := map[string]int{}
	var allKinds []cachetrack.Kind
	var allTokensRead, allTokensWritten []int64
	for rows.Next() {
		var sid, ts, model, kind, cause, predictedKind string
		var tokensRead, tokensWritten int64
		if err := rows.Scan(&sid, &ts, &model, &kind, &cause, &predictedKind, &tokensRead, &tokensWritten); err != nil {
			return report, fmt.Errorf("cache-health: scan: %w", err)
		}
		k := cachetrack.Kind(kind)
		allKinds = append(allKinds, k)
		allTokensRead = append(allTokensRead, tokensRead)
		allTokensWritten = append(allTokensWritten, tokensWritten)
		perSession[sid] = append(perSession[sid], k)
		perSessionTokensRead[sid] = append(perSessionTokensRead[sid], tokensRead)
		perSessionTokensWritten[sid] = append(perSessionTokensWritten[sid], tokensWritten)
		if cause != "" {
			causeRollup[cause]++
		}
		// §15.3 (c)-phase-2 G2 surface: bucket(predicted) !=
		// bucket(observed) (non-skipped) is the rate-blind
		// regression signal. Read directly off persisted
		// (predicted_kind, kind) pairs via the canonical
		// cachetrack.BucketMismatch helper so a future bucketOf
		// change can't silently drift the gate.
		if predictedKind != "" && cachetrack.BucketMismatch(cachetrack.Kind(predictedKind), k) {
			report.BucketMispredicts++
			perSessionBucketMispredicts[sid]++
		}
		if k == cachetrack.KindMispredict {
			report.MispredictEvents = append(report.MispredictEvents, MispredictEvent{
				SessionID:     sid,
				Timestamp:     ts,
				Model:         model,
				Kind:          kind,
				Cause:         cause,
				PredictedKind: predictedKind,
				ZeroUsage:     tokensRead == 0 && tokensWritten == 0,
			})
		}
		if isRewriteKind(k) && tokensRead > int64(thr.MaxRewriteReadRatio*float64(tokensWritten)) && tokensRead > 0 {
			ratio := 0.0
			if tokensWritten > 0 {
				ratio = float64(tokensRead) / float64(tokensWritten)
			}
			report.InconsistentRewriteEvents = append(report.InconsistentRewriteEvents, InconsistentRewriteEvent{
				SessionID:     sid,
				Timestamp:     ts,
				Model:         model,
				Kind:          kind,
				Cause:         cause,
				TokensRead:    tokensRead,
				TokensWritten: tokensWritten,
				Ratio:         ratio,
			})
		}
	}
	if err := rows.Err(); err != nil {
		return report, fmt.Errorf("cache-health: rows: %w", err)
	}

	report.TotalEvents = len(allKinds)
	// MispredictRateGraded skips zero-usage mispredict events (a
	// turn that produced tokens_read=0 AND tokens_written=0 is
	// observationally vacant — no token data to grade the
	// engine's prediction against). The mispredict_count reported
	// below also excludes these, so numerator and denominator
	// stay aligned. The 2026-06-09 soak surfaced 4 such events
	// on opus-4-8 (zero usage despite the proxy capturing the
	// turn) — treating them as real mispredicts distorted the
	// rate without adding signal.
	rate, denom := cachetrack.MispredictRateGraded(allKinds, allTokensRead, allTokensWritten)
	report.GradedEvents = denom
	for i, k := range allKinds {
		if k == cachetrack.KindMispredict && !isZeroUsage(i, allTokensRead, allTokensWritten) {
			report.Mispredicts++
		}
	}
	report.Rate = rate
	report.UniqueSessions = len(perSession)

	for sid, kinds := range perSession {
		sTokensRead := perSessionTokensRead[sid]
		sTokensWritten := perSessionTokensWritten[sid]
		sRate, sDenom := cachetrack.MispredictRateGraded(kinds, sTokensRead, sTokensWritten)
		var sMisp int
		for i, k := range kinds {
			if k == cachetrack.KindMispredict && !isZeroUsage(i, sTokensRead, sTokensWritten) {
				sMisp++
			}
		}
		report.PerSession = append(report.PerSession, SessionHealthRow{
			SessionID:    sid,
			GradedEvents: sDenom,
			Mispredicts:  sMisp,
			Rate:         sRate,
		})
	}

	for cause, count := range causeRollup {
		report.CauseBreakdown = append(report.CauseBreakdown, CauseCount{Cause: cause, Count: count})
	}
	// Sort cause breakdown descending by count so the operator's
	// eye lands on dominant causes first.
	sortCauseDesc(report.CauseBreakdown)

	// G2 per-session rollup. Sorted descending by count so the
	// operator sees the worst sessions first; ties broken by
	// session_id ascending for stable output.
	for sid, count := range perSessionBucketMispredicts {
		if count == 0 {
			continue
		}
		report.BucketMispredictsPerSession = append(report.BucketMispredictsPerSession, SessionBucketRow{
			SessionID:         sid,
			BucketMispredicts: count,
		})
	}
	sortBucketDesc(report.BucketMispredictsPerSession)

	// Cause-concentration check. Suffix_growth dominating is the
	// healthy baseline, so it's excluded by design. Compute share
	// over GradedEvents to align with the rate gate's denominator;
	// when no events are graded the check is silently skipped.
	report.DominantCause = dominantCause(report.CauseBreakdown, report.GradedEvents, thr.MaxCauseShare)

	report.GatePassed = report.GradedEvents >= report.MinEvents && report.Rate <= report.MaxRate
	return report, nil
}

// dominantCause returns the single non-suffix_growth cause whose share
// of gradedEvents exceeds maxShare, or nil when none does (or when
// there's nothing graded / the check is disabled via maxShare <= 0).
// suffix_growth is the healthy baseline; handoff_rehydration is the
// by-design cold write on a handoff target's first turn (kind=reanchor,
// so already denominator-excluded, but still counted in CauseBreakdown)
// — neither should trip the cause-concentration WARN. The breakdown is
// pre-sorted descending by count, so the first over-threshold cause is
// the dominant one.
func dominantCause(breakdown []CauseCount, gradedEvents int, maxShare float64) *DominantCauseRow {
	if gradedEvents <= 0 || maxShare <= 0 {
		return nil
	}
	for _, c := range breakdown {
		if c.Cause == string(cachetrack.CauseSuffixGrowth) ||
			c.Cause == string(cachetrack.CauseHandoffRehydration) {
			continue
		}
		share := float64(c.Count) / float64(gradedEvents)
		if share > maxShare {
			return &DominantCauseRow{
				Cause: c.Cause,
				Count: c.Count,
				Share: share,
			}
		}
	}
	return nil
}

// isZeroUsage mirrors cachetrack.isZeroUsage (unexported) so the
// CLI-side numerator stays aligned with the rate-side denominator
// when MispredictRateGraded excludes a zero-usage mispredict event.
// Out-of-range indices return false — defensive default matches
// the cachetrack-side semantics ("unknown tokens = grade the
// event"; bias toward grading, not toward exclusion).
func isZeroUsage(i int, tokensRead, tokensWritten []int64) bool {
	if i >= len(tokensRead) || i >= len(tokensWritten) {
		return false
	}
	return tokensRead[i] == 0 && tokensWritten[i] == 0
}

// isRewriteKind reports whether a kind labels a CACHE-INVALIDATION
// rewrite — the class for which tokens_read should be ≈ 0 because
// the prefix was cold-rebuilt. Excludes KindWrite (suffix_growth's
// normal write shape — large read coexists with small write on
// warm growth) and KindMispredict / KindReanchor / KindBelowMin
// (not rewrites; either denominator-excluded or non-applicable).
func isRewriteKind(k cachetrack.Kind) bool {
	switch k {
	case cachetrack.KindInvalidationRewrite,
		cachetrack.KindExpiryRewrite,
		cachetrack.KindModelSwitchRewrite,
		cachetrack.KindCompactionReset:
		return true
	}
	return false
}

// sortCauseDesc sorts a CauseCount slice descending by Count
// (ties broken alphabetically by Cause for stability).
func sortCauseDesc(rows []CauseCount) {
	// Tiny n; simple insertion sort keeps the dep surface
	// minimal and the output deterministic.
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && (rows[j-1].Count < rows[j].Count ||
			(rows[j-1].Count == rows[j].Count && rows[j-1].Cause > rows[j].Cause)) {
			rows[j-1], rows[j] = rows[j], rows[j-1]
			j--
		}
	}
}

// sortBucketDesc sorts a SessionBucketRow slice descending by
// BucketMispredicts (ties broken alphabetically by SessionID for
// stability).
func sortBucketDesc(rows []SessionBucketRow) {
	for i := 1; i < len(rows); i++ {
		j := i
		for j > 0 && (rows[j-1].BucketMispredicts < rows[j].BucketMispredicts ||
			(rows[j-1].BucketMispredicts == rows[j].BucketMispredicts && rows[j-1].SessionID > rows[j].SessionID)) {
			rows[j-1], rows[j] = rows[j], rows[j-1]
			j--
		}
	}
}

// printCacheHealth renders the report for human consumption.
func printCacheHealth(w interface{ Write([]byte) (int, error) }, r CacheHealthReport) {
	verdict := "PASS"
	if !r.GatePassed {
		verdict = "FAIL"
	}
	_, _ = fmt.Fprintf(w, "cache mispredict-rate gate: %s\n", verdict)
	_, _ = fmt.Fprintf(w, "  total events     : %d\n", r.TotalEvents)
	_, _ = fmt.Fprintf(w, "  graded events    : %d  (need ≥ %d)\n", r.GradedEvents, r.MinEvents)
	_, _ = fmt.Fprintf(w, "  mispredict count : %d\n", r.Mispredicts)
	_, _ = fmt.Fprintf(w, "  mispredict rate  : %.4f  (need ≤ %.4f)\n", r.Rate, r.MaxRate)
	_, _ = fmt.Fprintf(w, "  unique sessions  : %d\n", r.UniqueSessions)
	if len(r.PerSession) > 0 {
		_, _ = fmt.Fprintln(w, "  per-session:")
		for _, s := range r.PerSession {
			_, _ = fmt.Fprintf(w, "    %s: graded=%d misp=%d rate=%.4f\n",
				s.SessionID, s.GradedEvents, s.Mispredicts, s.Rate)
		}
	}
	if len(r.CauseBreakdown) > 0 {
		_, _ = fmt.Fprintln(w, "  cause breakdown (all events):")
		for _, c := range r.CauseBreakdown {
			_, _ = fmt.Fprintf(w, "    %s: %d\n", c.Cause, c.Count)
		}
	}
	// Primary secondary check: read:write consistency on rewrites.
	// Always rendered (with a CLEAN line on zero) so the operator
	// can confirm it ran. A non-empty list is mechanically
	// inconsistent with the rewrite label and almost certainly
	// signals over-firing of a non-suffix_growth rule.
	rwVerdict := "CLEAN"
	if len(r.InconsistentRewriteEvents) > 0 {
		rwVerdict = fmt.Sprintf("WARN - %d event(s)", len(r.InconsistentRewriteEvents))
	}
	_, _ = fmt.Fprintf(w, "read:write consistency: %s  (flag when read > %.1f× write on *_rewrite/compaction_reset)\n",
		rwVerdict, r.InconsistentRewriteThreshold)
	if len(r.InconsistentRewriteEvents) > 0 {
		for _, e := range r.InconsistentRewriteEvents {
			_, _ = fmt.Fprintf(w, "    %s @ %s: kind=%s cause=%s read=%d write=%d ratio=%.1fx model=%s\n",
				e.SessionID, e.Timestamp, e.Kind, e.Cause, e.TokensRead, e.TokensWritten, e.Ratio, e.Model)
		}
	}
	// Cause concentration WARN.
	if r.DominantCause != nil {
		_, _ = fmt.Fprintf(w, "cause concentration: WARN\n")
		_, _ = fmt.Fprintf(w, "    top cause:  %s at %d/%d graded (%.1f%%)\n",
			r.DominantCause.Cause, r.DominantCause.Count, r.GradedEvents, r.DominantCause.Share*100)
		_, _ = fmt.Fprintf(w, "    threshold:  ≤ %.1f%% (no single non-suffix_growth cause should dominate)\n",
			r.MaxCauseShare*100)
	} else if r.MaxCauseShare > 0 && r.GradedEvents > 0 {
		_, _ = fmt.Fprintf(w, "cause concentration: CLEAN  (no non-suffix_growth cause exceeds %.1f%% of graded)\n",
			r.MaxCauseShare*100)
	}
	if len(r.MispredictEvents) > 0 {
		_, _ = fmt.Fprintln(w, "  mispredict events (diagnose by cause):")
		for _, e := range r.MispredictEvents {
			marker := ""
			if e.ZeroUsage {
				marker = " [zero-usage, excluded from rate]"
			}
			_, _ = fmt.Fprintf(w, "    %s @ %s: kind=%s cause=%s predicted=%s model=%s%s\n",
				e.SessionID, e.Timestamp, e.Kind, e.Cause, e.PredictedKind, e.Model, marker)
		}
	}
	// G2 surface — §15.3 (c)-phase-2 rate-blind regression count.
	// Always rendered so the operator can confirm the gate read
	// even on zero (the rate is BLIND to growth-turn regressions
	// per c489ddb; this counter is the only catch).
	_, _ = fmt.Fprintf(w, "bucket-mispredict (G2): %d events across %d sessions\n",
		r.BucketMispredicts, len(r.BucketMispredictsPerSession))
	if len(r.BucketMispredictsPerSession) > 0 {
		_, _ = fmt.Fprintln(w, "  bucket-mispredicts per session (sessions with ≥1):")
		for _, s := range r.BucketMispredictsPerSession {
			_, _ = fmt.Fprintf(w, "    %s: %d\n", s.SessionID, s.BucketMispredicts)
		}
	}
}
