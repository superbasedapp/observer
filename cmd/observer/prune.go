package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/archivestore"
	"github.com/marmutapp/superbased-observer/internal/archivesvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/retention"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newPruneCmd implements `observer prune` — manual retention pass.
// `start` and `watch` also call retention.Run on boot when prune_on_startup
// is true; this command exists for ad-hoc cleanup outside that path.
func newPruneCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		vacuum     bool
		breakdown  bool
	)
	cmd := &cobra.Command{
		Use:   "prune",
		Short: "Run retention now: delete old actions, orphaned sessions, stale logs, stale cache_* rows",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			// T2.3 (2026-08-26 disk/compute remediation plan, P1-F): a
			// plain `observer prune` races the daemon's own retention
			// tick (retentionTickLoop in this file) against the same DB —
			// refuse it while the daemon is live, same as --vacuum below.
			// The dblease used by the daemon's own passes only protects
			// against two AUTOMATIC passes overlapping; a manual,
			// operator-invoked prune deserves a clear message up front
			// rather than silently losing the lease race.
			addr := fmt.Sprintf("127.0.0.1:%d", cfg.Proxy.Port)
			if portUp(addr) {
				return fmt.Errorf(
					"prune: the observer daemon is live on %s and already runs its own retention pass — a manual `observer prune` would race it.\n"+
						"Let the daemon's periodic tick handle it, or stop the daemon first (docs/daemon-restart-runbook.md: route OFF → stop → prune → relaunch → route ON) for an ad-hoc pass",
					addr,
				)
			}

			// --vacuum needs exclusive access: a full VACUUM rewrites the
			// whole file under an exclusive lock and needs ~2x disk
			// headroom — running it against a live daemon would stall
			// every proxied session. The blanket live-daemon guard above
			// already covers this case too; kept as an explicit check so
			// the --vacuum error message stays specific if the guard
			// above is ever loosened.
			if vacuum {
				if portUp(addr) {
					return fmt.Errorf(
						"prune --vacuum: the observer daemon is live on %s — a full VACUUM needs exclusive DB access.\n"+
							"Stop the daemon first (safe order in docs/daemon-restart-runbook.md: route OFF → stop → prune --vacuum → relaunch → route ON), then re-run",
						addr,
					)
				}
			}

			// BEFORE snapshot: per-table storage (dbstat) + WAL file size, so
			// the operator sees exactly what each retention pass reclaimed and
			// where the bulk lives. dbstat is a full DB scan, so it's opt-out
			// (--breakdown=false) and never runs on a poll loop — this is an
			// on-demand command.
			walPath := cfg.Observer.DBPath + "-wal"
			walBefore := fileSizeOrZero(walPath)
			var storBefore db.StorageReport
			if breakdown {
				fmt.Fprintln(cmd.OutOrStdout(),
					"prune: computing per-table storage breakdown (dbstat full scan — may take a while on a large DB)…")
				storBefore, _ = db.StorageStats(cmd.Context(), database)
			}

			res, err := runRetention(cmd.Context(), cfg, database)
			if err != nil {
				return err
			}

			// The one-time auto_vacuum=INCREMENTAL conversion + full
			// compaction (Ticket B). After this, every retention pass
			// reclaims freed pages live via PRAGMA incremental_vacuum —
			// no more restart-window VACUUMs needed to shrink the file.
			if vacuum {
				// T0.3 (2026-08-26 disk/compute remediation plan): a bare
				// VACUUM rewrites the whole DB file to a fresh temp copy
				// before atomically replacing the original, so it needs
				// roughly 2x the current file size in free disk headroom
				// for the duration of the run. Refuse up front rather than
				// let VACUUM fail (or fill the disk) partway through a
				// multi-GB file. Best-effort: statfs is unix-only, so this
				// is skipped (not failed) on platforms where
				// diskHeadroomCheckSupported is false.
				if diskHeadroomCheckSupported {
					dbSize := fileSizeOrZero(cfg.Observer.DBPath)
					needed := uint64(dbSize) * 2
					if free, ferr := statfsFreeBytes(cfg.Observer.DBPath); ferr == nil && free < needed {
						return fmt.Errorf(
							"prune --vacuum: not enough free disk space for a full VACUUM — it rewrites the whole %s DB to a temp copy and needs roughly 2x headroom (need ~%s free, have %s free, short by %s). Free up space or move observer.db_path to a volume with more room, then retry",
							humanBytes(dbSize), humanBytes(int64(needed)), humanBytes(int64(free)), humanBytes(int64(needed-free)),
						)
					}
					// ferr != nil: best-effort — an unreadable statfs
					// (an exotic filesystem, a permissions quirk) doesn't
					// block an operator-requested vacuum; it just means
					// this guard couldn't weigh in.
				}
				mode, verr := retention.ConvertToIncrementalVacuum(cmd.Context(), database)
				if verr != nil {
					return fmt.Errorf("prune --vacuum: %w", verr)
				}
				fmt.Fprintf(cmd.OutOrStdout(),
					"vacuum complete: db compacted, auto_vacuum mode = %d (2 = incremental — future retention passes reclaim pages live)\n",
					mode)
			}
			// AFTER snapshot (taken post-vacuum so it reflects the final
			// on-disk state): WAL size + per-table storage.
			walAfter := fileSizeOrZero(walPath)
			var storAfter db.StorageReport
			if breakdown {
				storAfter, _ = db.StorageStats(cmd.Context(), database)
			}

			if jsonOut {
				out := struct {
					retention.Result
					WALBytesBefore   int64             `json:"wal_bytes_before"`
					WALBytesAfter    int64             `json:"wal_bytes_after"`
					StorageBefore    *db.StorageReport `json:"storage_before,omitempty"`
					StorageAfter     *db.StorageReport `json:"storage_after,omitempty"`
					ReclaimableBytes int64             `json:"reclaimable_bytes"`
				}{Result: res, WALBytesBefore: walBefore, WALBytesAfter: walAfter}
				if breakdown {
					out.StorageBefore = &storBefore
					out.StorageAfter = &storAfter
					out.ReclaimableBytes = storAfter.ReclaimableBytes
				}
				body, _ := json.MarshalIndent(out, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), string(body))
				return nil
			}
			fmt.Fprintf(
				cmd.OutOrStdout(),
				"prune complete in %dms: actions=%d sessions=%d logs=%d file_state=%d cache_rows=%d guard_rows=%d prompt_reconsider_rows=%d process_rows=%d handoff_rows=%d benchmark_rows=%d codeintel_projects=%d compaction_events=%d compression_events=%d size_passes=%d (db %d → %d bytes)\n",
				res.DurationMs,
				res.ActionsDeleted,
				res.OrphanedSessionsDeleted,
				res.LogEntriesDeleted,
				res.FileStateDeleted,
				res.CacheRowsDeleted,
				res.GuardRowsDeleted,
				res.PromptReconsiderRowsDeleted,
				res.ProcessRowsDeleted,
				res.HandoffRowsDeleted,
				res.BenchmarkRowsDeleted,
				res.CodeIntelProjectsDeleted,
				res.EventRowsDeleted["compaction_events"],
				res.EventRowsDeleted["compression_events"],
				res.SizePassesRun,
				res.DBSizeBytesBefore,
				res.DBSizeBytesAfter,
			)
			printPruneReclamation(cmd.OutOrStdout(), storBefore, storAfter, walBefore, walAfter, breakdown, vacuum)
			if res.SizeCapUnmet {
				fmt.Fprintf(cmd.OutOrStdout(),
					"WARNING: DB still exceeds max_db_size_mb after shedding aged actions — the bulk is in other tables (token_usage / cache_*). Recent actions were protected. Raise [observer.retention].max_db_size_mb.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit JSON")
	cmd.Flags().BoolVar(&vacuum, "vacuum", false,
		"After pruning, convert the DB to auto_vacuum=INCREMENTAL and run a full VACUUM. "+
			"Refuses while the daemon is live — run in a restart window (docs/daemon-restart-runbook.md)")
	cmd.Flags().BoolVar(&breakdown, "breakdown", true,
		"Report a before/after per-table storage breakdown (dbstat) so you can see what was reclaimed and where the bulk lives. "+
			"dbstat is a full DB scan — pass --breakdown=false to skip it on a very large DB")
	return cmd
}

// fileSizeOrZero returns the size of path in bytes, or 0 if it does not
// exist / can't be stat'd (e.g. the -wal file when the DB is in a
// truncated/checkpointed state).
func fileSizeOrZero(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// pruneReclaimCategory maps a set of user-visible table names (or a name
// prefix) onto one operator-facing reclamation line. The big reclaimable
// bulk on a bloated observer.db falls into these buckets; anything else
// shows up in the generic top-reclaimed list.
type pruneReclaimCategory struct {
	label  string
	prefix string   // fold every table whose name starts with this (e.g. "codeintel_")
	names  []string // …or this explicit set
}

var pruneReclaimCategories = []pruneReclaimCategory{
	{label: "codeintel stale projects", prefix: "codeintel_"},
	{label: "process observability", names: []string{"process_runs", "process_events", "process_network_bodies"}},
	{label: "actions", names: []string{"actions", "action_excerpts"}},
	{label: "token usage", names: []string{"token_usage"}},
}

// groupBytes sums the byte footprint of a category's tables in a
// StorageReport (prefix match OR explicit name set).
func (c pruneReclaimCategory) groupBytes(byName map[string]int64) int64 {
	var total int64
	if c.prefix != "" {
		for name, b := range byName {
			if strings.HasPrefix(name, c.prefix) {
				total += b
			}
		}
		return total
	}
	for _, n := range c.names {
		total += byName[n]
	}
	return total
}

// printPruneReclamation renders the before/after storage breakdown and the
// per-category reclamation summary. When breakdown is false it prints only
// the WAL-checkpoint line (the dbstat scan was skipped). Reclamation is
// reported honestly as freed-to-freelist unless a full VACUUM ran: without
// --vacuum the main file size is unchanged and the freed pages sit on the
// freelist until an exclusive VACUUM returns them to the OS.
func printPruneReclamation(w io.Writer, before, after db.StorageReport, walBefore, walAfter int64, breakdown, vacuumed bool) {
	// WAL checkpoint line — always shown; the TRUNCATE runs inside every
	// retention pass. A near-zero delta on a live daemon usually means a
	// long-lived reader pinned the WAL (the checkpoint can't truncate past
	// the oldest reader's snapshot).
	walDelta := walBefore - walAfter
	switch {
	case walDelta > 0:
		fmt.Fprintf(w, "  WAL checkpoint: truncated %s (%s → %s)\n",
			fmtMB(walDelta), fmtMB(walBefore), fmtMB(walAfter))
	case walBefore > 8*1024*1024:
		fmt.Fprintf(w, "  WAL checkpoint: WAL still %s — a long-lived reader likely pinned it (checkpoint can't truncate past the oldest snapshot); retry when idle\n",
			fmtMB(walAfter))
	}

	if !breakdown {
		return
	}

	beforeByName := storageByName(before)
	afterByName := storageByName(after)

	// Per-category reclamation.
	fmt.Fprintln(w, "reclaimed by category (dbstat):")
	anyCat := false
	for _, c := range pruneReclaimCategories {
		b, a := c.groupBytes(beforeByName), c.groupBytes(afterByName)
		if b == 0 && a == 0 {
			continue
		}
		freed := b - a
		if freed <= 0 {
			continue
		}
		anyCat = true
		fmt.Fprintf(w, "  %-24s %s freed (%s → %s)\n", c.label+":", fmtMB(freed), fmtMB(b), fmtMB(a))
	}
	if !anyCat {
		fmt.Fprintln(w, "  (no table shrank — nothing was eligible for retention this pass)")
	}

	// Top individual tables by reclaimed bytes (surfaces anything not folded
	// into a named category).
	type delta struct {
		name  string
		freed int64
	}
	var deltas []delta
	for name, b := range beforeByName {
		if freed := b - afterByName[name]; freed > 1024*1024 { // > 1MB
			deltas = append(deltas, delta{name, freed})
		}
	}
	sort.Slice(deltas, func(i, j int) bool { return deltas[i].freed > deltas[j].freed })
	if len(deltas) > 0 {
		fmt.Fprintln(w, "top tables reclaimed:")
		for i, d := range deltas {
			if i >= 8 {
				break
			}
			fmt.Fprintf(w, "  %-28s %s (%s → %s)\n", d.name, fmtMB(d.freed),
				fmtMB(beforeByName[d.name]), fmtMB(afterByName[d.name]))
		}
	}

	// Whole-file position + the honest two-step message.
	reclaimable := after.ReclaimableBytes
	if vacuumed {
		fmt.Fprintf(w, "main DB file: %s → %s (freed pages returned to the OS by VACUUM)\n",
			fmtMB(before.TotalBytes), fmtMB(after.TotalBytes))
	} else {
		fmt.Fprintf(w, "main DB file: %s → %s (unchanged — deletes freed %s of pages onto the freelist)\n",
			fmtMB(before.TotalBytes), fmtMB(after.TotalBytes), fmtMB(reclaimable))
		if reclaimable > 16*1024*1024 {
			fmt.Fprintf(w, "run `observer prune --vacuum` with the daemon DOWN to return %s of free pages to the OS\n",
				fmtMB(reclaimable))
		}
	}
}

// storageByName folds a StorageReport's table list into a name→bytes map.
func storageByName(rep db.StorageReport) map[string]int64 {
	m := make(map[string]int64, len(rep.Tables))
	for _, t := range rep.Tables {
		m[t.Name] = t.Bytes
	}
	return m
}

// fmtMB renders a byte count as a right-sized MB string.
func fmtMB(b int64) string {
	return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
}

// runRetention executes one retention pass with options drawn from config.
// Reused by `prune` and by the startup hook in watch / start. Composes the
// retention package (sql.DB-only by design) with store.PruneCacheRows
// (cachetrack §9 sweep) — the retention package itself doesn't touch
// cache_* tables, so the orchestration lives here.
//
// Each call is idempotent: a second run within the same horizon is a no-op
// for both passes. Pinned by retention package's existing tests + the new
// TestPruneCacheRows_SecondRunNoop.
func runRetention(ctx context.Context, cfg config.Config, database *sql.DB) (retention.Result, error) {
	p := retention.New(database)
	res, err := p.Run(ctx, retention.Options{
		MaxAgeDays:            cfg.Observer.Retention.MaxAgeDays,
		MaxDBSizeMB:           cfg.Observer.Retention.MaxDBSizeMB,
		ObserverLogMaxAgeDays: cfg.Observer.Retention.ObserverLogMaxAgeDays,
		DBPath:                cfg.Observer.DBPath,
		// The bounded, table-driven event sweep (internal/retention/
		// events.go). These two tables had no horizon at all before
		// 2026-09-16 and held ~2.3 GiB between them on the operator's live
		// DB; 0 on either key keeps that table forever.
		EventSweep: retention.EventSweepDays{
			CompactionEventsDays:  cfg.Observer.Retention.CompactionEventsDays,
			CompressionEventsDays: cfg.Observer.Retention.CompressionEventsDays,
		},
	})
	if err != nil {
		return res, err
	}
	// Cachetrack §9 sweep — wired here because the retention package
	// stays sql.DB-only (no internal/store import). cfg.CacheTrack.
	// RetentionDays ≤ 0 short-circuits inside PruneCacheRows.
	if cfg.CacheTrack.RetentionDays > 0 {
		s := store.New(database)
		n, perr := s.PruneCacheRows(ctx, cfg.CacheTrack.RetentionDays)
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune cache rows: %w", perr)
		}
		res.CacheRowsDeleted = n
	}
	// Routing decision-log sweep ([routing].decision_log_retention_days,
	// model-routing spec §R21) — same orchestration rationale as the
	// cachetrack sweep. ≤ 0 short-circuits inside PruneRouterDecisions.
	if cfg.Routing.DecisionLogRetentionDays > 0 {
		s := store.New(database)
		n, perr := s.PruneRouterDecisions(ctx, cfg.Routing.DecisionLogRetentionDays)
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune router decisions: %w", perr)
		}
		res.RouterDecisionsDeleted = n
	}
	// Guard §10.3 sweep — same composition rationale. The prefix-prune
	// writes the chain checkpoint so `guard verify-audit` keeps
	// anchoring across retention; ≤ 0 short-circuits inside.
	if cfg.Guard.RetentionDays > 0 {
		s := store.New(database)
		n, perr := s.PruneGuardRows(ctx, cfg.Guard.RetentionDays)
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune guard rows: %w", perr)
		}
		res.GuardRowsDeleted = n
	}
	// Prompt-submit "reconsider-once" sweep (migration 110,
	// docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
	// §5.4) — same call site as the guard §10.3 sweep above, but
	// unconditional: the table's own expires_at is its prune horizon
	// (a short-lived grant, default 30 minutes), so there is no
	// retention-days knob to gate on.
	{
		s := store.New(database)
		n, perr := s.PrunePromptReconsider(ctx, time.Now().UTC())
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune prompt-reconsider rows: %w", perr)
		}
		res.PromptReconsiderRowsDeleted = n
	}
	// Process-observability sweep ([observer.process].retention_days,
	// docs/process-observability.md §11) — same composition rationale.
	// ≤ 0 (incl. the feature being disabled with the default 30 but no
	// rows) short-circuits inside PruneProcessRows.
	//
	// [archive].enabled changes the FATE of this bucket's rows exactly the
	// way it does for codeintel above, but with one extra move: process
	// capture is the ONLY-COPY bucket (design §2.2), so instead of a single
	// horizon that deletes, it gets two — archive_days moves capture to cold
	// storage, and retention_days becomes the archive file's own delete
	// horizon. The hot prune is then NOT run, because everything past
	// archive_days has already left the hot database and running a hot delete
	// on the same rows would be at best a no-op and at worst a race against
	// the mover.
	if cfg.Archive.Enabled && cfg.Observer.Process.ArchiveDays > 0 {
		sweep, aerr := runProcessArchiveSweep(ctx, cfg)
		res.ProcessWindowsArchived = sweep.Archived
		res.ProcessRowsArchived = sweep.RowsArchived
		res.ProcessWindowsExpired = sweep.Expired
		if aerr != nil {
			return res, fmt.Errorf("runRetention: archive process windows: %w", aerr)
		}
	} else if cfg.Observer.Process.RetentionDays > 0 {
		s := store.New(database)
		n, perr := s.PruneProcessRows(ctx, cfg.Observer.Process.RetentionDays)
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune process rows: %w", perr)
		}
		res.ProcessRowsDeleted = n
	}
	// Session-handoff sweep ([handoff].retention_days, plan §15 P4) — same
	// composition rationale as the cachetrack sweep: the retention package
	// stays sql.DB-only, so the handoffs prune is orchestrated here through
	// the store seam. ≤ 0 short-circuits inside PruneHandoffRows
	// (keep-forever).
	if cfg.Handoff.RetentionDays > 0 {
		s := store.New(database)
		n, perr := s.PruneHandoffRows(ctx, cfg.Handoff.RetentionDays)
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune handoff rows: %w", perr)
		}
		res.HandoffRowsDeleted = n
	}
	// Benchmarks-Harness sweep ([benchmark].retention_days, plan §3.12) — same
	// composition rationale as the cachetrack sweep: the retention package
	// stays sql.DB-only, so the benchmark_* prune is orchestrated here through
	// the store seam. ≤ 0 short-circuits inside PruneBenchmarkRows (keep
	// forever). The delete cascades a run's attempts/members/scores.
	if cfg.Benchmark.RetentionDays > 0 {
		s := store.New(database)
		n, perr := s.PruneBenchmarkRows(ctx, cfg.Benchmark.RetentionDays)
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune benchmark rows: %w", perr)
		}
		res.BenchmarkRowsDeleted = n
	}
	// Code-intelligence sweep ([codeintel].retention_days, Ticket B of the
	// 2026-07-12 hook-stall + DB-prune plan) — same composition rationale:
	// all codeintel_* SQL stays in the store seam (internal/store/
	// codeintel.go), reusing the SAME per-project delete `observer index
	// delete -r` rides. A project whose last index pass is past the horizon
	// is removed wholesale; never-indexed and actively-indexed projects are
	// untouched. ≤ 0 short-circuits inside CodeIntelPruneStaleProjects.
	//
	// [archive].enabled swaps the ACTION on that same staleness set from
	// delete to copy-then-delete-into-cold-storage
	// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md).
	// The trigger, the horizon and the conservatism are identical; only the
	// fate of the rows differs.
	if cfg.CodeIntel.RetentionDays > 0 {
		if cfg.Archive.Enabled {
			archived, rows, aerr := runCodeIntelArchiveSweep(ctx, cfg)
			res.CodeIntelProjectsArchived = archived
			res.CodeIntelRowsArchived = rows
			if aerr != nil {
				return res, fmt.Errorf("runRetention: archive codeintel projects: %w", aerr)
			}
		} else {
			s := store.New(database)
			deleted, perr := s.CodeIntelPruneStaleProjects(ctx, cfg.CodeIntel.RetentionDays)
			if perr != nil {
				return res, fmt.Errorf("runRetention: prune codeintel projects: %w", perr)
			}
			res.CodeIntelProjectsDeleted = len(deleted)
		}
	}
	// Org-served Cloud Intelligence result-cache sweep (migration 112/114,
	// org-served-cloud-intelligence plan §3.5; finding 7) — same composition
	// rationale as the cachetrack sweep: the retention package stays sql.DB-only,
	// so the node-local org_intel_cache prune is orchestrated here through the
	// store seam. It runs UNCONDITIONALLY (orphans are always swept; the broad
	// max_age_days window additionally ages rows when > 0) — the same
	// reuse-the-existing-sweep shape as the prompt-reconsider prune, not a second
	// scheduler.
	{
		s := store.New(database)
		n, perr := s.PruneOrgIntelCache(ctx, cfg.Observer.Retention.MaxAgeDays, time.Now().UTC())
		if perr != nil {
			return res, fmt.Errorf("runRetention: prune org intel cache: %w", perr)
		}
		res.OrgIntelCacheDeleted = n
	}
	return res, nil
}

// runCodeIntelArchiveSweep moves one bounded batch of stale code-intelligence
// projects into ~/.observer/archive.db.
//
// It opens the archive database for the duration of the sweep and closes it
// again: the archive is touched once per retention pass, so holding a second
// connection pool open for the daemon's whole lifetime would cost idle
// connections (each a candidate temp-file holder) for no benefit.
//
// FAIL-OPEN, and specifically fail-open in ONE direction: if the archive
// database cannot be opened, the codeintel sweep is SKIPPED for this pass —
// it never falls back to the delete path. An operator who asked for archival
// and got deletion because a file was momentarily unavailable would have lost
// data to a config option whose entire purpose was to stop losing data. The
// projects stay hot and are re-offered next pass.
func runCodeIntelArchiveSweep(ctx context.Context, cfg config.Config) (projects int, rows int64, err error) {
	path := cfg.Archive.Path
	if path == "" {
		return 0, 0, nil
	}
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		slog.Warn("archive sweep skipped: archive directory unavailable",
			"path", path, "error", mkErr)
		return 0, 0, nil
	}
	cold, openErr := archivestore.Open(ctx, archivestore.Options{Path: path})
	if openErr != nil {
		slog.Warn("archive sweep skipped: archive database unavailable (projects stay hot)",
			"path", path, "error", openErr)
		return 0, 0, nil
	}
	defer func() { _ = cold.Close() }()

	// A SEPARATE hot handle, not the caller's: an archive move streams a
	// whole project through the pool, and borrowing the shared handle for
	// that would put a long cold-path read on the same connections the
	// daemon's hot work uses (design §1.2's explicit rejection).
	hotDB, dbErr := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if dbErr != nil {
		slog.Warn("archive sweep skipped: could not open a dedicated hot handle",
			"error", dbErr)
		return 0, 0, nil
	}
	defer func() { _ = hotDB.Close() }()

	mover := &archivesvc.Mover{
		Hot:       store.New(hotDB),
		Cold:      cold,
		BatchRows: cfg.Archive.BatchRows,
	}
	res, sweepErr := mover.SweepCodeIntel(ctx, cfg.CodeIntel.RetentionDays,
		archive.PlanOptions{MaxUnitsPerPass: cfg.Archive.MaxProjectsPerPass})
	if res.Considered > res.Attempted {
		slog.Info("archive sweep capped for this pass",
			"considered", res.Considered, "attempted", res.Attempted,
			"max_projects_per_pass", cfg.Archive.MaxProjectsPerPass)
	}
	return res.Archived, res.RowsArchived, sweepErr
}

// runProcessArchiveSweep moves one bounded batch of stale process-capture
// day-windows into ~/.observer/archive.db, then applies the archive file's own
// (later) expiry horizon.
//
// Same open-for-the-pass, separate-hot-handle, FAIL-OPEN-IN-ONE-DIRECTION
// posture as runCodeIntelArchiveSweep — and the fail-open direction matters
// more here than anywhere else in the arc. If the archive database cannot be
// opened, the sweep is SKIPPED and NOTHING is deleted; it never falls back to
// the hot prune. An operator who turned archival on and got their only copy of
// a process trail deleted because a file was momentarily unavailable would have
// lost unrecoverable data to a setting whose entire purpose was to stop losing
// it. The windows stay hot and are re-offered next pass.
func runProcessArchiveSweep(ctx context.Context, cfg config.Config) (archivesvc.ProcessSweepResult, error) {
	var zero archivesvc.ProcessSweepResult
	path := cfg.Archive.Path
	if path == "" {
		return zero, nil
	}
	if mkErr := os.MkdirAll(filepath.Dir(path), 0o755); mkErr != nil {
		slog.Warn("process archive sweep skipped: archive directory unavailable",
			"path", path, "error", mkErr)
		return zero, nil
	}
	cold, openErr := archivestore.Open(ctx, archivestore.Options{Path: path})
	if openErr != nil {
		slog.Warn("process archive sweep skipped: archive database unavailable (windows stay hot)",
			"path", path, "error", openErr)
		return zero, nil
	}
	defer func() { _ = cold.Close() }()

	hotDB, dbErr := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if dbErr != nil {
		slog.Warn("process archive sweep skipped: could not open a dedicated hot handle",
			"error", dbErr)
		return zero, nil
	}
	defer func() { _ = hotDB.Close() }()

	mover := &archivesvc.ProcessMover{
		Hot:       store.New(hotDB),
		Cold:      cold,
		BatchRows: cfg.Archive.BatchRows,
	}
	res, sweepErr := mover.SweepProcess(ctx, cfg.Observer.Process.ArchiveDays, cfg.Archive.MaxProjectsPerPass)

	// The cold expiry runs even when the move half reported errors: a window
	// that failed to archive is unrelated to windows whose cold copy is now
	// past the delete horizon, and letting one block the other would grow the
	// archive without bound.
	expired, expErr := mover.ExpireProcessWindows(ctx, cfg.Observer.Process.RetentionDays, cfg.Archive.MaxProjectsPerPass)
	res.Expired = expired
	if res.Considered > res.Archived+res.Skipped+res.Failed {
		slog.Info("process archive sweep capped for this pass", "considered", res.Considered)
	}
	return res, errors.Join(sweepErr, expErr)
}

// runRetentionLeased wraps runRetention with the T2.3 (P1-F) cross-process
// "retention" dblease so multiple observer processes on the same machine
// (proxy, watcher, a manual `observer prune`) don't run a retention pass
// against the same DB at once. ran=false means another process legitimately
// holds the lease this round — res/err are zero and the caller should
// simply skip this pass, not treat it as a failure. Any lease mechanism
// error fails open (ran=true, proceeds normally) per dblease's contract.
func runRetentionLeased(ctx context.Context, cfg config.Config, database *sql.DB, logger *slog.Logger) (res retention.Result, ran bool, err error) {
	release, proceed := acquireMaintenanceLease(cfg, "retention", logger)
	defer release()
	if !proceed {
		return retention.Result{}, false, nil
	}
	res, err = runRetention(ctx, cfg, database)
	return res, true, err
}

// retentionTickLoop is the daemon's periodic maintenance tick (Ticket B):
// it re-runs the full runRetention pass every
// [observer.retention].interval_hours while `observer start` is up, so a
// daemon that stays up for weeks still prunes — historically retention
// only ran at startup (prune_on_startup) and via manual `observer prune`,
// despite config comments claiming a periodic tick existed.
//
// Self-contained config+DB handle (same pattern as the advisor digest
// refresher in start.go) and P1 fail-soft: any error logs and the loop
// keeps ticking; it never cancels proxy/watcher/dashboard. interval_hours
// ≤ 0 disables the loop. The first tick fires one full interval after
// startup — prune_on_startup already covers the boot pass.
func retentionTickLoop(ctx context.Context, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	logger := newLogger(cfg.Observer.LogLevel)

	// Startup prune pass (spec §19), moved OFF the synchronous buildWatcher
	// readiness path (2026-07-16): on a multi-GB DB the delete + incremental
	// vacuum runs for many seconds and used to block the listener from
	// binding. It now runs here, once, in the background after the daemon is
	// already serving. Gated by prune_on_startup (default true) and run
	// BEFORE the interval_hours<=0 early return so disabling the periodic
	// tick doesn't also disable the startup prune.
	if cfg.Observer.Retention.PruneOnStartup {
		if res, ran, err := runRetentionLeased(ctx, cfg, database, logger); !ran {
			// Another observer process holds the "retention" lease this
			// round (T2.3, P1-F) — it's already doing this pass.
		} else if err != nil {
			if !errors.Is(err, context.Canceled) {
				logger.Warn("retention startup pass failed", "err", err)
			}
		} else {
			if res.ActionsDeleted+res.LogEntriesDeleted+res.OrphanedSessionsDeleted+res.FileStateDeleted+res.EventRowsDeleted.Total() > 0 {
				logger.Info("retention startup pass",
					"actions", res.ActionsDeleted, "sessions", res.OrphanedSessionsDeleted,
					"logs", res.LogEntriesDeleted, "file_state", res.FileStateDeleted,
					"compaction_events", res.EventRowsDeleted["compaction_events"],
					"compression_events", res.EventRowsDeleted["compression_events"],
					"incremental_vacuum", res.IncrementalVacuumRun,
					"duration_ms", res.DurationMs)
			}
			if res.SizeCapUnmet {
				logger.Warn("retention: DB still over max_db_size_mb after shedding aged actions — the bulk is in other tables (token_usage / cache_* / codeintel_* / process_runs). Recent actions were protected by the keep-floor. Raise [observer.retention].max_db_size_mb or add token retention.",
					"max_db_size_mb", cfg.Observer.Retention.MaxDBSizeMB,
					"db_bytes", res.DBSizeBytesAfter)
			}
		}
	}

	hours := cfg.Observer.Retention.IntervalHours
	if hours <= 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(hours) * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			res, ran, err := runRetentionLeased(ctx, cfg, database, logger)
			if !ran {
				// Another observer process holds the "retention" lease
				// this round (T2.3, P1-F) — skip, it's already running.
				continue
			}
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					logger.Warn("retention tick failed", "err", err)
				}
				continue
			}
			logger.Info("retention tick",
				"actions", res.ActionsDeleted,
				"sessions", res.OrphanedSessionsDeleted,
				"codeintel_projects", res.CodeIntelProjectsDeleted,
				"process_rows", res.ProcessRowsDeleted,
				"compaction_events", res.EventRowsDeleted["compaction_events"],
				"compression_events", res.EventRowsDeleted["compression_events"],
				"incremental_vacuum", res.IncrementalVacuumRun,
				"db_bytes", res.DBSizeBytesAfter,
				"duration_ms", res.DurationMs)
			if res.SizeCapUnmet {
				logger.Warn("retention tick: DB still over max_db_size_mb after shedding aged actions — the bulk is in other tables. Recent actions were protected by the keep-floor.")
			}
		}
	}
}
