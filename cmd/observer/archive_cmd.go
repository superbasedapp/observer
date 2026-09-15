package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/archive"
	"github.com/marmutapp/superbased-observer/internal/archivestore"
	"github.com/marmutapp/superbased-observer/internal/archivesvc"
	"github.com/marmutapp/superbased-observer/internal/codeintel"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer archive` — the operator surface for the corpus archival arc
// (docs/plans/observer-corpus-archival-lazyload-design-2026-08-26.md).
//
// Archiving itself is automatic: it rides the ordinary retention pass when
// [archive].enabled is true. These commands exist for the two things an
// operator does by hand — ask what is in cold storage, and bring a project
// back.

func newArchiveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "archive",
		Short: "Inspect cold storage and rehydrate archived data",
		Long: "Cold storage (~/.observer/archive.db) holds data that is not garbage but\n" +
			"is no longer part of the hot working set: code indexes for projects you\n" +
			"have not touched in a while, and process capture past [observer.process]\n" +
			"archive_days. Nothing here is lost — it is one rehydrate (code index) or\n" +
			"one page load (process trail) away.",
	}
	cmd.AddCommand(newArchiveStatusCmd(), newArchiveRehydrateCmd(), newArchiveReclaimCmd())
	return cmd
}

// newArchiveReclaimCmd implements `observer archive reclaim` — the P5.2/P5.3
// operator surface (design §5.2).
//
// WHY A COMMAND AND NOT A RUNBOOK LINE. Open question 5 offered both: document
// the existing restart-window `observer prune --vacuum` sequence as sufficient,
// or build a guided flow. The command won on three counts that the runbook
// cannot cover on its own:
//
//  1. `prune --vacuum` runs a BARE VACUUM — an in-place rewrite of the live
//     file. The audit's whole finding was that the in-place rewrite is the
//     dangerous shape: it needs ~2× the file in headroom, it builds an
//     invisible deleted-but-open temp copy (the ~80 GiB that filled the disk),
//     and an interrupt lands mid-rewrite. VACUUM INTO writes ONE new visible
//     file and never touches the source, so an interrupt costs a wasted copy
//     and nothing else. That is a different operation, not a documented one.
//  2. The free-space precondition has to be arithmetic over live measurements
//     (file size, freelist, statfs). A runbook can tell an operator to check;
//     only a command can refuse.
//  3. Before/after reporting is GATE P5's requirement, and it needs the
//     pre-reclaim numbers, which are gone by the time a human would look.
//
// It never runs automatically and never deletes anything: the original is
// renamed aside, and the operator removes it once the daemon is back clean.
func newArchiveReclaimCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
		run        bool
		force      bool
	)
	cmd := &cobra.Command{
		Use:   "reclaim",
		Short: "Report reclaimable space, and (with --run) compact the database via VACUUM INTO",
		Long: "Archival and retention move rows OUT of the database, but SQLite does not\n" +
			"shrink the file when rows leave — the freed pages sit on the freelist and\n" +
			"the file stays the size it grew to. This is the step that turns those\n" +
			"pages back into free disk.\n\n" +
			"With no flags it only MEASURES: how much is on the freelist, what the file\n" +
			"would shrink to, and whether the preconditions for running it hold. The\n" +
			"measurement is three O(1) pragma reads — safe on a database of any size.\n\n" +
			"With --run it writes a fresh compacted copy via VACUUM INTO, verifies that\n" +
			"copy, renames the original aside, and puts the copy in its place. Nothing\n" +
			"is deleted: the original stays on disk under a .pre-reclaim name until you\n" +
			"remove it. Requires the daemon to be stopped\n" +
			"(docs/daemon-restart-runbook.md).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			closed := false
			closeDB := func() {
				if !closed {
					cleanup()
					closed = true
				}
			}
			defer closeDB()

			rep, err := buildReclaimReport(cmd.Context(), cfg, database, force)
			if err != nil {
				return err
			}
			if !run {
				return emitReclaimReport(cmd, rep, jsonOut)
			}
			if !rep.Plan.OK() {
				_ = emitReclaimReport(cmd, rep, jsonOut)
				return fmt.Errorf("archive reclaim: %s", rep.Plan.Reason)
			}
			if err := performReclaim(cmd, cfg, database, closeDB, &rep, jsonOut); err != nil {
				return err
			}
			return emitReclaimReport(cmd, rep, jsonOut)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	cmd.Flags().BoolVar(&run, "run", false,
		"actually compact the database (VACUUM INTO + verify + swap). Without this the command only measures")
	cmd.Flags().BoolVar(&force, "force", false,
		"compact even when little is reclaimable. Does NOT lift the daemon-stopped or free-disk preconditions")
	return cmd
}

// reclaimReport is the one shape both the measurement view and the post-run
// summary render, so "what it would return" and "what it returned" are never
// two different reports that can disagree.
type reclaimReport struct {
	DBPath string              `json:"db_path"`
	Plan   archive.ReclaimPlan `json:"plan"`
	// FreeDiskBytes is -1 where the platform cannot measure it.
	FreeDiskBytes int64  `json:"free_disk_bytes"`
	DaemonAddr    string `json:"daemon_addr"`
	// Ran, and everything below it, are populated only by --run.
	Ran            bool   `json:"ran"`
	BytesBefore    int64  `json:"bytes_before"`
	BytesAfter     int64  `json:"bytes_after"`
	BytesFreed     int64  `json:"bytes_freed"`
	BackupPath     string `json:"backup_path,omitempty"`
	ArchiveBytes   int64  `json:"archive_bytes"`
	ArchiveReclaim int64  `json:"archive_reclaimable_bytes"`
}

// buildReclaimReport measures the database and its volume and runs the pure
// precondition rules over the result. It performs no writes.
func buildReclaimReport(ctx context.Context, cfg config.Config, database *sql.DB, force bool) (reclaimReport, error) {
	rep := reclaimReport{
		DBPath:        cfg.Observer.DBPath,
		FreeDiskBytes: -1,
		DaemonAddr:    fmt.Sprintf("127.0.0.1:%d", cfg.Proxy.Port),
	}
	fp, err := db.ReadFootprint(ctx, database)
	if err != nil {
		return rep, err
	}
	in := archive.ReclaimInput{
		// The FILE size, not page_count × page_size: a live -wal makes the two
		// differ, and the operator's disk cares about the file.
		FileBytes:     fileSizeOrZero(cfg.Observer.DBPath),
		PageSize:      fp.PageSize,
		FreelistPages: fp.FreelistPages,
		DaemonLive:    portUp(rep.DaemonAddr),
		Force:         force,
	}
	if in.FileBytes == 0 {
		in.FileBytes = fp.TotalBytes
	}
	if diskHeadroomCheckSupported {
		if free, ferr := statfsFreeBytes(cfg.Observer.DBPath); ferr == nil {
			in.FreeDiskBytes, in.FreeDiskKnown = int64(free), true
			rep.FreeDiskBytes = int64(free)
		}
		// ferr != nil: best-effort, exactly as in `prune --vacuum`. An
		// unreadable statfs leaves the rule unable to weigh in rather than
		// inventing a verdict.
	}
	rep.Plan = archive.PlanReclaim(in)
	rep.BytesBefore = in.FileBytes

	// The archive file's own footprint, so the aggregate storage view (P5.1)
	// answers "where did it go" as well as "what can come back". Cheap: a stat
	// plus the same three pragmas, and skipped entirely when there is no
	// archive.
	if cfg.Archive.Path != "" {
		if size := fileSizeOrZero(cfg.Archive.Path); size > 0 {
			rep.ArchiveBytes = size
			if cold, cerr := db.OpenPlain(ctx, cfg.Archive.Path); cerr == nil {
				if cfp, cferr := db.ReadFootprint(ctx, cold); cferr == nil {
					rep.ArchiveReclaim = cfp.ReclaimableBytes
				}
				_ = cold.Close()
			}
		}
	}
	return rep, nil
}

// performReclaim executes the copy → verify → swap. The order is the safety
// contract, and it mirrors the arc's standing invariants: copy first, verify
// the copy that landed (not what the writer believed it wrote), and only then
// move anything — except that here "move" is a rename, so even the last step
// destroys nothing.
func performReclaim(cmd *cobra.Command, cfg config.Config, database *sql.DB, closeDB func(), rep *reclaimReport, quiet bool) error {
	ctx := cmd.Context()
	// Progress narration is suppressed under --json so the stream stays a
	// single parseable document.
	progress := func(format string, args ...any) {
		if !quiet {
			fmt.Fprintf(cmd.OutOrStdout(), format, args...)
		}
	}
	dbPath := cfg.Observer.DBPath
	stamp := time.Now().UTC().Format("20060102T150405Z")
	copyPath := dbPath + ".reclaim-" + stamp
	backupPath := dbPath + ".pre-reclaim-" + stamp

	// The identity the copy must reproduce, read from the SOURCE while it is
	// still open.
	srcFP, err := db.ReadFingerprint(ctx, database)
	if err != nil {
		return fmt.Errorf("archive reclaim: fingerprint source: %w", err)
	}
	if srcFP.QuickCheck != "ok" {
		return fmt.Errorf(
			"archive reclaim: the SOURCE database fails quick_check (%q) — compaction would faithfully copy the damage.\n"+
				"Investigate with `observer db check` before reclaiming", srcFP.QuickCheck,
		)
	}

	// Fold the WAL in first, so the copy is taken from a checkpointed file and
	// the -wal we carry aside with the original is not holding committed pages
	// the backup would need.
	if _, err := database.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		return fmt.Errorf("archive reclaim: checkpoint WAL: %w", err)
	}

	progress("writing compacted copy → %s (VACUUM INTO; the original is not touched)\n", copyPath)
	if err := db.BackupInto(ctx, database, copyPath); err != nil {
		// The source is untouched by definition — VACUUM INTO only ever writes
		// the destination — so cleaning up the partial copy fully restores the
		// pre-command state.
		_ = os.Remove(copyPath)
		return fmt.Errorf("archive reclaim: %w", err)
	}

	// Verify the copy that actually landed, by reading it back off disk.
	cold, err := db.OpenPlain(ctx, copyPath)
	if err != nil {
		return fmt.Errorf("archive reclaim: reopen the copy at %s: %w (the original is untouched)", copyPath, err)
	}
	copyFP, ferr := db.ReadFingerprint(ctx, cold)
	_ = cold.Close()
	if ferr != nil {
		return fmt.Errorf("archive reclaim: verify the copy: %w (the original is untouched)", ferr)
	}
	if copyFP != srcFP {
		return fmt.Errorf(
			"archive reclaim: the compacted copy does not match the source (source %+v, copy %+v) — NOTHING was swapped, "+
				"the original is untouched, and %s can be deleted", srcFP, copyFP, copyPath,
		)
	}

	// Release every handle before touching filenames.
	closeDB()

	// Carry the -wal/-shm across with the original rather than deleting them,
	// so the file left behind stays a complete, openable database. A truncated
	// WAL makes this a formality; doing it anyway means the backup is valid
	// even if the checkpoint above only partially succeeded.
	if err := os.Rename(dbPath, backupPath); err != nil {
		return fmt.Errorf("archive reclaim: rename the original aside: %w (nothing was swapped; delete %s)", err, copyPath)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, serr := os.Stat(dbPath + suffix); serr == nil {
			_ = os.Rename(dbPath+suffix, backupPath+suffix)
		}
	}
	if err := os.Rename(copyPath, dbPath); err != nil {
		// Put the original back: a half-swap that leaves no database at
		// db_path would take the daemon down on its next start.
		_ = os.Rename(backupPath, dbPath)
		return fmt.Errorf("archive reclaim: swap in the compacted copy: %w (the original was restored)", err)
	}

	rep.Ran = true
	rep.BackupPath = backupPath
	rep.BytesAfter = fileSizeOrZero(dbPath)
	rep.BytesFreed = rep.BytesBefore - rep.BytesAfter
	return nil
}

func emitReclaimReport(cmd *cobra.Command, rep reclaimReport, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "database\t%s\t%s\n", rep.DBPath, humanBytes(rep.BytesBefore))
	fmt.Fprintf(w, "on the freelist\t%s\t(what a reclaim would return)\n", humanBytes(rep.Plan.ReclaimableBytes))
	fmt.Fprintf(w, "estimated after\t%s\n", humanBytes(rep.Plan.EstimatedAfterBytes))
	if rep.FreeDiskBytes >= 0 {
		fmt.Fprintf(w, "free disk\t%s\t(need %s for the copy)\n",
			humanBytes(rep.FreeDiskBytes), humanBytes(rep.Plan.RequiredFreeBytes))
	} else {
		fmt.Fprintf(w, "free disk\tnot measurable on this platform\t(the space check is skipped, not assumed)\n")
	}
	if rep.ArchiveBytes > 0 {
		fmt.Fprintf(w, "archive file\t%s\t(%s reclaimable)\n",
			humanBytes(rep.ArchiveBytes), humanBytes(rep.ArchiveReclaim))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	switch {
	case rep.Ran:
		fmt.Fprintf(out, "\nreclaimed %s: %s → %s\n",
			humanBytes(rep.BytesFreed), humanBytes(rep.BytesBefore), humanBytes(rep.BytesAfter))
		fmt.Fprintf(out, "the original is preserved at %s — start the daemon, confirm it is healthy, then delete it.\n",
			rep.BackupPath)
	case rep.Plan.OK():
		fmt.Fprintf(out, "\nReady. Run `observer archive reclaim --run` to compact (daemon must stay stopped).\n")
	default:
		fmt.Fprintf(out, "\nCannot reclaim: %s\n", rep.Plan.Reason)
	}
	return nil
}

func newArchiveStatusCmd() *cobra.Command {
	var (
		configPath string
		jsonOut    bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show what is in cold storage",
		Long: "An explicitly AGGREGATE view: how many code-intelligence projects and\n" +
			"how many days of process capture have moved to cold storage, and how\n" +
			"many rows that is. Answered from the hot marker tables alone — it never\n" +
			"joins across the two databases and never enumerates archived rows.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			st := store.New(database)
			windows, err := st.ProcessArchivedWindows(cmd.Context(), 0)
			if err != nil {
				return err
			}
			out := archiveStatusReport{
				Enabled:     cfg.Archive.Enabled,
				Path:        cfg.Archive.Path,
				ArchiveDays: cfg.Observer.Process.ArchiveDays,
			}
			out.Days = append(out.Days, windows...)
			// The COUNTS come from the aggregate seam, never from summing the
			// per-day rows above: that lister caps its result to render a
			// table, so folding it would under-report a large archive without
			// saying so.
			sum, err := st.ArchivedSummary(cmd.Context())
			if err != nil {
				return err
			}
			out.ProcessWindows = sum.ProcessWindows
			out.ProcessRows = sum.ProcessRows
			out.CodeIntelProjects = sum.CodeIntelProjects
			out.CodeIntelRows = sum.CodeIntelRows
			// The storage half (P5.1): what archival has already freed INSIDE
			// the hot file but not yet returned to the filesystem. Three O(1)
			// pragma reads — never the dbstat walk, which would make a status
			// command a full scan of a 36 GB file.
			out.HotBytes = fileSizeOrZero(cfg.Observer.DBPath)
			if fp, ferr := db.ReadFootprint(cmd.Context(), database); ferr == nil {
				out.HotReclaimableBytes = fp.ReclaimableBytes
			}
			if cfg.Archive.Path != "" {
				out.ArchiveBytes = fileSizeOrZero(cfg.Archive.Path)
			}
			if jsonOut {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}
			return out.render(cmd)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit JSON")
	return cmd
}

type archiveStatusReport struct {
	Enabled           bool                   `json:"enabled"`
	Path              string                 `json:"path"`
	ArchiveDays       int                    `json:"process_archive_days"`
	ProcessWindows    int64                  `json:"process_windows_archived"`
	ProcessRows       int64                  `json:"process_rows_archived"`
	CodeIntelProjects int64                  `json:"codeintel_projects_archived"`
	CodeIntelRows     int64                  `json:"codeintel_rows_archived"`
	Days              []archive.WindowMarker `json:"process_days,omitempty"`
	// HotBytes / ArchiveBytes are the two files' sizes on disk;
	// HotReclaimableBytes is what archival has already freed inside the hot
	// file but not yet returned to the filesystem — the number
	// `observer archive reclaim` acts on.
	HotBytes            int64 `json:"hot_db_bytes"`
	HotReclaimableBytes int64 `json:"hot_db_reclaimable_bytes"`
	ArchiveBytes        int64 `json:"archive_db_bytes"`
}

func (r archiveStatusReport) render(cmd *cobra.Command) error {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	state := "disabled"
	if r.Enabled {
		state = "enabled"
	}
	fmt.Fprintf(w, "archive\t%s\t%s\n", state, r.Path)
	fmt.Fprintf(w, "codeintel projects\t%d\t%d rows\n", r.CodeIntelProjects, r.CodeIntelRows)
	fmt.Fprintf(w, "process windows\t%d\t%d rows\n", r.ProcessWindows, r.ProcessRows)
	fmt.Fprintf(w, "hot database\t%s\t%s reclaimable\n",
		humanBytes(r.HotBytes), humanBytes(r.HotReclaimableBytes))
	if r.ArchiveBytes > 0 {
		fmt.Fprintf(w, "archive database\t%s\n", humanBytes(r.ArchiveBytes))
	}
	if r.HotReclaimableBytes > 0 {
		fmt.Fprintf(w, "\nFreed pages stay inside the file until you compact it:\n")
		fmt.Fprintf(w, "  observer archive reclaim        # measure\n")
		fmt.Fprintf(w, "  observer archive reclaim --run  # compact (daemon stopped)\n")
	}
	if !r.Enabled {
		fmt.Fprintln(w, "\nArchival is off. Nothing is being moved to cold storage;")
		fmt.Fprintln(w, "the existing retention horizons still DELETE at their usual ages.")
	}
	if len(r.Days) > 0 {
		fmt.Fprintln(w, "\nDAY\tRUNS\tEVENTS\tBODIES")
		for _, d := range r.Days {
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\n", d.Day, d.Runs, d.Events, d.Bodies)
		}
	}
	return w.Flush()
}

func newArchiveRehydrateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "rehydrate <project-path>",
		Short: "Restore an archived project's code index from cold storage",
		Long: "Replays a project's archived code-intelligence rows back into the hot\n" +
			"database, verifies what landed against the cold copy, rebuilds the\n" +
			"derived search index, and clears the archived marker.\n\n" +
			"If the cold copy is missing, incomplete, or was produced by a parser\n" +
			"this build no longer accepts, it says so and tells you to run\n" +
			"`observer index <path>` instead — the floor that always works, because\n" +
			"a code index is derived from the repository on disk.\n\n" +
			"Process capture needs no equivalent: its archived rows are read straight\n" +
			"from cold storage by the dashboard, with nothing copied back.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			project, err := filepath.Abs(args[0])
			if err != nil {
				return err
			}
			cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			defer cleanup()
			if cfg.Archive.Path == "" {
				return fmt.Errorf("[archive].path is empty — nothing to rehydrate from")
			}
			cold, err := archivestore.Open(cmd.Context(), archivestore.Options{Path: cfg.Archive.Path})
			if err != nil {
				return fmt.Errorf("open archive %s: %w", cfg.Archive.Path, err)
			}
			defer func() { _ = cold.Close() }()

			mover := &archivesvc.Mover{
				Hot:          store.New(database),
				Cold:         cold,
				BatchRows:    cfg.Archive.BatchRows,
				AcceptParser: codeintel.ParserReplayable,
			}
			out, err := mover.RehydrateCodeIntelProject(cmd.Context(), project)
			if err != nil {
				return err
			}
			switch out.Result {
			case archivesvc.RehydrateRestored:
				fmt.Fprintf(cmd.OutOrStdout(), "restored %s (%d rows)\n", project, out.RowsRestored)
			case archivesvc.RehydrateNotArchived:
				fmt.Fprintf(cmd.OutOrStdout(), "%s is not archived — nothing to do\n", project)
			case archivesvc.RehydrateAlreadyHot:
				fmt.Fprintf(cmd.OutOrStdout(),
					"%s was re-indexed after it was archived, so its live index is newer than the\n"+
						"cold copy. Left the live index alone and cleared the stale marker.\n", project)
			case archivesvc.RehydrateReindexRequired:
				fmt.Fprintf(cmd.OutOrStdout(),
					"cannot replay %s: %s\nrun `observer index %s` to rebuild it from the repository\n",
					project, out.Reason, project)
			}
			if out.Marker.LastIndexedAt > 0 && out.Result != archivesvc.RehydrateNotArchived {
				fmt.Fprintf(cmd.OutOrStdout(), "  (archived copy last indexed %s)\n",
					time.Unix(out.Marker.LastIndexedAt, 0).UTC().Format("2006-01-02"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config.toml")
	return cmd
}

// openProcessArchiveReader gives the dashboard its cold-storage seam for
// archived process trails (P3.5), or nil when archival is off.
//
// nil is the honest default: with [archive].enabled false nothing has been
// archived, so the process surfaces behave exactly as they did before this arc
// and pay nothing for it. The handle is held for the server's lifetime rather
// than opened per request — a session drawer polls, and paying a file open per
// poll would be the wrong trade — but its pool is small (4) for exactly the
// reason the archive is a separate file: it must not become another idle
// connection holder on the hot path.
func openProcessArchiveReader(ctx context.Context, cfg config.Config) (dashboard.ProcessArchiveReader, func()) {
	noop := func() {}
	if !cfg.Archive.Enabled || cfg.Archive.Path == "" {
		return nil, noop
	}
	if _, err := os.Stat(cfg.Archive.Path); err != nil {
		// No archive file yet: nothing has been moved. Not an error, and
		// creating one just to answer "nothing archived" would be worse.
		return nil, noop
	}
	cold, err := archivestore.Open(ctx, archivestore.Options{Path: cfg.Archive.Path})
	if err != nil {
		slog.Warn("archived process trails unavailable: could not open the archive",
			"path", cfg.Archive.Path, "error", err)
		return nil, noop
	}
	return cold, func() { _ = cold.Close() }
}
