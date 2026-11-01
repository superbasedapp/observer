//go:build !sbo_omit_org_update

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/quiesce"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// update_verbs.go adds the three EFFECTFUL verbs of §3.10 — `apply`,
// `rollback` and `history` — on top of W1's read-only `status` / `check`.
//
// WHERE AN APPLY ACTUALLY RUNS, and why the CLI is mostly a messenger. The
// drain and the handshake are only meaningful in the process that OWNS the
// listeners: a CLI that swapped the binary under a running daemon would
// leave that daemon executing its old inode with nobody watching a successor
// that was never spawned. So `observer update apply` ASKS THE DAEMON over
// loopback when one is running (the `observer statusline` pattern —
// resolveDashboardAddr, a plain bounded http.Client, a locally-declared wire
// struct so cmd never imports the dashboard package), and only performs the
// apply itself when there is no daemon to ask. In that second case there are
// no listeners to hand over, so the handshake degrades honestly to the
// --version probe that already ran at step 4 — stated here rather than
// pretending a supervision step happened.

// updateAPIPath is the daemon's loopback apply endpoint.
const updateAPIPath = "/api/update/apply"

// updateDaemonTimeout bounds the CLI's wait on the daemon. An apply includes
// a drain and a handshake, so it is generous by design; the daemon's own
// budgets are the real bounds.
const updateDaemonTimeout = 10 * time.Minute

// updateApplyRequest / updateApplyResponse are the loopback wire. They are
// declared HERE, not imported from the dashboard package, so `cmd` keeps its
// one-way dependency and a shape change is visible on both sides.
type updateApplyRequest struct {
	Version  string `json:"version,omitempty"`
	Force    bool   `json:"force,omitempty"`
	DryRun   bool   `json:"dry_run,omitempty"`
	Rollback bool   `json:"rollback,omitempty"`
}

type updateApplyResponse struct {
	State      string   `json:"state"`
	Reason     string   `json:"reason,omitempty"`
	ErrorClass string   `json:"error_class,omitempty"`
	Detail     string   `json:"detail,omitempty"`
	Steps      []string `json:"steps,omitempty"`
	Applied    bool     `json:"applied,omitempty"`
	RolledBack bool     `json:"rolled_back,omitempty"`
	Deferred   bool     `json:"deferred,omitempty"`
	Error      string   `json:"error,omitempty"`
	// Accepted / EventID are the 202 answer: the daemon took the request and
	// is running the apply on its own budget, off this request's goroutine.
	Accepted bool  `json:"accepted,omitempty"`
	EventID  int64 `json:"event_id,omitempty"`
}

// newUpdateApplyCmd builds `observer update apply`.
func newUpdateApplyCmd() *cobra.Command {
	var (
		version string
		force   bool
		dryRun  bool
		cfgPath string
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Download, verify and install the update this node is eligible for",
		Long: `observer update apply runs the full apply sequence: download from the org
mirror, verify the archive hash and the vendor signature, extract and probe
the binary, drain in-flight proxied requests, stage a rollback (and, when the
target advances the database schema, a snapshot), swap atomically, and watch
the new binary until it passes its self-check.

Any doubt at any step aborts and leaves the running binary untouched. If the
new binary fails, exits or hangs, the OLD process - which is still alive
precisely for this - restores the previous binary and reports rolled_back.

--force ignores the local maintenance window and, inside an admin maintenance
window, permits an apply while a dashboard terminal is live. It never
shortens the drain and never skips verification.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUpdateVerb(cmd, cfgPath, updateApplyRequest{Version: version, Force: force, DryRun: dryRun})
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&version, "version", "", "Target version (defaults to whatever the org published for this node)")
	cmd.Flags().BoolVar(&force, "force", false, "Ignore the maintenance window; with an admin window, proceed past a live dashboard terminal")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print the plan, including whether a database snapshot is involved, and do nothing")
	return cmd
}

// newUpdateRollbackCmd builds `observer update rollback`.
func newUpdateRollbackCmd() *cobra.Command {
	var (
		yes     bool
		cfgPath string
	)
	cmd := &cobra.Command{
		Use:   "rollback",
		Short: "Restore the previous binary (and its database snapshot when the schema advanced)",
		Long: `observer update rollback restores the binary this node ran before its last
apply, and - when that apply advanced the database schema - the pre-apply
snapshot taken alongside it.

Restoring the snapshot DISCARDS every row ingested since it was taken. That
window is normally seconds to a couple of minutes, and it is named explicitly
before anything is restored. Confirmation is required unless --yes is given.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !yes {
				st, _, err := loadUpdateStateForCLIAt(cmd.Context(), cfgPath)
				if err != nil {
					return err
				}
				if strings.TrimSpace(st.PreviousVersion) == "" {
					return fmt.Errorf("observer update rollback: this node has no recorded previous version")
				}
				out := cmd.OutOrStdout()
				fmt.Fprintf(out, "This will restore %s over the running %s.\n", st.PreviousVersion, version)
				if strings.TrimSpace(st.PreviousDBBackupPath) != "" {
					fmt.Fprintf(out, "It will ALSO restore the database snapshot at %s, discarding every row\ningested since it was taken.\n", st.PreviousDBBackupPath)
				}
				fmt.Fprintln(out, "\nRe-run with --yes to proceed.")
				return nil
			}
			return runUpdateVerb(cmd, cfgPath, updateApplyRequest{Rollback: true})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "Proceed without the confirmation prompt")
	cmd.Flags().StringVar(&cfgPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// newUpdateHistoryCmd builds `observer update history`.
func newUpdateHistoryCmd() *cobra.Command {
	var (
		limit   int
		jsonOut bool
		cfgPath string
	)
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Print this node's update ledger (local only, no network)",
		Long: `observer update history prints every apply, rollback and refusal this node
has recorded, newest first, with the reason for each - including the
timestamp of any pre-apply database snapshot, so the operator can see exactly
which data window a rollback discarded.

The ledger is NODE-LOCAL and never leaves the machine: its reasons may name
local paths, which is precisely why the org-bound posture carries only
enums.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			s, closeDB, err := openUpdateStore(ctx, cfgPath)
			if err != nil {
				return err
			}
			defer closeDB()
			events, err := s.LoadUpdateEvents(ctx, limit)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if jsonOut {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(events)
			}
			if len(events) == 0 {
				fmt.Fprintln(out, "No update events recorded on this node.")
				return nil
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "WHEN\tFROM\tTO\tSTATE\tERROR\tDETAIL")
			for _, e := range events {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
					e.At.Local().Format("2006-01-02 15:04:05"),
					orDash(e.FromVersion), orDash(e.ToVersion),
					e.State, orDash(string(e.ErrorClass)), e.Detail)
			}
			return tw.Flush()
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum rows to print")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Emit the ledger as JSON")
	cmd.Flags().StringVar(&cfgPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

// runUpdateVerb sends the request to a running daemon, or performs it here.
// cfgPath is the --config file ("" = the default): the no-daemon path
// snapshots and restores exactly that file (merge audit finding 8).
func runUpdateVerb(cmd *cobra.Command, cfgPath string, req updateApplyRequest) error {
	ctx := cmd.Context()
	out := cmd.OutOrStdout()
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		return fmt.Errorf("observer update: loading the config: %w", err)
	}
	if !cfg.Update.Enabled {
		return fmt.Errorf("observer update: [update].enabled is false on this node; nothing to do")
	}

	resp, reached, err := askDaemonToUpdate(ctx, cfg, req)
	if err != nil {
		return err
	}
	if reached {
		return printUpdateResponse(out, resp)
	}

	// REVIEW-4 P4-09: "nothing answered the dashboard address" is not "no
	// daemon". A daemon built without ui.dashboard (or started with
	// --no-dashboard, or on another address) still holds the database and the
	// proxy. Applying or rolling back here would swap its binary, or rename a
	// snapshot over its open database, with no drain and nobody watching the
	// successor. The start lock beside the database is in every build, so it
	// decides. A dry run changes nothing and still runs.
	if lock, live := liveDaemonFor(cfg.Observer.DBPath); live && !req.DryRun {
		addr := resolveDashboardAddr("", cfg.Dashboard.Addr, "127.0.0.1:8081")
		msg := updateUnderDaemonRefusal(lock, cfg.Observer.DBPath, addr, req.Rollback)
		fmt.Fprintln(out, msg)
		return fmt.Errorf("observer update: refused: a running daemon (pid %d) holds this database", lock.PID)
	}

	fmt.Fprintln(out, "No running daemon answered on the dashboard address, so this apply runs")
	fmt.Fprintln(out, "in the CLI process. There are no listeners to hand over, so the")
	fmt.Fprintln(out, "fork-exec-and-watch handshake does not apply: the --version probe of the")
	fmt.Fprintln(out, "staged binary is the acceptance gate, and the previous binary is still")
	fmt.Fprintln(out, "preserved for `observer update rollback`.")
	return runUpdateLocally(ctx, out, cfg, cfgPath, req)
}

// updateUnderDaemonRefusal is the one reason an update verb prints when a
// daemon holds this database but did not answer the update endpoint
// (REVIEW-4 P4-09). Refusing is the D-514 data-safety exception, so it names
// the cause and the fix: the daemon's own update loop for an apply, or stop
// the daemon (route off first) and run the verb again.
func updateUnderDaemonRefusal(lock diag.LockInfo, dbPath, addr string, rollback bool) string {
	verb, effect := "apply", "swap the binary"
	if rollback {
		verb, effect = "rollback", "restore the previous binary (and, when the schema advanced, rename the database snapshot over the open database)"
	}
	cause := fmt.Sprintf("it serves no dashboard on %s (started with --no-dashboard, or listening on another address)", addr)
	if note := dashboardNotInBuildNote(); note != "" {
		cause = note + ", so the daemon serves no update endpoint"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "observer update %s refused: an observer daemon (pid %d, lock %s) is running on this database, but %s.\n",
		verb, lock.PID, diag.LockPath(filepath.Dir(dbPath), lock.PID), cause)
	fmt.Fprintf(&b, "Running the %s in this process would %s underneath it, with no drain and no handshake.\n", verb, effect)
	b.WriteString("Fix:\n")
	if !rollback {
		b.WriteString("  - let the daemon apply it itself: its update loop applies an eligible update when [update].auto_apply is on; or\n")
	}
	if dashboardInBuild {
		b.WriteString("  - if the daemon serves its dashboard on another address, point this command at it with OBSERVER_DASHBOARD_ADDR; or\n")
	}
	fmt.Fprintf(&b, "  - stop that daemon (take any tool's proxy route off first: docs/daemon-restart-runbook.md), run `observer update %s` again, then start it.\n", verb)
	b.WriteString("If that pid is not an observer daemon, the lock is stale: remove the lock file and run this again.")
	return b.String()
}

// askDaemonToUpdate posts the request to the running daemon.
//
// reached=false means no daemon answered, which is a normal condition, not an
// error: the CLI then performs the apply itself.
func askDaemonToUpdate(ctx context.Context, cfg config.Config, req updateApplyRequest) (updateApplyResponse, bool, error) {
	addr := resolveDashboardAddr("", cfg.Dashboard.Addr, "127.0.0.1:8081")
	body, err := json.Marshal(req)
	if err != nil {
		return updateApplyResponse{}, false, err
	}
	rctx, cancel := context.WithTimeout(ctx, updateDaemonTimeout)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(rctx, http.MethodPost, "http://"+addr+updateAPIPath, bytes.NewReader(body))
	if err != nil {
		return updateApplyResponse{}, false, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: updateDaemonTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		// No daemon (or it is not serving the dashboard). Not an error.
		return updateApplyResponse{}, false, nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		// A daemon that predates this endpoint. Say so rather than silently
		// applying underneath it, which would swap the binary of a running
		// process with nobody watching the successor.
		return updateApplyResponse{}, false, fmt.Errorf(
			"observer update: a daemon is running on %s but does not serve %s - stop it, or upgrade it first",
			addr, updateAPIPath)
	}
	var out updateApplyResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return updateApplyResponse{}, false, fmt.Errorf("observer update: the daemon's reply could not be decoded: %w", err)
	}
	if out.Error != "" {
		return out, true, fmt.Errorf("observer update: %s", out.Error)
	}
	return out, true, nil
}

// printUpdateResponse renders the daemon's answer.
func printUpdateResponse(w io.Writer, resp updateApplyResponse) error {
	if resp.Accepted {
		// The daemon answers 202: it took the request and is running the
		// drain, the swap and the handshake on its own budget rather than on
		// this request's. Saying so beats a "state: applying" line the reader
		// would take for a finished answer.
		fmt.Fprintln(w, "The daemon accepted this request and is running it now.")
		if resp.EventID > 0 {
			fmt.Fprintf(w, "Ledger event %d. Follow it with `observer update history`.\n", resp.EventID)
		} else {
			fmt.Fprintln(w, "Follow it with `observer update history`.")
		}
		if resp.Detail != "" {
			fmt.Fprintf(w, "%s\n", resp.Detail)
		}
		return nil
	}
	if len(resp.Steps) > 0 {
		fmt.Fprintln(w, "Plan:")
		for i, s := range resp.Steps {
			fmt.Fprintf(w, "  %d. %s\n", i+1, s)
		}
		return nil
	}
	fmt.Fprintf(w, "state: %s\n", resp.State)
	if resp.Reason != "" {
		fmt.Fprintf(w, "reason: %s\n", resp.Reason)
	}
	if resp.ErrorClass != "" {
		fmt.Fprintf(w, "error class: %s\n", resp.ErrorClass)
	}
	if resp.Detail != "" {
		fmt.Fprintf(w, "%s\n", resp.Detail)
	}
	return nil
}

// runUpdateLocally performs the apply in this process. It is the no-daemon
// path only; see the file doc for why.
func runUpdateLocally(ctx context.Context, w io.Writer, cfg config.Config, cfgPath string, req updateApplyRequest) error {
	s, closeDB, err := openUpdateStore(ctx, cfgPath)
	if err != nil {
		return err
	}
	defer closeDB()

	st, err := s.LoadUpdateState(ctx)
	if err != nil {
		return err
	}
	if req.Rollback {
		return runLocalRollback(ctx, w, s, st, cfg, cfgPath)
	}
	if strings.TrimSpace(st.ManifestJSON) == "" {
		return fmt.Errorf("observer update: this node holds no accepted manifest; run `observer update check` while the daemon is enrolled and running")
	}
	man, err := update.DecodeManifest([]byte(st.ManifestJSON))
	if err != nil {
		return fmt.Errorf("observer update: the stored manifest could not be decoded: %w", err)
	}
	art, ok := update.SelectArtifact(man, "agent", runtime.GOOS, runtime.GOARCH)
	if !ok {
		return fmt.Errorf("observer update: manifest %d builds nothing for %s/%s", man.ManifestVersion, runtime.GOOS, runtime.GOARCH)
	}
	deps, opts, err := buildLocalApply(ctx, s, cfg, cfgPath, man, art, req)
	if err != nil {
		return err
	}
	deps.WarmUpNotice = w
	out, err := runUpdateApply(ctx, deps, opts)
	_ = printUpdateResponse(w, updateApplyResponse{
		State: string(out.State), Reason: string(out.Reason), ErrorClass: string(out.ErrorClass),
		Detail: out.Detail, Steps: out.Steps, Applied: out.Applied,
		RolledBack: out.RolledBack, Deferred: out.Deferred,
	})
	return err
}

// runLocalRollback restores the previous binary and its pre-apply
// config.toml (cfgPath, "" = the default), and the snapshot when the schema
// advanced, naming the discarded window first.
func runLocalRollback(ctx context.Context, w io.Writer, s *store.Store, st store.UpdateStateRow, cfg config.Config, cfgPath string) error {
	schemaNow, err := s.SchemaVersion(ctx)
	if err != nil {
		return err
	}
	appliedNow, err := s.AppliedMigrationSteps(ctx)
	if err != nil {
		return err
	}
	decision := update.DecideRollback(update.RollbackInput{
		State:                 st.State,
		HasPreviousBinary:     fileExists(st.PreviousBinaryPath),
		PreviousSchemaVersion: st.PreviousSchemaVersion,
		CurrentSchemaVersion:  schemaNow,
		PreviousAppliedSteps:  st.PreviousAppliedSteps,
		CurrentAppliedSteps:   appliedNow,
		HasDBBackup:           fileExists(st.PreviousDBBackupPath),
	})
	if decision.Refuse {
		fmt.Fprintf(w, "rollback refused: %s\n", decision.Reason)
		return fmt.Errorf("observer update rollback: %s", decision.Reason)
	}
	exePath := updateExecutablePath()
	var cfgRes rollbackConfigResult
	if decision.RestoreBinary {
		if err := restoreBinary(osSwapFS{}, runtime.GOOS, st.PreviousBinaryPath, exePath, st.PreviousVersion); err != nil {
			return err
		}
		// The pre-apply config.toml comes back with the binary, through the
		// one restore every rollback path shares; the newer file is kept as
		// a displaced copy beside it. A failure is reported at the end and
		// never skips the database restore (merge audit finding 2).
		cfgRes = restoreRollbackConfig(updateConfigPathFor(cfgPath), st.PreviousBinaryPath, time.Now())
	}
	// writer is the handle the ledger row goes through. The DB-restoring
	// branch replaces the file underneath this process, so it must close its
	// own handle BEFORE the rename (nothing may keep writing to the orphaned
	// inode) and record through a handle on the file that survives.
	var writer updateStateStore = s
	if decision.RestoreDB {
		if cerr := s.CloseDatabase(); cerr != nil {
			fmt.Fprintf(w, "warning: closing the database before restoring the snapshot failed: %v\n", cerr)
		}
		if err := restoreDatabaseSnapshot(st.PreviousDBBackupPath, cfg.Observer.DBPath); err != nil {
			if cfgRes.Err != nil {
				return fmt.Errorf("observer update rollback: %w%s", err, cfgRes.failureNote())
			}
			return err
		}
		reopened, rerr := reopenUpdateStore(cfg.Observer.DBPath)
		if rerr != nil {
			fmt.Fprintf(w, "warning: the snapshot was restored but reopening it failed, so this rollback is not in the ledger: %v\n", rerr)
			writer = nil
		} else {
			writer = reopened
		}
	}
	state, class := decision.State, decision.ErrorClass
	if cfgRes.Err != nil {
		state, class = update.StateFailed, update.ErrorPermission
	}
	fmt.Fprintf(w, "state: %s\n%s\n", state, decision.Reason)
	if cfgRes.Err != nil {
		fmt.Fprintf(w, "the previous binary was restored%s\n", cfgRes.failureNote())
	}
	var cfgErr error
	if cfgRes.Err != nil {
		cfgErr = fmt.Errorf("observer update rollback: the previous binary was restored but config.toml was not: %w", cfgRes.Err)
	}
	if writer == nil {
		return cfgErr
	}
	row := st
	row.State = update.StateRolledBack
	row.TargetVersion = st.PreviousVersion
	row.ErrorClass = class
	if cfgRes.Err != nil {
		row.State = state
	}
	_ = writer.SaveUpdateState(ctx, row)
	detail := "operator-invoked rollback: " + decision.Reason
	if decision.DiscardsDataWindow {
		detail += "; rows ingested after the pre-apply snapshot were discarded"
	}
	detail += cfgRes.failureNote()
	if err := writer.AppendUpdateEvent(ctx, store.UpdateEventRow{
		FromVersion: version, ToVersion: st.PreviousVersion,
		State: row.State, ErrorClass: class,
		Detail: detail,
	}); err != nil {
		return err
	}
	return cfgErr
}

// buildLocalApply wires the CLI-side apply. Download is deliberately absent:
// a CLI with no daemon has no enrolment bearer loaded, so it can only apply
// an artifact the daemon already staged. Saying that plainly is better than
// opening a second fetch path on the node (ruling R8).
func buildLocalApply(ctx context.Context, s *store.Store, cfg config.Config, cfgPath string, man update.Manifest, art update.Artifact, req updateApplyRequest) (applyDeps, applyOptions, error) {
	win, err := update.ParseWindow(cfg.Update.Window)
	if err != nil {
		return applyDeps{}, applyOptions{}, err
	}
	schema, err := s.SchemaVersion(ctx)
	if err != nil {
		return applyDeps{}, applyOptions{}, err
	}
	exePath := resolvedExecutablePath()
	det := update.Detect(update.PathProbe{
		ExecPath: exePath, GOOS: runtime.GOOS,
		Writable: pathIsReplaceable(exePath), SiblingExists: fileExistsIn,
	})
	deps := applyDeps{
		Store: s,
		// No Quiescence: with no daemon there is nothing to drain.
		Download:              nil,
		VerifyVendorSignature: verifyVendorSignature,
		Probe:                 probeBinaryVersion,
		Supervise: func(context.Context, string, string, time.Duration) (handshakeResult, error) {
			return handshakeResult{Ready: true, Detail: "no daemon was running, so the --version probe was the acceptance gate"}, nil
		},
		WarmUp: warmUpNewBinary,
		FS:     osSwapFS{},
		GOOS:   runtime.GOOS,
		Logger: slog.Default(),
		// This process holds the only handle on the live database, so it is
		// the one that must let go before a snapshot is renamed over it.
		CloseDB:     s.CloseDatabase,
		ReopenStore: func() (updateStateStore, error) { return reopenUpdateStore(cfg.Observer.DBPath) },
		FreeBytes:   updateFreeBytes,
	}
	opts := applyOptions{
		Manifest: man, Artifact: art,
		Installed: update.Installed{
			Version: version, SchemaVersion: schema, ExecPath: exePath, Detection: det,
		},
		StateDir:   cfg.Update.StateDir,
		DBPath:     cfg.Observer.DBPath,
		ConfigPath: updateConfigPathFor(cfgPath),
		Window:     win,
		Force:      req.Force,
		DryRun:     req.DryRun,
		// The manifest's own declaration of the target's schema version. Zero
		// still means "may advance", so a pre-field manifest snapshots as
		// before and a declared-equal one skips the VACUUM INTO.
		TargetSchemaVersion: man.SchemaVersion,
		AllowDowngrade:      cfg.Update.AllowDowngrade,
		DrainTimeout:        durationOr(cfg.Update.DrainTimeout, quiesce.DefaultDrainTimeout),
		HandshakeTimeout:    durationOr(cfg.Update.HandshakeTimeout, time.Minute),
		MaxDownloadBytes:    cfg.Update.MaxDownloadBytes,
	}
	return deps, opts, nil
}

// probeBinaryVersion runs a staged binary with --version.
//
// It is bounded and its output is capped: the binary being probed is one this
// node has verified but not yet trusted to run as a daemon, so it gets a
// short leash.
func probeBinaryVersion(ctx context.Context, binPath string) (string, error) {
	pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(pctx, binPath, "--version") //nolint:gosec // a staged artifact this node hash- and signature-verified
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(buf.String()), err
	}
	out := buf.String()
	if len(out) > 4096 {
		out = out[:4096]
	}
	return strings.TrimSpace(out), nil
}

// durationOr parses a config duration with a fallback.
func durationOr(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// openUpdateStore opens the node's database for the update verbs.
func openUpdateStore(ctx context.Context, cfgPath string) (*store.Store, func(), error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		return nil, nil, fmt.Errorf("observer update: loading the config: %w", err)
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return nil, nil, fmt.Errorf("observer update: opening %s: %w", cfg.Observer.DBPath, err)
	}
	return store.New(database), func() { _ = closeDBQuietly(database) }, nil
}

// closeDBQuietly closes a database handle.
func closeDBQuietly(d *sql.DB) error {
	if d == nil {
		return nil
	}
	return d.Close()
}

// loadUpdateStateForCLI reads the node's update state, preferring the
// database (migration 105) and falling back to W1's JSON document.
//
// The fallback is not indefinite compatibility: it exists so a node that
// still holds a pre-105 state file reports the truth instead of "idle" for
// one release. The source is returned so a surface can say which it read.
func loadUpdateStateForCLI(ctx context.Context) (update.NodeState, string, error) {
	return loadUpdateStateForCLIAt(ctx, "")
}

// loadUpdateStateForCLIAt is loadUpdateStateForCLI for a --config file.
func loadUpdateStateForCLIAt(ctx context.Context, cfgPath string) (update.NodeState, string, error) {
	s, closeDB, err := openUpdateStore(ctx, cfgPath)
	if err == nil {
		defer closeDB()
		row, lerr := s.LoadUpdateState(ctx)
		if lerr == nil {
			return row.NodeState, "database", nil
		}
	}
	path, perr := updateStatePath()
	if perr != nil {
		return update.DefaultNodeState(), "none", nil //nolint:nilerr // fail-open: an unreadable state is an idle node, not an error.
	}
	st, lerr := loadUpdateNodeState(path)
	if lerr != nil {
		return update.DefaultNodeState(), "none", nil //nolint:nilerr // same fail-open rule.
	}
	return st, "file", nil
}

// updateStateDirFor resolves [update].state_dir with the env override W1
// introduced still winning, so a relocated home keeps working.
func updateStateDirFor(cfg config.Config) string {
	if dir := strings.TrimSpace(os.Getenv(updateStateDirEnv)); dir != "" {
		return dir
	}
	if dir := strings.TrimSpace(cfg.Update.StateDir); dir != "" {
		return dir
	}
	return config.DefaultUpdateStateDir
}
