//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// sandbox_readopt_cmd_linux.go holds the user-facing verbs and routes of
// re-adoption and the Podman checkpoint (lane GATES-SBX): `observer sandbox
// runs` (the offers), `readopt <run>` (re-adopt, or --end), `checkpoint
// <run>` and `restore <run>`, and the dashboard's Local routes that list the
// offers and end, checkpoint or restore one. A checkpoint or restore runs
// only from these, never from a timer, a sweep or the update path.

// The dashboard's "Re-attach in a terminal" (dashboard CLI parity plan item
// B-G3, decision P-3) runs `observer sandbox readopt <run>` in a dashboard
// terminal; readoptAttachCheck answers whether the run is one it offers now,
// since this file alone owns the offer files. The registration with the
// dashboard lives in sandbox_readopt_attach_dash_linux.go, behind the
// dashboard's own build tag, so a build without the dashboard links none of
// it (tests/invariant TestComponentsL1PackageAbsence).

// readoptAttachStates are the run states a re-attach takes: an offer that
// is still open, or one held while an update waits (readoptViews' states).
var readoptAttachStates = map[string]bool{"offered": true, "held": true}

// readoptAttachCheck reports why run cannot be re-attached now (nil when it
// can): the component off, a malformed id, no offer, or an offer in a state
// a re-attach does not take (checkpointed, already re-adopted, expiring).
func readoptAttachCheck(ctx context.Context, run string) error {
	if !readoptLoadSettings(ctx).active {
		return fmt.Errorf("re-adoption is off on this node; select %s in Settings > Components", readoptComponent)
	}
	if !sandboxoci.ValidToken(run) {
		return errors.New("not a run id")
	}
	obs, err := readoptCLIObserverDir()
	if err != nil {
		return err
	}
	for _, v := range readoptViews(obs) {
		if v.RunID != run {
			continue
		}
		if !readoptAttachStates[v.State] {
			return fmt.Errorf("run %s is %s, so it cannot be re-attached now", run, v.State)
		}
		return nil
	}
	return readoptNotOffered(obs, run)
}

// readoptRunView is one offer as the CLI and the dashboard show it.
type readoptRunView struct {
	RunID        string    `json:"run_id"`
	Tool         string    `json:"tool"`
	Project      string    `json:"project"`
	State        string    `json:"state"`
	Code         string    `json:"code"`
	Row          string    `json:"row,omitempty"`
	Reason       string    `json:"reason"`
	OfferedAt    time.Time `json:"offered_at"`
	Expires      time.Time `json:"expires,omitzero"`
	ReadoptedAt  time.Time `json:"readopted_at,omitzero"`
	Checkpointed bool      `json:"checkpointed"`
	Command      string    `json:"command"`
}

// readoptViews renders the offers under observerDir.
func readoptViews(observerDir string) []readoptRunView {
	now := readoptNow()
	var out []readoptRunView
	for _, e := range readoptOffered(observerDir) {
		v := readoptRunView{
			RunID: e.kept.RunID, Tool: e.kept.Facts.Tool, Project: e.kept.Facts.ProjectRoot,
			Code: string(e.offer.Code), Row: e.offer.Row, Reason: e.offer.Reason, OfferedAt: e.offer.OfferedAt,
			Expires: e.offer.Expires, ReadoptedAt: e.offer.ReadoptedAt, Checkpointed: e.offer.Checkpointed,
		}
		switch {
		case e.offer.Checkpointed && now.Before(e.offer.Expires):
			v.State, v.Command = "checkpointed", "observer sandbox restore "+v.RunID
		case e.offer.Checkpointed:
			v.State = "expiring"
		case !e.offer.ReadoptedAt.IsZero():
			v.State = "readopted"
		case e.offer.Code == sandboxadopt.CodeHeldForUpdate:
			v.State, v.Command = "held", "observer sandbox readopt "+v.RunID
		case now.Before(e.offer.Expires):
			v.State, v.Command = "offered", "observer sandbox readopt "+v.RunID
		default:
			v.State = "expiring"
		}
		out = append(out, v)
	}
	return out
}

// readoptCLIObserverDir is the observer dir the verbs act on (a test seam).
var readoptCLIObserverDir = hostedObserverDir

func newSandboxRunsCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "runs",
		Short: "List local container runs offered for re-adoption or waiting for a restore (beta)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !readoptLoadSettings(cmd.Context()).active {
				return fmt.Errorf("re-adoption is off on this node; select %s in Settings > Components", readoptComponent)
			}
			obs, err := readoptCLIObserverDir()
			if err != nil {
				return err
			}
			return renderReadoptRuns(cmd.OutOrStdout(), obs, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print JSON")
	return cmd
}

// renderReadoptRuns prints the offers under obs, each with the table row
// that decided it, then the runs the re-adoption step recently ended with
// the row that ended each (F-046).
func renderReadoptRuns(w io.Writer, obs string, asJSON bool) error {
	views := readoptViews(obs)
	ended := readoptEndedList(obs)
	if asJSON {
		if ended == nil {
			ended = []readoptEnded{}
		}
		return json.NewEncoder(w).Encode(map[string]any{"runs": views, "ended": ended})
	}
	if len(views) == 0 {
		fmt.Fprintln(w, "No local container run is offered for re-adoption.")
	}
	for _, v := range views {
		fmt.Fprintf(w, "%s  %s  %s  %s\n", v.RunID, v.State, v.Tool, v.Project)
		if v.Row != "" {
			fmt.Fprintf(w, "  decided by row %s (%s)\n", v.Row, v.Code)
		}
		if !v.Expires.IsZero() && v.State == "offered" {
			fmt.Fprintf(w, "  removed at %s unless re-adopted\n", v.Expires.Local().Format(time.RFC3339))
		}
		if !v.Expires.IsZero() && v.State == "checkpointed" {
			fmt.Fprintf(w, "  checkpoint removed at %s unless restored\n", v.Expires.Local().Format(time.RFC3339))
		}
		if v.Command != "" {
			fmt.Fprintf(w, "  %s\n", v.Command)
		}
	}
	if len(ended) > 0 {
		fmt.Fprintln(w, "Recently ended by the re-adoption step (newest first):")
		for _, x := range ended {
			fmt.Fprintf(w, "%s  ended %s  row %s (%s): %s\n", x.RunID, x.At.Local().Format(time.RFC3339), x.Row, x.Code, x.Reason)
		}
	}
	return nil
}

func newSandboxReadoptCmd() *cobra.Command {
	var end bool
	cmd := &cobra.Command{
		Use:   "readopt <run id>",
		Short: "Re-attach a local container run whose helper went away, in this terminal (beta)",
		Long: "Re-attaches a container run that `observer sandbox runs` offers: a new helper serves its capture relay with new keys and attaches to the container. " +
			"The terminal starts with an empty scrollback (a marker says so) and capture resumes at the next event; the gap is recorded. --end ends the run instead.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			obs, err := readoptCLIObserverDir()
			if err != nil {
				return err
			}
			if end {
				return readoptEndByUser(cmd.Context(), obs, args[0], cmd.OutOrStdout())
			}
			t, done := realOCITerm()
			defer done()
			code, err := readoptRunHelper(cmd.Context(), obs, args[0], t)
			if err != nil {
				return err
			}
			if code != 0 {
				return exitErr(code)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&end, "end", false, "end the run and remove its container instead")
	return cmd
}

func newSandboxCheckpointCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "checkpoint <run id>",
		Short: "Checkpoint an offered container run to a local file (rootful Podman with CRIU; beta)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			obs, err := readoptCLIObserverDir()
			if err != nil {
				return err
			}
			return readoptCheckpoint(cmd.Context(), obs, args[0], cmd.OutOrStdout())
		},
	}
}

func newSandboxRestoreCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restore <run id>",
		Short: "Restore a checkpointed container run, then offer it for re-adoption (beta)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			obs, err := readoptCLIObserverDir()
			if err != nil {
				return err
			}
			return readoptRestore(cmd.Context(), obs, args[0], cmd.OutOrStdout())
		},
	}
}

// readoptEndByUser ends an offered run on the user's word: its record goes
// and the daemon's next sweep removes its container.
func readoptEndByUser(ctx context.Context, observerDir, runID string, out io.Writer) error {
	if !readoptLoadSettings(ctx).active {
		return fmt.Errorf("re-adoption is off on this node; select %s in Settings > Components", readoptComponent)
	}
	if !sandboxoci.ValidToken(runID) {
		return errors.New("not a run id")
	}
	e := readoptRead(observerDir, runID)
	if !e.hasOffer {
		return readoptNotOffered(observerDir, runID)
	}
	readoptEndOrDecline(observerDir, runID, e)
	fmt.Fprintf(out, "Run %s ended; its container is removed at the daemon's next sweep.\n", runID)
	return nil
}

// readoptCRIUVersion runs `criu --version` (a variable so tests set it).
var readoptCRIUVersion = func(ctx context.Context) string {
	p, err := exec.LookPath("criu")
	if err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(cctx, p, "--version").Output() //nolint:gosec // G204: the criu found on PATH, fixed argv
	if err != nil {
		return ""
	}
	return sandboxadopt.ParseCRIUVersion(string(b))
}

// readoptCheckpointFacts reads the checkpoint table's facts.
func readoptCheckpointFacts(ctx context.Context, observerDir string, p readoptPrepared, capBytes int64) sandboxadopt.CheckpointFacts {
	f := sandboxadopt.CheckpointFacts{UserAction: true, Engine: p.eng.facts, Running: p.ct.Running, CapBytes: capBytes}
	if p.eng.id.Engine == sandboxoci.EnginePodman {
		if raw, err := p.c.ContainerInspectLibpod(ctx, p.ct.ID); err == nil {
			f.Runtime = sandboxengine.ContainerOCIRuntime(raw)
		}
	}
	if p.entry.plan.Create.Runtime != "" {
		f.Runtime = p.entry.plan.Create.Runtime
	}
	f.CRIUVersion = readoptCRIUVersion(ctx)
	if fi, err := os.Lstat(readoptRunDir(observerDir, p.entry.kept.RunID)); err == nil && fi.IsDir() {
		f.StateDirPerm, f.StateDirOwned = uint32(fi.Mode().Perm()), ownedByMe(fi)
	}
	return f
}

// readoptCheckpoint checkpoints an offered run to an owner-only file in its
// state dir and removes the container (the export holds it).
func readoptCheckpoint(ctx context.Context, observerDir, runID string, out io.Writer) error {
	p, err := readoptPrepare(ctx, observerDir, runID)
	if err != nil {
		return err
	}
	set := readoptLoadSettings(ctx)
	plan, refusal := sandboxadopt.PlanCheckpoint(runID, readoptCheckpointFacts(ctx, observerDir, p, set.capBytes))
	if refusal != nil {
		return refusal
	}
	path := filepath.Join(readoptRunDir(observerDir, runID), plan.ExportName)
	f, err := ociCreateExcl(path)
	if err != nil {
		return fmt.Errorf("create the export: %w", err)
	}
	n, err := p.c.ContainerCheckpointExport(ctx, p.ct.ID, f, plan.CapBytes)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if r := sandboxadopt.ExportVerdict(n, plan.CapBytes); r != nil {
			err = r
		}
	} else if errors.Is(err, sandboxengine.ErrExportCap) {
		err = sandboxadopt.ExportVerdict(n, plan.CapBytes)
	}
	if err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("checkpoint: %w", err)
	}
	if err := p.c.ContainerRemove(ctx, p.ct.ID); err != nil {
		return fmt.Errorf("the checkpoint was written to %s but the container could not be removed: %w", path, err)
	}
	offer := p.entry.offer
	offer.Checkpointed, offer.Export = true, plan.ExportName
	// Kept for a bounded time, then the sweep removes the record and the
	// export (audit F9).
	offer.Expires = readoptNow().Add(sandboxadopt.CheckpointRetention)
	if err := readoptWriteFile(readoptRunDir(observerDir, runID), readoptOfferFile, offer); err != nil {
		return err
	}
	fmt.Fprintf(out, "Run %s checkpointed to %s (%d bytes, this machine only). Restore it with: observer sandbox restore %s\n", runID, path, n, runID)
	return nil
}

// readoptRestore restores a checkpointed run and offers it again; a
// restored container that lost its relay socket dir or its plan is removed
// and the run ended, never run without capture.
func readoptRestore(ctx context.Context, observerDir, runID string, out io.Writer) error {
	set := readoptLoadSettings(ctx)
	if !set.active {
		return fmt.Errorf("re-adoption is off on this node; select %s in Settings > Components", readoptComponent)
	}
	if !sandboxoci.ValidToken(runID) {
		return errors.New("not a run id")
	}
	e := readoptRead(observerDir, runID)
	if !e.hasOffer || !e.offer.Checkpointed || !e.planOK || !e.keptOK {
		return fmt.Errorf("run %s has no checkpoint to restore", runID)
	}
	// A restore rebuilds the run's host services from the kept argv: today's
	// settings, floors and backend list first (audit F4).
	if err := readoptPolicyCheck(e.kept.Policy); err != nil {
		return err
	}
	c, err := ociEngineClient(e.plan.Socket, e.plan.APIVersion)
	if err != nil {
		return err
	}
	if err := readoptCheckSocket(e.plan); err != nil {
		return err
	}
	eng := readoptReadEngine(ctx, c)
	if eng.err != nil {
		return fmt.Errorf("%s: %w", sandboxoci.VerdictEngineUnreachable, eng.err)
	}
	export := filepath.Join(readoptRunDir(observerDir, runID), e.offer.Export)
	fi, ferr := os.Lstat(export)
	rf := sandboxadopt.RestoreFacts{
		Checkpoint:  sandboxadopt.CheckpointFacts{UserAction: true, Engine: eng.facts, Runtime: e.plan.Create.Runtime, CRIUVersion: readoptCRIUVersion(ctx), StateDirPerm: 0o700, StateDirOwned: true},
		ExportOwned: ferr == nil && fi.Mode().IsRegular() && ownedByMe(fi) && fi.Mode().Perm()&0o077 == 0,
	}
	if dfi, err := os.Lstat(readoptRunDir(observerDir, runID)); err == nil {
		rf.Checkpoint.StateDirPerm, rf.Checkpoint.StateDirOwned = uint32(dfi.Mode().Perm()), ownedByMe(dfi)
	}
	if r := sandboxadopt.PlanRestore(rf); r != nil {
		return r
	}
	src, err := os.OpenFile(export, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: the run's own export, owner-checked above
	if err != nil {
		return err
	}
	installID, err := ociInstallID(observerDir)
	if err != nil {
		_ = src.Close()
		return err
	}
	id, err := c.ContainerRestoreImport(ctx, sandboxoci.ContainerName(installID, runID), src)
	_ = src.Close()
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	h, herr := readoptHostArgs(e.kept)
	rf.SocketDirIntact = herr == nil && readoptSockDirCheck(h.SockDir) == nil
	if v := readoptReadBack(ctx, c, id, eng.id, e.plan.Create); v.OK() {
		rf.ReadBackOK = true
	} else {
		rf.ReadBackReason = v.Reason
	}
	if r := sandboxadopt.RestoredVerdict(rf); r != nil {
		_ = c.ContainerRemove(context.WithoutCancel(ctx), id)
		readoptEndOrDecline(observerDir, runID, e)
		return r
	}
	offer := e.offer
	offer.Checkpointed, offer.Export, offer.ContainerID = false, "", id
	offer.OfferedAt = readoptNow()
	offer.Expires = offer.OfferedAt.Add(set.bound)
	_ = os.Remove(export)
	if err := readoptWriteFile(readoptRunDir(observerDir, runID), readoptOfferFile, offer); err != nil {
		return err
	}
	fmt.Fprintf(out, "Run %s restored. Re-adopt it with: observer sandbox readopt %s\n", runID, runID)
	return nil
}

// readoptDashboardRoutes are the re-adoption panel's routes: Local, 404
// while the component is off, every action behind the confirm token.
func readoptDashboardRoutes(string) []dashapi.ExtraRoute {
	gate := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !readoptLoadSettings(r.Context()).active {
				http.NotFound(w, r)
				return
			}
			h(w, r)
		}
	}
	action := func(do func(ctx context.Context, obs, run string, out io.Writer) error) http.HandlerFunc {
		return gate(func(w http.ResponseWriter, r *http.Request) {
			if !hostedConfirmed(w, r) {
				return
			}
			var body struct {
				Run string `json:"run"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || !sandboxoci.ValidToken(strings.TrimSpace(body.Run)) {
				http.Error(w, "a run id is required", http.StatusBadRequest)
				return
			}
			obs, err := readoptCLIObserverDir()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var msg strings.Builder
			if err := do(r.Context(), obs, strings.TrimSpace(body.Run), &msg); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"message": strings.TrimSpace(msg.String())})
		})
	}
	return []dashapi.ExtraRoute{
		{Pattern: "GET /api/terminal/sandbox/readopt", Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request) {
			tok := hostedConfirmToken(w, r)
			obs, err := readoptCLIObserverDir()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"runs": readoptViews(obs), "confirm_token": tok})
		})},
		{Pattern: "POST /api/terminal/sandbox/readopt/end", Capability: dashapi.CapabilityLocal, Handler: action(readoptEndByUser)},
		{Pattern: "POST /api/terminal/sandbox/readopt/checkpoint", Capability: dashapi.CapabilityLocal, Handler: action(readoptCheckpoint)},
		{Pattern: "POST /api/terminal/sandbox/readopt/restore", Capability: dashapi.CapabilityLocal, Handler: action(readoptRestore)},
	}
}
