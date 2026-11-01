//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/watcher"
)

// terminal_sandbox_oci_ingest_linux.go is the host helper's one-shot read
// of an unwatched run's projected transcripts (lane LEFT-SBX): a CLI launch
// has no daemon watcher, so the helper reads them once after the run,
// before it removes the projection.

// ociIngestProjectionFn reads one unwatched transcript root once into the
// daemon's database (the config at configPath), bound to the run; a
// variable so a test can stand in for the database.
var ociIngestProjectionFn = ociIngestProjection

// ociIngestProjection opens the daemon's database the way `observer scan
// --adapter <tool>` does and reads root once through the watcher's one-shot
// seam (watcher.IngestProjectionOnce).
func ociIngestProjection(ctx context.Context, configPath, tool string, root sandboxoci.TranscriptRoot, bind watcher.ProjectionBinding) (int, error) {
	w, cleanup, err := buildWatcherWithOverride(ctx, configPath, tool)
	if err != nil {
		return 0, err
	}
	defer cleanup()
	res, err := w.IngestProjectionOnce(ctx, tool, root.Host, root.Box, bind)
	return res.FilesProcessed, err
}

// ociIngestUnwatched reads the transcripts of a run no watcher took (a CLI
// launch, `observer <tool> --observer-sandbox oci-runsc`) once, before the
// helper removes the projection (lane LEFT-SBX). A run the daemon watched,
// or one with no transcript roots, reads nothing here. Each failure is said
// on the run's terminal; the projection is still removed after.
func ociIngestUnwatched(plan ociPlanFile, t ociTerm) {
	if plan.TranscriptsWatched || len(plan.Transcripts) == 0 {
		return
	}
	if plan.ConfigPath == "" || plan.Tool == "" {
		fmt.Fprintf(t.out, "\r\n[observer: this run's transcripts were not watched and the plan names no config, so they are not kept]\r\n")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bind := watcher.ProjectionBinding{RunID: plan.Create.RunID, Workspace: plan.Create.WorkDir}
	for _, root := range plan.Transcripts {
		if _, err := ociIngestProjectionFn(ctx, plan.ConfigPath, plan.Tool, root, bind); err != nil {
			fmt.Fprintf(t.out, "\r\n[observer: this run's transcripts under %s were not read: %v]\r\n", root.Host, err)
		}
	}
}
