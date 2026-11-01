//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// cpSetup is an offered run on a fake rootful Podman with CRIU 3.19 and a
// read-back that passes (the libpod inspect shape is the oci lane's; the
// read-back itself is pinned by its own tests).
func cpSetup(t *testing.T, podman bool, criu string, capMiB int) (*raFake, raRun) {
	t.Helper()
	f := newRAFake(t)
	f.podman = podman
	raSettings(t, true, 0)
	old := readoptLoadSettings
	readoptLoadSettings = func(ctx context.Context) readoptSettings {
		s := old(ctx)
		if capMiB > 0 {
			s.capBytes = int64(capMiB)
		}
		return s
	}
	oldRB, oldCRIU := readoptReadBack, readoptCRIUVersion
	readoptReadBack = func(context.Context, *sandboxengine.Client, string, sandboxoci.Identity, sandboxoci.CreatePlan) sandboxoci.Verdict {
		return sandboxoci.Verdict{Code: sandboxoci.VerdictAvailable}
	}
	readoptCRIUVersion = func(context.Context) string { return criu }
	t.Cleanup(func() { readoptLoadSettings, readoptReadBack, readoptCRIUVersion = old, oldRB, oldCRIU })
	ra := raSetup(t, f, "run0000000000000010")
	raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if e := readoptRead(ra.obs, ra.runID); !e.hasOffer {
		t.Fatalf("not offered: %v", e.keptErr)
	}
	// The fake's export is the container's own create body, so its restore
	// rebuilds the same container.
	f.mu.Lock()
	f.export, _ = json.Marshal(f.bodies[ra.cid])
	f.mu.Unlock()
	return f, ra
}

// TestCheckpointRefusedPerEngine: Docker and a host without CRIU are
// refused with checkpoint_unsupported naming why, and nothing is written.
func TestCheckpointRefusedPerEngine(t *testing.T) {
	cases := []struct {
		name   string
		podman bool
		criu   string
		want   string
	}{
		{"docker", false, "3.19", "Docker"},
		{"podman without criu", true, "", "criu is not installed"},
		{"podman old criu", true, "3.10", "older than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, ra := cpSetup(t, c.podman, c.criu, 0)
			err := readoptCheckpoint(context.Background(), ra.obs, ra.runID, &strings.Builder{})
			var r *sandboxadopt.Refusal
			if !errors.As(err, &r) || r.Code != sandboxadopt.CodeCheckpointUnsupported || !strings.Contains(r.Reason, c.want) {
				t.Fatalf("checkpoint = %v, want checkpoint_unsupported naming %q", err, c.want)
			}
			if _, err := os.Lstat(filepath.Join(readoptRunDir(ra.obs, ra.runID), ra.runID+sandboxadopt.ExportSuffix)); err == nil {
				t.Fatal("a refused checkpoint wrote an export")
			}
			if len(f.removed) != 0 {
				t.Fatal("a refused checkpoint removed the container")
			}
		})
	}
}

// TestCheckpointAndRestore: the export is an owner-only file in the run's
// 0700 state dir, the container goes, and the restore re-enters the
// re-adoption table (the next sweep offers the restored container).
func TestCheckpointAndRestore(t *testing.T) {
	f, ra := cpSetup(t, true, "3.19", 0)
	if err := readoptCheckpoint(context.Background(), ra.obs, ra.runID, &strings.Builder{}); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	export := filepath.Join(readoptRunDir(ra.obs, ra.runID), ra.runID+sandboxadopt.ExportSuffix)
	fi, err := os.Lstat(export)
	if err != nil || fi.Mode().Perm() != 0o600 || fi.Size() == 0 {
		t.Fatalf("export: %v %v", fi, err)
	}
	if di, _ := os.Lstat(readoptRunDir(ra.obs, ra.runID)); di.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v", di.Mode().Perm())
	}
	if len(f.removed) != 1 || f.removed[0] != ra.cid {
		t.Fatalf("the checkpointed container was not removed: %v", f.removed)
	}
	e := readoptRead(ra.obs, ra.runID)
	if !e.offer.Checkpointed || readoptLiveCount() != 0 {
		t.Fatalf("checkpointed = %v, live = %d", e.offer.Checkpointed, readoptLiveCount())
	}
	// A sweep keeps the checkpointed run (no container, waiting for its
	// restore): its record stays.
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err != nil {
		t.Fatalf("the checkpointed run's record went: %v", err)
	}
	if err := readoptRestore(context.Background(), ra.obs, ra.runID, &strings.Builder{}); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, err := os.Lstat(export); err == nil {
		t.Fatal("the export outlived its restore")
	}
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	e = readoptRead(ra.obs, ra.runID)
	if !e.hasOffer || e.offer.Checkpointed || e.offer.Code != sandboxadopt.CodeOffered || e.offer.ContainerID != "restored1" {
		t.Fatalf("after restore: %+v", e.offer)
	}
}

// TestCheckpointExportCap: an export over the cap is removed and refused;
// the container keeps running (leaveRunning) and stays offered.
func TestCheckpointExportCap(t *testing.T) {
	f, ra := cpSetup(t, true, "3.19", 8)
	err := readoptCheckpoint(context.Background(), ra.obs, ra.runID, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("checkpoint over the cap = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(readoptRunDir(ra.obs, ra.runID), ra.runID+sandboxadopt.ExportSuffix)); err == nil {
		t.Fatal("the over-cap export was kept")
	}
	f.mu.Lock()
	running := f.running[ra.cid]
	f.mu.Unlock()
	if !running || len(f.removed) != 0 {
		t.Fatalf("a refused export ended the run: running=%v removed=%v", running, f.removed)
	}
}

// TestRestoreLosingTheRelayIsRefused: a restore whose relay socket dir did
// not survive is refused, the restored container removed and the run ended
// (never run without capture).
func TestRestoreLosingTheRelayIsRefused(t *testing.T) {
	f, ra := cpSetup(t, true, "3.19", 0)
	if err := readoptCheckpoint(context.Background(), ra.obs, ra.runID, &strings.Builder{}); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	_ = os.RemoveAll(ra.sockDir)
	err := readoptRestore(context.Background(), ra.obs, ra.runID, &strings.Builder{})
	var r *sandboxadopt.Refusal
	if !errors.As(err, &r) || r.Code != sandboxadopt.CodeRestoreLostCapture {
		t.Fatalf("restore = %v, want restore_lost_capture", err)
	}
	f.mu.Lock()
	removed := strings.Join(f.removed, ",")
	f.mu.Unlock()
	if !strings.Contains(removed, "restored1") {
		t.Fatalf("the restored container was not removed: %v", removed)
	}
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
		t.Fatal("the run was not ended")
	}
	if _, err := os.Lstat(readoptRunDir(ra.obs, ra.runID)); err == nil {
		t.Fatal("the entry outlived the refused restore")
	}
}

// TestCheckpointNeverAutomatic: no sweep, offer or bound ever checkpoints:
// the only callers are the verb and the dashboard route.
func TestCheckpointNeverAutomatic(t *testing.T) {
	f, ra := cpSetup(t, true, "3.19", 0)
	old := readoptNow
	readoptNow = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	defer func() { readoptNow = old }()
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	for _, call := range f.callList() {
		if strings.Contains(call, "/checkpoint") || strings.Contains(call, "/restore") {
			t.Fatalf("a sweep called %s", call)
		}
	}
}

// TestCheckpointedRunReapedAfterItsRetention (audit F9): a checkpoint is
// kept for sandboxadopt.CheckpointRetention while the component is on; a
// sweep after that removes its relay record and its export and ends the
// run.
func TestCheckpointedRunReapedAfterItsRetention(t *testing.T) {
	f, ra := cpSetup(t, true, "3.19", 0)
	ended := raEnder(t)
	if err := readoptCheckpoint(context.Background(), ra.obs, ra.runID, &strings.Builder{}); err != nil {
		t.Fatalf("checkpoint: %v", err)
	}
	e := readoptRead(ra.obs, ra.runID)
	if left := time.Until(e.offer.Expires); left < sandboxadopt.CheckpointRetention-time.Minute || left > sandboxadopt.CheckpointRetention+time.Minute {
		t.Fatalf("the checkpoint is kept %v, want %v", left, sandboxadopt.CheckpointRetention)
	}
	export := filepath.Join(readoptRunDir(ra.obs, ra.runID), ra.runID+sandboxadopt.ExportSuffix)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if _, err := os.Lstat(export); err != nil {
		t.Fatal("a checkpoint within its retention was removed")
	}
	oldNow := readoptNow
	readoptNow = func() time.Time { return time.Now().UTC().Add(sandboxadopt.CheckpointRetention + time.Minute) }
	t.Cleanup(func() { readoptNow = oldNow })
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if _, err := os.Lstat(export); err == nil {
		t.Fatal("the export outlived the checkpoint's retention")
	}
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
		t.Fatal("the relay record outlived the checkpoint's retention")
	}
	if len(*ended) != 1 || (*ended)[0] != ra.runID {
		t.Fatalf("ended %v", *ended)
	}
}
