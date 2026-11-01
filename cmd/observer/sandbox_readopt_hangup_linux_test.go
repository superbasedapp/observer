//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
)

// TestOCIRunKeepsTheContainerOnADaemonExitHangup (R-033): when the hangup
// check says keep, the helper leaves the running container alone (no stop,
// no remove) and reports the hung-up status; when it says stop, the run
// stops as before (TestOCIRunStopRequest).
func TestOCIRunKeepsTheContainerOnADaemonExitHangup(t *testing.T) {
	f := newOCIFake(t)
	tt := newOCITestTerm()
	var detached atomic.Bool
	tt.term.detached = &detached
	tt.term.keepOnHangup = func() bool { return true }
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	}()
	tt.waitFor(t, "agent$ ")
	tt.stop <- "hangup"
	select {
	case code := <-done:
		if code != ociDetachedCode {
			t.Fatalf("exit %d, want %d", code, ociDetachedCode)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the helper never left the container")
	}
	if !detached.Load() {
		t.Fatal("the helper did not record that it left the container")
	}
	stopped := f.callIndex("POST /containers/c1/stop") >= 0
	f.mu.Lock()
	removed := append([]string(nil), f.removed...)
	f.mu.Unlock()
	if stopped || len(removed) != 0 {
		t.Fatalf("a container kept for re-adoption was stopped (%v) or removed (%v)", stopped, removed)
	}
}

// holdAlive holds the run's helper lock as a live helper does; the returned
// func releases it (the helper exited).
func holdAlive(t *testing.T, obs, runID string) func() {
	t.Helper()
	fh, err := os.OpenFile(filepath.Join(sandboxrelayd.RunsDir(obs), runID+".alive"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(fh.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // G115: a descriptor number
		t.Fatal(err)
	}
	return func() { _ = fh.Close() }
}

// TestReadoptDaemonRestartOffersTheRun (R-033) with the fake engine: the
// daemon's stop marks the live re-adoptable run, the helper's hangup check
// keeps the container once (the mark is consumed), and after the helper
// has left the daemon's next start sweeps the run into an offer instead of
// reaping it. A terminal closed with no mark stops as before.
func TestReadoptDaemonRestartOffersTheRun(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run0000000000000033")
	raEnder(t)
	release := holdAlive(t, ra.obs, ra.runID)

	keep := readoptHangupKeeper(ra.obs, ra.runID)
	if keep == nil {
		t.Fatal("no hangup check for a re-adoptable run")
	}
	if keep() {
		t.Fatal("a terminal closed with no daemon-exit mark kept the container")
	}
	marked := readoptMarkDaemonExitIn(ra.obs, readoptNow())
	if len(marked) != 1 || marked[0] != ra.runID {
		t.Fatalf("the daemon's stop marked %v, want the live run", marked)
	}
	if !keep() {
		t.Fatal("the daemon-exit hangup did not keep the container")
	}
	if _, err := os.Lstat(filepath.Join(readoptRunDir(ra.obs, ra.runID), sandboxadopt.DaemonExitMark)); !os.IsNotExist(err) {
		t.Fatalf("the mark was not consumed: %v", err)
	}
	if keep() {
		t.Fatal("a later hangup reused the consumed mark")
	}
	release() // the helper left without its teardown

	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(f.removed) != 0 {
		t.Fatalf("the restarted daemon reaped a run kept for re-adoption: %v", f.removed)
	}
	if e := readoptRead(ra.obs, ra.runID); !e.hasOffer || e.offer.Code != sandboxadopt.CodeOffered {
		t.Fatalf("the restarted daemon did not offer the run: %+v", e.offer)
	}
	if again := readoptMarkDaemonExitIn(ra.obs, readoptNow()); len(again) != 0 {
		t.Fatalf("an offered run was marked again: %v", again)
	}
}

// TestReadoptStaleMarkStops: a mark older than the grace does not keep the
// container.
func TestReadoptStaleMarkStops(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run0000000000000034")
	release := holdAlive(t, ra.obs, ra.runID)
	defer release()
	if len(readoptMarkDaemonExitIn(ra.obs, readoptNow().Add(-2*sandboxadopt.HangupGrace))) != 1 {
		t.Fatal("not marked")
	}
	if readoptHangupKeeper(ra.obs, ra.runID)() {
		t.Fatal("a stale mark kept the container")
	}
}

// TestReadoptDaemonExitMarkSkipsACLIRun (LEFT2 audit S2): a CLI run keeps a
// plan and a live helper too, but the daemon does not route it. Its exit
// must not mark the run, so a user who closes their own CLI terminal while
// the daemon is down gets the container stopped. The control without the
// CLI watch file is marked.
func TestReadoptDaemonExitMarkSkipsACLIRun(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	const term = "cli-run-0035"
	ra := raSetupWith(t, f, "run0000000000000035", func(r *sandboxrelayd.RunRecord) { r.TerminalRunID = term })
	release := holdAlive(t, ra.obs, ra.runID)
	defer release()
	if e := readoptRead(ra.obs, ra.runID); !e.keptOK || e.kept.Facts.TerminalRunID != term {
		t.Fatalf("the kept record does not name the CLI terminal run: %+v", e.kept.Facts)
	}
	watch, _ := sandboxCLIEndPaths(ra.obs, term)
	if err := os.MkdirAll(filepath.Dir(watch), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watch, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if marked := readoptMarkDaemonExitIn(ra.obs, readoptNow()); len(marked) != 0 {
		t.Fatalf("the daemon's exit marked a CLI run %v", marked)
	}
	if readoptHangupKeeper(ra.obs, ra.runID)() {
		t.Fatal("a CLI terminal closed while the daemon was down kept the container")
	}
	if err := os.Remove(watch); err != nil {
		t.Fatal(err)
	}
	if marked := readoptMarkDaemonExitIn(ra.obs, readoptNow()); len(marked) != 1 {
		t.Fatalf("control: the daemon's own run was not marked: %v", marked)
	}
}

// raFakeClock replaces the re-adoption clock and the kept helper's sleep
// with a fake clock that each sleep advances; onSleep, when set, runs after
// every sleep. It returns the total slept.
func raFakeClock(t *testing.T, onSleep func()) *time.Duration {
	t.Helper()
	clock := time.Now().UTC()
	var slept time.Duration
	oldNow, oldSleep := readoptNow, readoptSleep
	readoptNow = func() time.Time { return clock }
	readoptSleep = func(d time.Duration) {
		slept += d
		clock = clock.Add(d)
		if onSleep != nil {
			onSleep()
		}
	}
	t.Cleanup(func() { readoptNow, readoptSleep = oldNow, oldSleep })
	return &slept
}

// TestReadoptKeptHelperWaitsAtMostTheBound (LEFT2 audit S4): a helper that
// kept its container through a daemon hangup drops its liveness lock and
// waits at most the re-adoption bound (fake clock) for an offer; with no
// daemon start in that time it reports none, so the container is stopped.
func TestReadoptKeptHelperWaitsAtMostTheBound(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 5*time.Minute)
	ra := raSetup(t, f, "run0000000000000036")
	unhold, err := sandboxrelayd.HoldRun(ra.obs, ra.runID)
	if err != nil {
		t.Fatal(err)
	}
	defer unhold()
	if readoptHelper(ra.obs, ra.runID) != readoptHelperHeld {
		t.Fatal("the helper's liveness lock is not held")
	}
	slept := raFakeClock(t, nil)
	wait := readoptAwaitOfferFor(ra.obs, ra.runID)
	if wait == nil {
		t.Fatal("no wait for a re-adoptable run")
	}
	if wait() {
		t.Fatal("an offer was reported with no daemon start")
	}
	if *slept != 5*time.Minute {
		t.Fatalf("the helper waited %v, want the 5 minute bound", *slept)
	}
	if readoptHelper(ra.obs, ra.runID) != readoptHelperGone {
		t.Fatal("the kept helper still holds its liveness lock, so no start could offer the run")
	}
}

// TestReadoptKeptHelperSeesTheNextStartsOffer (LEFT2 audit S4): a daemon
// start inside the bound sweeps the run (the helper dropped its lock) and
// offers it; the helper sees the offer and leaves the container to it.
func TestReadoptKeptHelperSeesTheNextStartsOffer(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 5*time.Minute)
	ra := raSetup(t, f, "run0000000000000037")
	raEnder(t)
	unhold, err := sandboxrelayd.HoldRun(ra.obs, ra.runID)
	if err != nil {
		t.Fatal(err)
	}
	defer unhold()
	swept := false
	slept := raFakeClock(t, func() {
		if !swept {
			swept = true
			(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
		}
	})
	if !readoptAwaitOfferFor(ra.obs, ra.runID)() {
		t.Fatal("the next start's offer was not seen")
	}
	if *slept >= 5*time.Minute {
		t.Fatalf("the helper waited out the bound (%v) despite the offer", *slept)
	}
	if len(f.removed) != 0 {
		t.Fatalf("the offered run's container was removed: %v", f.removed)
	}
}

// TestOCIRunStopsAKeptContainerWithNoOffer (LEFT2 audit S4) with the fake
// engine: the hangup keeps the container, then the wait reports no offer,
// so the helper stops and removes it and no longer reads as detached.
func TestOCIRunStopsAKeptContainerWithNoOffer(t *testing.T) {
	f := newOCIFake(t)
	tt := newOCITestTerm()
	var detached atomic.Bool
	tt.term.detached = &detached
	tt.term.keepOnHangup = func() bool { return true }
	asked := false
	tt.term.awaitOffer = func() bool { asked = true; return false }
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	}()
	tt.waitFor(t, "agent$ ")
	tt.stop <- "hangup"
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the helper never returned")
	}
	if !asked {
		t.Fatal("the kept container's wait was never asked")
	}
	if detached.Load() {
		t.Fatal("the helper still reads as having left the container for re-adoption")
	}
	if f.callIndex("POST /containers/c1/stop") < 0 {
		t.Fatal("a container with no offer was not stopped")
	}
	f.mu.Lock()
	removed := append([]string(nil), f.removed...)
	f.mu.Unlock()
	if len(removed) == 0 {
		t.Fatal("a container with no offer was not removed")
	}
}
