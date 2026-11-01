//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

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

	"github.com/marmutapp/superbased-observer/internal/config"
)

// deferredTestDir makes a run's deferred dir as attachDeferred does and
// returns it with the waiter's arguments.
func deferredTestDir(t *testing.T, obs, runID string) (string, []string) {
	t.Helper()
	dir := ociDeferredDir(obs, runID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := ociCreateExcl(filepath.Join(dir, ociDeferredProgress))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return dir, []string{ociDeferredFlag, dir, "--relay-run", runID, "--observer-dir", obs}
}

// TestOCIDeferredPullAnnouncesBeforeTheDownload (R-037): on a deferred
// (dashboard) launch the announcement is on the terminal before the engine
// receives the pull, the helper then runs the argv the daemon planned, and
// with no terminal showing it nothing is pulled.
func TestOCIDeferredPullAnnouncesBeforeTheDownload(t *testing.T) {
	f := newP3CFake(t)
	store, tr, d := installTestImage(t)
	trust := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
	f.pullStream = p3cPullStream(d.Digest)
	f.onPull[d.Ref()] = p3cDefaultImageInspect(d)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	obs := t.TempDir()
	const runID = "run0000000000000037"
	dir, args := deferredTestDir(t, obs, runID)

	term := &ociSyncBuf{}
	var onTerminalAtPull string
	f.onPullRequest = func() { onTerminalAtPull = term.String() }
	type waited struct {
		argv []string
		code int
	}
	done := make(chan waited, 1)
	go func() {
		argv, code := ociWaitDeferred(args, term, 30*time.Second, time.Sleep)
		done <- waited{argv, code}
	}()

	if _, err := ociDeferredPull(context.Background(), c, trust, obs, dir, func(string) {}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(onTerminalAtPull, "observer sandbox: ") || !strings.Contains(onTerminalAtPull, "from ghcr.io/example/observer-sandbox") {
		t.Fatalf("the terminal did not show the announcement before the pull started; it showed %q", onTerminalAtPull)
	}
	real := []string{"/usr/bin/observer", ociHostVerb, "--plan", "/tmp/plan.json", "--", "x"}
	b, _ := json.Marshal(real)
	if err := ociDeferredWrite(dir, ociDeferredArgv, b); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-done:
		if w.code != 0 || strings.Join(w.argv, " ") != strings.Join(real[2:], " ") {
			t.Fatalf("the waiter returned %v (%d), want the real host step's arguments", w.argv, w.code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the waiter never took the daemon's argv")
	}
	if !strings.Contains(term.String(), "pulled "+d.Ref()) {
		t.Fatalf("the terminal did not show the pull's progress: %q", term.String())
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("the deferred dir outlived the hand-over: %v", err)
	}
}

// TestOCIDeferredPullNeedsTheTerminal: with no terminal showing the
// announcement, the pull never starts.
func TestOCIDeferredPullNeedsTheTerminal(t *testing.T) {
	f := newP3CFake(t)
	store, tr, d := installTestImage(t)
	trust := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
	f.pullStream = p3cPullStream(d.Digest)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	prev := ociDeferredAckWait
	ociDeferredAckWait = 200 * time.Millisecond
	t.Cleanup(func() { ociDeferredAckWait = prev })
	obs := t.TempDir()
	dir, _ := deferredTestDir(t, obs, "run0000000000000038")
	if _, err := ociDeferredPull(context.Background(), c, trust, obs, dir, func(string) {}); !errors.Is(err, errOCIDeferredNotShown) {
		t.Fatalf("err = %v, want the not-shown refusal", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.pulled) != 0 {
		t.Fatalf("pulled %v with no terminal showing the announcement", f.pulled)
	}
}

// TestOCIDeferredWaiterShowsARefusal: a daemon refusal reaches the terminal
// and ends the helper.
func TestOCIDeferredWaiterShowsARefusal(t *testing.T) {
	obs := t.TempDir()
	dir, args := deferredTestDir(t, obs, "run0000000000000039")
	ociDeferredSay(dir, "a line before")
	if err := ociDeferredWrite(dir, ociDeferredRefused, []byte("terminal_sandbox: tool_unavailable_in_image: no node")); err != nil {
		t.Fatal(err)
	}
	term := &ociSyncBuf{}
	argv, code := ociWaitDeferred(args, term, 5*time.Second, time.Sleep)
	if argv != nil || code != sandboxHelperFailCode || !strings.Contains(term.String(), "a line before") || !strings.Contains(term.String(), "tool_unavailable_in_image") {
		t.Fatalf("argv %v code %d terminal %q", argv, code, term.String())
	}
	// Arguments that do not name this run's own dir are refused.
	bad := append([]string(nil), args...)
	bad[1] = t.TempDir()
	if argv, code := ociWaitDeferred(bad, term, time.Second, time.Sleep); argv != nil || code != sandboxHelperFailCode {
		t.Fatalf("a foreign dir was waited on: %v %d", argv, code)
	}
}

// TestOCICheckRunImageDefersOnADaemonLaunch: Create leaves the pull pending
// on a daemon launch (no pull call), and still pulls inline on a CLI one.
func TestOCICheckRunImageDefersOnADaemonLaunch(t *testing.T) {
	for _, deferPull := range []bool{true, false} {
		f := newP3CFake(t)
		store, tr, d := installTestImage(t)
		trust := ociResolveImage(config.TerminalSandboxOCIConfig{}, store, tr)
		f.pullStream = p3cPullStream(d.Digest)
		f.onPull[d.Ref()] = p3cDefaultImageInspect(d)
		c, err := ociEngineClient(f.sock, "1.52")
		if err != nil {
			t.Fatal(err)
		}
		drv := &ociDriver{r: &sandboxRuntime{observerDir: t.TempDir()}}
		choice := ociRunChoice{image: trust.image}
		note := ""
		if err := drv.checkRunImage(context.Background(), c, trust, &choice, &note, deferPull); err != nil {
			t.Fatalf("defer %v: %v", deferPull, err)
		}
		f.mu.Lock()
		pulled := len(f.pulled)
		f.mu.Unlock()
		if deferPull && (choice.pending == nil || pulled != 0) {
			t.Fatalf("a daemon launch pulled before its terminal (pending %v, pulled %d)", choice.pending, pulled)
		}
		if !deferPull && (choice.pending != nil || pulled != 1) {
			t.Fatalf("a CLI launch did not pull inline (pending %v, pulled %d)", choice.pending, pulled)
		}
	}
}
