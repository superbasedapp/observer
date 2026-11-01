//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// asDaemon makes this process look like the daemon and swaps the background
// attempt for fetch; both are restored, with the attempt state, at cleanup.
func asDaemon(t *testing.T, fetch func(content.Kind, string) error) {
	t.Helper()
	old := daemonConfigPathSetting.Load()
	p := "/nonexistent/config.toml"
	daemonConfigPathSetting.Store(&p)
	prev := sandboxContentEnsureFetch
	sandboxContentEnsureFetch = fetch
	reset := func() {
		sandboxContentAuto.mu.Lock()
		sandboxContentAuto.next = map[content.Kind]time.Time{}
		sandboxContentAuto.inflight = map[content.Kind]bool{}
		sandboxContentAuto.mu.Unlock()
	}
	reset()
	t.Cleanup(func() {
		daemonConfigPathSetting.Store(old)
		sandboxContentEnsureFetch = prev
		reset()
	})
}

// waitIdle waits for kind's background attempt to finish.
func waitIdle(t *testing.T, kind content.Kind) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sandboxContentAuto.mu.Lock()
		busy := sandboxContentAuto.inflight[kind]
		sandboxContentAuto.mu.Unlock()
		if !busy {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the background attempt never finished")
}

func sandboxNextAttempt(kind content.Kind) time.Duration {
	sandboxContentAuto.mu.Lock()
	defer sandboxContentAuto.mu.Unlock()
	return time.Until(sandboxContentAuto.next[kind])
}

// TestSandboxContentEnsureNeverBlocks (SBX-P3D audit finding 3): the
// first-use fetch runs in the background, so its caller (the availability
// probe, the image resolve) returns at once while the attempt is still
// running; a second call while it runs starts nothing.
func TestSandboxContentEnsureNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 4)
	var calls atomic.Int64
	asDaemon(t, func(content.Kind, string) error {
		calls.Add(1)
		started <- struct{}{}
		<-release
		return errors.New("offline")
	})
	dir := t.TempDir()
	begin := time.Now()
	sandboxContentEnsure(content.SandboxImage, dir)
	if d := time.Since(begin); d > time.Second {
		t.Fatalf("the caller waited %s on the fetch", d)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("no background attempt started")
	}
	sandboxContentEnsure(content.SandboxImage, dir)
	if calls.Load() != 1 {
		t.Fatalf("%d attempts while one was running", calls.Load())
	}
	close(release)
	waitIdle(t, content.SandboxImage)
	if d := sandboxNextAttempt(content.SandboxImage); d < 50*time.Minute || d > time.Hour {
		t.Fatalf("after a transient failure the next attempt is in %s, want an hour", d)
	}
	sandboxContentEnsure(content.SandboxImage, dir)
	if calls.Load() != 1 {
		t.Fatal("a retry ran inside the hour")
	}
}

// TestSandboxContentNotPublishedBacksOffToDaily: a source that says it does
// not publish the kind is asked again in a day, not an hour.
func TestSandboxContentNotPublishedBacksOffToDaily(t *testing.T) {
	asDaemon(t, func(content.Kind, string) error {
		return fmt.Errorf("sandbox content: from the org mirror: %w", orgclient.ErrSecurityContentNotMirrored)
	})
	sandboxContentEnsure(content.SandboxImage, t.TempDir())
	waitIdle(t, content.SandboxImage)
	if d := sandboxNextAttempt(content.SandboxImage); d < 23*time.Hour {
		t.Fatalf("a kind the source does not publish is retried in %s, want a day", d)
	}
}

// TestSandboxContentRefreshOverAnInstalledKind: the refresh variant (the
// MXC manifest past its age floor) starts an attempt even though the kind
// is installed, and the first-use variant does not.
func TestSandboxContentRefreshOverAnInstalledKind(t *testing.T) {
	var calls atomic.Int64
	asDaemon(t, func(content.Kind, string) error { calls.Add(1); return nil })
	r := newSandboxContentRig(t, false)
	if _, err := r.env.fetch(t.Context(), content.SandboxNative); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	r.env.store.Root = sandboxContentStore(dir).Root
	if _, err := r.env.fetch(t.Context(), content.SandboxNative); err != nil {
		t.Fatal(err)
	}
	sandboxContentEnsure(content.SandboxNative, dir)
	waitIdle(t, content.SandboxNative)
	if calls.Load() != 0 {
		t.Fatal("the first-use fetch ran over an installed kind")
	}
	sandboxContentRefresh(content.SandboxNative, dir)
	waitIdle(t, content.SandboxNative)
	if calls.Load() != 1 {
		t.Fatalf("the refresh ran %d times, want once", calls.Load())
	}
}
