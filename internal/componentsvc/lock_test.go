package componentsvc

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// recordingLock is an in-memory stand-in for the cross-process lock: it
// records which paths are held, so a test can ask whether a callback ran
// under the lock.
type recordingLock struct {
	mu   sync.Mutex
	held map[string]int
}

func (l *recordingLock) lock(path string) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.held == nil {
		l.held = map[string]int{}
	}
	l.held[path]++
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		l.held[path]--
	}, nil
}

func (l *recordingLock) isHeld(path string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.held[path] > 0
}

// recheckStore is a PurgeStore whose execute runs the recheck (as the real
// store does, inside its transaction) and then calls during, standing in
// for the deletes.
type recheckStore struct {
	during  func()
	recheck error
}

func (r *recheckStore) CreateComponentPurgePlan(context.Context, store.ComponentPurgeSpec) (store.ComponentPurgePlan, error) {
	return store.ComponentPurgePlan{}, nil
}

func (r *recheckStore) ExecuteComponentPurgePlan(ctx context.Context, _ string, recheck store.PurgeRecheck, _ time.Time) (store.PurgeResult, error) {
	r.recheck = recheck(ctx, store.ComponentPurgePlan{Component: "adapter.zed"})
	if r.during != nil {
		r.during()
	}
	return store.PurgeResult{}, r.recheck
}

func (r *recheckStore) ComponentPurgePlanByID(context.Context, string) (store.ComponentPurgePlan, error) {
	return store.ComponentPurgePlan{}, nil
}

const zedRemoved = seedConfig + `
[components]
remove = ["adapter.zed"]
`

// TestPurgeAndApplyTakeTheConfigLock is ledger MODPKG-12 (T-679): the
// purge's inactivity re-check runs under the same cross-process lock Apply
// holds while it rewrites the block, so the two cannot interleave.
func TestPurgeAndApplyTakeTheConfigLock(t *testing.T) {
	ctx := context.Background()
	s, path, _, _ := newSvc(t, zedRemoved)
	lk := &recordingLock{}
	s.opts.Lock = lk.lock
	rs := &recheckStore{}
	var heldDuringPurge bool
	rs.during = func() { heldDuringPurge = lk.isHeld(path) }
	s.opts.Purge = rs
	if _, err := s.PurgeExecute(ctx, "plan"); err != nil {
		t.Fatalf("purge of an inactive component: %v", err)
	}
	if rs.recheck != nil {
		t.Fatalf("recheck refused an inactive component: %v", rs.recheck)
	}
	if !heldDuringPurge {
		t.Fatal("the purge ran without the config lock held: an Apply in another process could re-activate the component mid-purge")
	}
	var heldDuringLoad bool
	load := s.opts.Load
	s.opts.Load = func() (config.Config, error) {
		heldDuringLoad = lk.isHeld(path)
		return load()
	}
	if _, err := s.Apply(ctx, Change{Add: []string{"adapter.zed"}}, ApplyOptions{SkipTeardown: true}); err != nil {
		t.Fatal(err)
	}
	if !heldDuringLoad {
		t.Fatal("Apply read and rewrote the block without the config lock held")
	}
	if lk.isHeld(path) {
		t.Fatal("the lock was not released")
	}
}

// TestApplyWaitsForAPurgeHoldingTheRealLock uses the production lock (the
// file-based cross-process one): an Apply that starts while a purge holds
// it finishes only after the purge has returned.
func TestApplyWaitsForAPurgeHoldingTheRealLock(t *testing.T) {
	ctx := context.Background()
	s, _, _, _ := newSvc(t, zedRemoved)
	rs := &recheckStore{}
	var mu sync.Mutex
	var order []string
	rec := func(x string) { mu.Lock(); order = append(order, x); mu.Unlock() }
	done := make(chan error, 1)
	// The production lock, wrapped to say when Apply reaches it: the purge
	// takes the lock first (call 1), so call 2 is Apply's, made while the
	// purge still holds it.
	applyAtLock := make(chan struct{})
	var lockCalls atomic.Int32
	s.opts.Lock = func(path string) (func(), error) {
		if lockCalls.Add(1) == 2 {
			close(applyAtLock)
		}
		return hook.LockSettingsFile(path)
	}
	rs.during = func() {
		go func() {
			_, err := s.Apply(ctx, Change{Add: []string{"adapter.zed"}}, ApplyOptions{SkipTeardown: true})
			rec("apply")
			done <- err
		}()
		// Only once Apply is known to be at the lock does the window below
		// test anything: a lock that let it through would record "apply"
		// before the purge does.
		select {
		case <-applyAtLock:
		case <-time.After(10 * time.Second):
			t.Error("Apply never reached the config lock")
		}
		time.Sleep(300 * time.Millisecond)
		rec("purge")
	}
	s.opts.Purge = rs
	if _, err := s.PurgeExecute(ctx, "plan"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("apply after the purge: %v", err)
	}
	if len(order) != 2 || order[0] != "purge" || order[1] != "apply" {
		t.Fatalf("apply did not wait for the purge: %v", order)
	}
}
