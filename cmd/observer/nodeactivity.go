package main

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
)

// activityTurn is the activity kind of a committed api_turn. It spells
// proxy.ActivityTurn without importing internal/proxy, so a build without
// capture.proxy still counts watcher turns (lane MP-L1L, T-715); proxy.go
// pins the two spellings equal at compile time.
const activityTurn = "turn"

// isTurnActivity reports a committed-turn event (spend moved, data to push).
func isTurnActivity(kind string) bool { return kind == activityTurn }

// activityCapture is the activity kind the watcher reports for an ingest that
// inserted action rows but no token rows (P3).
const activityCapture = "capture"

// isPushActivity reports an event that means new pushable rows exist (or are
// about to, for a prompt): the org push loop's activity kick (P3).
func isPushActivity(kind string) bool {
	switch kind {
	case activityTurn, activityCapture, activityPrompt:
		return true
	}
	return false
}

// noteIngestActivity is the watcher's ingest notifier (Watcher.SetIngestNotifier):
// token rows are a committed turn (spend moved), action-only rows a capture.
func noteIngestActivity(tokens, _ int) {
	if tokens > 0 {
		processNodeActivity.Note(activityTurn)
		return
	}
	processNodeActivity.Note(activityCapture)
}

// Node-activity fan-out (2026-10-02 budget-latency arc).
//
// The proxy (and, for non-proxied tools, the hook activity stamp and the
// watcher) report "the developer is working" / "a priced turn committed".
// Three daemon subsystems react, none of them known to the reporters
// (CLAUDE.md #2):
//
//   - the budget-warning service re-measures spend on a committed turn (P1);
//   - the policy-freshness checker probes the org's version map (P2);
//   - the push loop schedules an activity-driven push (P3).
//
// Subscribers MUST NOT block: each is a non-blocking channel send or an
// atomic store.

// nodeActivityBus is the process-level fan-out. Subscribe before traffic.
type nodeActivityBus struct {
	mu   sync.RWMutex
	subs []func(kind string)
}

// processNodeActivity is the one bus per daemon process.
var processNodeActivity = &nodeActivityBus{}

// Note reports one activity event to every subscriber.
func (b *nodeActivityBus) Note(kind string) {
	if b == nil {
		return
	}
	b.mu.RLock()
	subs := b.subs
	b.mu.RUnlock()
	for _, f := range subs {
		f(kind)
	}
}

// Subscribe adds a non-blocking subscriber.
func (b *nodeActivityBus) Subscribe(f func(kind string)) {
	if b == nil || f == nil {
		return
	}
	b.mu.Lock()
	b.subs = append(append([]func(string){}, b.subs...), f)
	b.mu.Unlock()
}

// activityPrompt is the activity kind a prompt hook's stamp produces.
const activityPrompt = "prompt"

// activityStampPoll is how often the daemon looks at the hooks' activity
// stamp (an mtime stat, nothing else).
const activityStampPoll = 2 * time.Second

// watchActivityStamp turns the prompt hooks' activity stamp
// (budgetwarnfile.TouchActivity, beside the DB) into node-activity events.
// Hooks are short-lived processes with no daemon IPC; an mtime is the
// cheapest signal that needs no listener, no auth surface and works with the
// dashboard off. The first observation only records the baseline.
func watchActivityStamp(ctx context.Context, dbPath string, note func(kind string)) {
	watchActivityStampEvery(ctx, dbPath, activityStampPoll, note)
}

// watchActivityStampEvery is watchActivityStamp looking at the stamp every
// poll; the daemon always passes activityStampPoll, a test a shorter one.
func watchActivityStampEvery(ctx context.Context, dbPath string, poll time.Duration, note func(kind string)) {
	path := budgetwarnfile.ActivityPath(dbPath)
	if path == "" || note == nil {
		return
	}
	var last time.Time
	if fi, err := os.Stat(path); err == nil {
		last = fi.ModTime()
	}
	t := time.NewTicker(poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		fi, err := os.Stat(path)
		if err != nil {
			continue
		}
		if m := fi.ModTime(); m.After(last) {
			last = m
			note(activityPrompt)
		}
	}
}

// processBudgetWarn is the daemon's budget-warning service once wired (nil
// before, and in every non-daemon process).
var processBudgetWarn atomic.Pointer[budgetWarnService]

// processBudgetWarningHeader is the proxy's X-SBO-Budget-Warning source.
func processBudgetWarningHeader() string {
	if s := processBudgetWarn.Load(); s != nil {
		return s.HeaderValue()
	}
	return ""
}
