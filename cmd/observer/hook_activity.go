package main

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hookliveness"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
)

// HOOK LIVENESS ON THE HOOK PATH (surface-gap review OBS-7 / CC-2, agent
// migration 198).
//
// Every `observer hook <tool> <event>` invocation appends ONE DB-free
// activity record to the hook spool (internal/hookspool) after its handler
// has run; the daemon's single drainer (hook_lifecycle_wire.go) folds it
// into hook_activity through store.UpsertHookActivity. This file never
// opens SQLite and never loads the TOML config: opening and migrating the
// database does not reliably fit a hook's budget (internal/hookspool/doc.go),
// and the record must cost well under a millisecond (BenchmarkHookActivity).
//
// The emission is central (runHookInvocation arms emitHookActivity once and
// defers flushHookActivity) so a receiver path nobody wired still counts, in
// the unattributed bucket. A block or fail-closed answer that ends the process
// through hookExitProcess, and a watchdog or panic exit through the wrapped
// exitFn, flush the same armed emission first: os.Exit skips deferred calls,
// so without the flush a tool whose hooks only block would read as silent
// (R-188 F4). The flush runs the emission at most once per invocation. The
// session id is per receiver: runHookInvocation's handlers consume stdin, so
// each receiver that has parsed its payload reports the id it read through
// noteHookSession / noteHookPayload (one call per receiver path). A payload
// another host replayed through Observer's hook command (a foreign Claude
// Code payload) is not this tool's liveness: it is not recorded when the host
// is unidentified or its own Observer hook already counts the call
// (noteHookForeign), and it is recorded under the HOST's tool and event when
// the receiver serves it as the host's call (noteHookActivityTool; surface-gap
// FU-53), as is a surface that ran another tool's registration
// (hookSurfaceBinding, W-2c).

// hookActivity is the invocation's liveness state: the session id the first
// receiver reported, whether the invocation is a foreign replay nobody
// claims, and the tool and event the call is attributed to when that is not
// the argv's.
//
// emit is the invocation's armed emission (armHookActivity); flushHookActivity
// takes and runs it, so it runs at most once whichever exit comes first.
var hookActivity struct {
	mu        sync.Mutex
	sessionID string
	foreign   bool
	tool      string
	event     string
	emit      func()
}

// resetHookActivity clears the per-invocation state (runHookInvocation's
// single reset point, beside resetHookInvocationState).
func resetHookActivity() {
	hookActivity.mu.Lock()
	hookActivity.sessionID, hookActivity.foreign = "", false
	hookActivity.tool, hookActivity.event = "", ""
	hookActivity.emit = nil
	hookActivity.mu.Unlock()
}

// armHookActivity sets the invocation's one activity emission. It runs on the
// first flushHookActivity, never again.
func armHookActivity(emit func()) {
	hookActivity.mu.Lock()
	hookActivity.emit = emit
	hookActivity.mu.Unlock()
}

// flushHookActivity runs the armed emission once and disarms it. Every path
// that ends the invocation calls it: the deferred return, hookExitProcess and
// the wrapped exitFn (activityFlushingExit). Nothing armed is a no-op. The
// emission runs outside hookActivity.mu (it takes the lock itself).
func flushHookActivity() {
	hookActivity.mu.Lock()
	emit := hookActivity.emit
	hookActivity.emit = nil
	hookActivity.mu.Unlock()
	if emit != nil {
		emit()
	}
}

// activityFlushingExit wraps a process exit so the armed activity record is
// written before the process ends (os.Exit runs no deferred call).
func activityFlushingExit(exitFn func(int)) func(int) {
	return func(code int) {
		flushHookActivity()
		exitFn(code)
	}
}

// noteHookActivityTool attributes the invocation's activity record to tool
// and event (a host's native event name) instead of the argv's: the receiver
// is serving the call as that tool's. It clears a foreign mark.
func noteHookActivityTool(tool, event string) {
	if tool == "" || event == "" {
		return
	}
	hookActivity.mu.Lock()
	hookActivity.tool, hookActivity.event, hookActivity.foreign = tool, event, false
	hookActivity.mu.Unlock()
}

// noteHookSession records the session id a receiver read from its payload.
// The first non-empty id wins.
func noteHookSession(sessionID string) {
	if sessionID == "" {
		return
	}
	hookActivity.mu.Lock()
	if hookActivity.sessionID == "" {
		hookActivity.sessionID = sessionID
	}
	hookActivity.mu.Unlock()
}

// noteHookPayload is noteHookSession for a receiver that holds the payload
// bytes but did not parse an id of its own (hookliveness.PayloadSessionID
// stops at the first id key, so a large tool input costs nothing).
func noteHookPayload(body []byte) {
	noteHookSession(hookliveness.PayloadSessionID(body))
}

// noteHookForeign marks the invocation as another host's payload replayed
// through this tool's hook command: no activity record is written for it.
func noteHookForeign() {
	hookActivity.mu.Lock()
	hookActivity.foreign = true
	hookActivity.mu.Unlock()
}

// hookActivityDeps is the emission's injected I/O.
type hookActivityDeps struct {
	now       func() time.Time
	getenv    func(string) string
	spoolPath func(configPath string) string
	appendRow func(path string, r hookspool.Record) error
}

// hookActivityDepsFor builds the emission's deps for one invocation. A seam
// so the test binary keeps every emission inside a temp dir (TestMain).
var hookActivityDepsFor = productionHookActivityDeps

func productionHookActivityDeps(getenv func(string) string) hookActivityDeps {
	return hookActivityDeps{
		now:    time.Now,
		getenv: getenv,
		spoolPath: func(configPath string) string {
			resolved, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return ""
			}
			return hookspool.Path(resolved)
		},
		appendRow: hookspool.Append,
	}
}

// hookActivityEvent is the event an activity row names: the registry
// binding's native event when the invocation resolves to one (so the
// classifier can match it against the registry), else the argv spelling.
func hookActivityEvent(tool, event string) string {
	if b, ok := resolveHookInvocationBinding(tool, event); ok && b.NativeEvent != "" {
		return b.NativeEvent
	}
	return event
}

// emitHookActivity appends the invocation's one activity record. It is
// fail-open and silent on success: a failed append is one stderr line and a
// lost count, never a changed reply. A record skipped because the spool is
// past its cap (nothing drains it) is silent too: the skip is counted.
func emitHookActivity(tool, event, configPath string, stderr io.Writer, deps hookActivityDeps) {
	defer func() { _ = recover() }()
	if tool == "" || event == "" {
		return
	}
	hookActivity.mu.Lock()
	sid, foreign := hookActivity.sessionID, hookActivity.foreign
	if hookActivity.tool != "" {
		tool, event = hookActivity.tool, hookActivity.event
	}
	hookActivity.mu.Unlock()
	if foreign {
		return
	}
	path := deps.spoolPath(configPath)
	if path == "" {
		return
	}
	rec := hookspool.Record{
		Kind:      hookspool.KindActivity,
		Tool:      tool,
		HookEvent: hookActivityEvent(tool, event),
		SessionID: sid,
		Timestamp: deps.now().UTC(),
		Env:       hookliveness.EnvClasses(deps.getenv),
	}
	// A record skipped past the spool cap is already counted for the doctor
	// (hookspool.SkippedActivity): nothing for the hook's stderr.
	if err := deps.appendRow(path, rec); err != nil && !errors.Is(err, hookspool.ErrActivitySkipped) {
		fmt.Fprintf(stderr, "observer-hook: %s:%s activity spool: %v\n", tool, event, err)
	}
}
