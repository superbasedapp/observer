package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hooklifecycle"
	"github.com/marmutapp/superbased-observer/internal/hookspool"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// The ONE lifecycle handler (hook-parity Lane C1). Every receiver that gets
// a session / turn / sub-agent lifecycle event it does not own itself calls
// serveLifecycleHook with the payload it already read; the registry binding
// decides whether the event is a wired lifecycle capability, and
// internal/hooklifecycle's table decides what to do with it.
//
// Ordering is the hook path's standing rule, tightened for lifecycle ends:
//
//  1. reply first ({} - the neutral answer, see hook.HandleNeutral), so the
//     host is never held;
//  2. a session / turn / sub-agent END row is appended to the DB-free hook
//     spool (internal/hookspool) beside the global config. A host's end
//     budget can be tiny (Claude Code about 1.5 s shared, Codex 3 s) and
//     the host may kill the hook on exit, so this path never opens the
//     database or parses the TOML config; the daemon ingests the spool;
//  3. a session START seeds pidbridge for a binding whose hook runs as a
//     descendant of the agent (the proxy needs that row before the first
//     model request, so it is written directly, after the reply).
//
// Lifecycle capabilities are observe-only: every failure is fail-open.

// lifecycleDeps is the injected I/O (production: the real spool, pidbridge
// writer and ancestor walk; tests substitute recorders).
type lifecycleDeps struct {
	now       func() time.Time
	spoolPath func(configPath string) string
	appendRow func(path string, r hookspool.Record) error
	parentPID int
	ancestors ancestorsFunc
	pidbridge func(configPath string) pidbridgeWriter
}

func productionLifecycleDeps(ctx context.Context) lifecycleDeps {
	hc := hookContext(ctx)
	return lifecycleDeps{
		now: time.Now,
		spoolPath: func(configPath string) string {
			resolved, err := config.ResolveGlobalPath(configPath)
			if err != nil {
				return ""
			}
			return hookspool.Path(resolved)
		},
		appendRow: hookspool.Append,
		parentPID: hc.ParentPID(),
		ancestors: hc.Ancestors,
		pidbridge: makePidbridgeWriter,
	}
}

// lifecycleDialect is the binding dialect that routes an event to this
// handler (internal/integration hookDialectLifecycle). A lifecycle event a
// tool's own receiver owns (Codex SessionStart / Stop, every Cursor event)
// carries that receiver's dialect and is left to it.
const lifecycleDialect = "lifecycle"

// lifecycleBinding resolves (tool, event) to a wired lifecycle binding the
// handler serves. ok=false: not a lifecycle event this handler owns.
func lifecycleBinding(tool, event string) (integration.HookBinding, bool) {
	b, ok := resolveHookBinding(tool, event)
	if !ok || !b.Wired || b.Dialect != lifecycleDialect || !hooklifecycle.Handled(b.Cap) {
		return integration.HookBinding{}, false
	}
	return b, true
}

// handleLifecycleHook is the one lifecycle handler (deps injected).
// runHookInvocation calls it for every tool whose (tool, event) resolves to
// a lifecycle-dialect binding; the claude-code receiver calls it for
// session-end after ruling out a foreign replay.
func handleLifecycleHook(ctx context.Context, tool, label string, b integration.HookBinding, body []byte, configPath string, stdout, stderr io.Writer, deps lifecycleDeps) {
	hook.DumpHookShape(tool, b.NativeEvent, body)
	hook.HandleNeutral(label, bytes.NewReader(body), stdout, stderr)
	markHookReplied()

	plan := hooklifecycle.Decide(tool, b, body, deps.now())
	noteHookSession(plan.SessionID)
	if plan.SessionID == "" {
		fmt.Fprintf(stderr, "observer-hook: %s no session id in payload; nothing recorded\n", label)
		return
	}
	if plan.Row != nil {
		path := deps.spoolPath(configPath)
		if err := deps.appendRow(path, hookspool.FromEvent(*plan.Row)); err != nil {
			fmt.Fprintf(stderr, "observer-hook: %s spool: %v\n", label, err)
		}
	}
	if plan.SeedPidbridge {
		registerSessionAncestors(ctx, deps.parentPID, deps.ancestors, plan.SessionID, plan.Cwd,
			tool, deps.pidbridge(configPath), stderr, label)
	}
}
