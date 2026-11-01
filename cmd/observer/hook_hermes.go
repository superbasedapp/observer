//go:build !sbo_omit_adapter_hermes

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/marmutapp/superbased-observer/internal/adapter/hermes"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// hook_hermes.go is adapter.hermes's half of the hook receiver table
// (modular packaging P5, lane MP-L1D, T-598): a build with
// sbo_omit_adapter_hermes leaves this file and internal/adapter/hermes
// out. Without it `observer hook hermes <event>` has no receiver: a
// leftover plugin hook is answered by the L2 adapter gate
// (hook_components.go), and a pre_tool_call gate still reaches the
// binding-driven plugin dialect (dispatchBindingDialect), which needs no
// hermes code.
func init() { hookReceivers["hermes"] = handleHermesHook }

// handleHermesHook dispatches a Hermes Agent hook event delivered by
// the Python plugin bridge at ~/.hermes/plugins/superbased-observer/.
//
// Wire shape per docs/hermes-adapter-plan.md §11.1 + §17.1.F:
// structured JSON on stdin carrying event=tool_call|session_start|
// session_end|api_request|subagent_stop plus tool-specific fields
// (tool_name, args, result, cwd, model, usage, …). Per
// hermes_cli/plugins.py the bridge's subprocess.run wrapper has a
// 0.5 s timeout and swallows exceptions - observer being down or
// slow MUST never propagate into the host. We reply approve on
// stdout immediately and do all DB work after.
//
// Both tool-event (ActionFoo rows) and token-event (post_api_request
// usage) paths flow through here; the per-event dispatch lives in
// internal/adapter/hermes/hook.go::BuildToolEvent / BuildTokenEvent
// so the parser is shared with the SQLite backfill path.
func handleHermesHook(ctx context.Context, event, configPath string) {
	label := "hermes"
	if event != "" {
		label = "hermes:" + event
	}
	// pre_tool_call is a GATE (Lane A7, operator decision 2026-10-02): it is
	// answered in the plugin dialect by the shared plugin tool gate, never by
	// the approve-first capture path below.
	if dispatchBindingDialect(ctx, "hermes", event, configPath) {
		return
	}

	body, _ := io.ReadAll(io.LimitReader(os.Stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	noteHookPayload(body)
	// Reply approve immediately - host must never wait on the DB
	// path. Bridge accepts "approve" identically to the Claude Code
	// shape; on parse failure it falls back to no-op.
	_ = json.NewEncoder(hookStdout).Encode(hook.Decision{Decision: "approve"})
	markHookReplied()

	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: %s config: %v\n", label, err)
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: %s db: %v\n", label, err)
		return
	}
	defer database.Close()

	// A hermes session_start seeds the pid bridge. The reply already
	// went out above; do this before the (possibly early-returning)
	// ingest so a session_start always seeds. Writer reuses this
	// process's open DB handle.
	seedHermesSessionPidbridge(ctx, event, body, hookContext(ctx).ParentPID(), hookContext(ctx).Ancestors,
		func(wctx context.Context, e pidbridge.Entry) error { return pidbridge.New(database).Write(wctx, e) },
		os.Stderr)

	sc := scrub.New()

	var toolEvents []models.ToolEvent
	var tokenEvents []models.TokenEvent

	if ev, ok, buildErr := hermes.BuildToolEvent(event, body, sc); buildErr != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: %s build tool event: %v\n", label, buildErr)
	} else if ok {
		toolEvents = append(toolEvents, ev)
	}

	if tok, ok, buildErr := hermes.BuildTokenEvent(event, body); buildErr != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: %s build token event: %v\n", label, buildErr)
	} else if ok {
		tokenEvents = append(tokenEvents, tok)
	}

	if len(toolEvents) == 0 && len(tokenEvents) == 0 {
		return
	}

	insertCtx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
	defer cancel()
	hookStore := store.New(database)
	hookStore.SetTasksEnabled(cfg.Tasks.Enabled)
	hookStore.SetTasksOptions(cfg.Tasks.MatchMode, cfg.Tasks.ConcurrentAttribution, cfg.Tasks.IncludeSidechains)
	if _, err := hookStore.Ingest(insertCtx, toolEvents, tokenEvents, store.IngestOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: %s insert: %v\n", label, err)
	}
}

// seedHermesSessionPidbridge writes a pidbridge row for a hermes
// session_start hook. Unlike claude-code/codex/cursor, the Hermes plugin
// runs IN-PROCESS in the long-lived python agent and can hand us its own
// pid directly (os.getpid(), additive wire field since v1.20), so we
// register that single pid - it is the process that opens provider API
// sockets. The os.getppid() the plugin also sends is the agent's PARENT
// (usually the user's shell) and is deliberately NOT seeded: registering
// a shell would poison the bridge for later unrelated connections (D17).
//
// Compat both ways: an OLDER plugin sends no pid - we fall back to the
// ancestor-walk, which still works because `observer hook hermes` is an
// exec'd subprocess CHILD of that same python process (subprocess.run,
// no shell), so os.Getppid() reaches it. A NEWER plugin talking to an
// OLDER observer is fine too: Go's json.Unmarshal ignores the unknown
// pid/ppid fields. Split out for unit-testability (injected ancestors +
// writer). Best-effort + fail-open throughout.
func seedHermesSessionPidbridge(
	ctx context.Context,
	event string,
	body []byte,
	hookParentPID int,
	ancestors ancestorsFunc,
	writer pidbridgeWriter,
	stderr io.Writer,
) {
	var meta struct {
		Event     string `json:"event"`
		SessionID string `json:"session_id"`
		Cwd       string `json:"cwd"`
		PID       int    `json:"pid"`
	}
	_ = json.Unmarshal(body, &meta)
	name := event
	if name == "" {
		name = meta.Event
	}
	if name != hermes.EventSessionStart {
		return
	}
	if meta.PID > 1 {
		// Plugin-supplied pid: register it directly (the plugin runs in
		// this process, so no walk is required).
		registerSessionAncestors(ctx, meta.PID, func(p int) []int { return []int{p} },
			meta.SessionID, meta.Cwd, models.ToolHermes, writer, stderr, "hermes:session-start")
		return
	}
	// Older plugin without a pid: ancestor-walk the exec'd hook child.
	registerSessionAncestors(ctx, hookParentPID, ancestors, meta.SessionID, meta.Cwd,
		models.ToolHermes, writer, stderr, "hermes:session-start")
}
