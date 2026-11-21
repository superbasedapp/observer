//go:build !sbo_omit_adapter_cursor

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	cursoradapter "github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// hook_cursor.go is adapter.cursor's half of the hook receiver table (lane
// MP-L1D, T-598): a build with sbo_omit_adapter_cursor leaves this file,
// internal/hook's cursor receiver and internal/adapter/cursor out, and
// hook_cursor_omit.go registers the gate-only receiver instead.
func init() { hookReceivers["cursor"] = handleCursorHook }

// handleCursorHook opens the observer DB and dispatches the cursor hook.
// Replies on stdout immediately (handled inside HandleCursorEvent) so the
// host doesn't wait on the DB insert.
func handleCursorHook(ctx context.Context, event, configPath string) {
	if event == "" {
		event = "unknown"
	}
	if event == cursoradapter.EventAfterAgentThought {
		// This observation only stashes a scrubbed preview for the next
		// action; it has neither a database row nor a guard decision. Cursor
		// CLI waits for process exit, so opening/checking the full database
		// here can stall its stream even after the hook has written a reply.
		//
		// The one exception is a root-less Cloud Agent thought
		// (cursoradapter.ThoughtMintsRow): no local successor ever fires
		// for it, so it lands its own row. The reply still goes out first,
		// with no database open; only then is the row captured.
		body, _ := readHookBodyDetectTruncation(os.Stdin, defaultHookBodyLimit)
		body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
		noteHookPayload(body)
		hook.HandleCursorEvent(event, nil, scrub.New(), bytes.NewReader(body), hookStdout, os.Stderr, 0)
		markHookReplied()
		if cursoradapter.ThoughtMintsRow(body) {
			captureCursorAfterReply(ctx, event, body, configPath)
		}
		return
	}
	if b, ok := resolveHookInvocationBinding(models.ToolCursor, event); ok && toolGateServed(b) {
		// The universal preToolUse gate (hook-parity A2): answered through
		// the one tool-gate path with NO DB open before the reply, then
		// captured like every other cursor event.
		body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
		body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
		runToolGate(models.ToolCursor, "cursor:"+event, b, body, truncated, configPath, hookStdout, os.Stderr)
		captureCursorAfterReply(ctx, event, body, configPath)
		return
	}
	cfg, stop, err := loadGateConfig(configPath, nil, os.Stderr)
	if stop {
		return
	}
	if err != nil {
		// Fall back to approve-only (a gate event under enforcement has
		// failed closed above, section 5.7).
		fmt.Fprintf(os.Stderr, "observer-hook: cursor config: %v\n", err)
		hook.HandleApprove("cursor:"+event, os.Stdin, hookStdout, os.Stderr)
		markHookReplied()
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: cursor db: %v\n", err)
		// The guarded receiver cannot be composed without its store.
		if hookFailClosed(guardposture.KindGuardInit, nil) {
			return
		}
		hook.HandleApprove("cursor:"+event, os.Stdin, hookStdout, os.Stderr)
		markHookReplied()
		return
	}
	defer database.Close()

	sc := scrub.New()
	// v1.6.23 audit F3/F4: postToolUse tool_output bodies and beforeReadFile
	// file content land in action_excerpts the same way the daemon watcher
	// indexes them, and under the SAME [compression.indexing].enabled switch
	// (T-420): hookCaptureStore resolves it once, so with indexing off the
	// hook writes no excerpt rows.

	// Guard seam (G6): cursor's before-events carry documented
	// permission JSON, so the guarded receiver can deny/ask. Nil
	// guard (disabled, mode off, construction failure) degrades to
	// the unguarded receiver - exactly the pre-G6 behavior. The
	// persist callback reuses THIS process's already-open DB handle
	// (unlike claude-code's lazy open, the cursor hook holds one for
	// capture anyway).
	// Read the body once: the event receiver needs it for the ingest,
	// and the sessionStart pidbridge seed below needs the
	// conversation_id + workspace root. The receiver still replies on
	// stdout first, so the host is never blocked by the seed. A raised,
	// truncation-detecting bound (B2, final-fix review): this same read
	// carries Cursor's beforeSubmitPrompt event, so it must be sized
	// and instrumented like every other prompt-submit-capable read in
	// this file - see readHookBodyDetectTruncation's doc comment.
	body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	hook.DumpHookShape(models.ToolCursor, event, body)
	noteHookPayload(body)

	if !truncated && hookPayloadUnparseable(body) && hookFailClosed(guardposture.KindUnparseable, body) {
		return
	}
	var g *guard.Guard
	if cfg.Guard.Enabled && cfg.Guard.Mode != "off" {
		g = buildHookGuard(cfg, os.Stderr)
		if g == nil && hookFailClosed(guardposture.KindGuardInit, body) {
			return
		}
	}
	// sessionStart can carry an armed session handoff as
	// additional_context (context_inject binding, handoff_hook.go).
	cursorOut := wrapSessionStartContext(ctx, hookStdout, models.ToolCursor, event, body, configPath)
	// postToolUse can carry the security feedback lines as
	// additional_context (lane sec-h, security_feedback.go); unchanged
	// unless security.feedback is selected.
	cursorOut = securityPostFeedbackWriter(ctx, cursorOut, models.ToolCursor, event, body, configPath)
	judgedOnly := false
	if event == cursoradapter.EventBeforeSubmitPrompt && (g == nil || !promptGuardEnabled(cfg)) {
		// The local prompt guard does not evaluate this prompt, but the
		// organization's judge still runs (adm-2 fixes-1, H3). On its block
		// the reply is out; the capture still runs (a refused prompt is an
		// attempt worth recording).
		handled, after, _ := hook.HandlePromptSubmitOrgJudge(models.ToolCursor, hook.PromptDialectCursor, event, body, truncated, newOrgPromptJudge(configPath, cfg), cursorOut, os.Stderr)
		if handled {
			judgedOnly = true
			markHookReplied()
			hook.CaptureCursorEvent(event, body, hookCaptureStore(database, cfg.Compression.Indexing), sc, os.Stderr, cfg.Observer.Hooks.HookTimeout())
			if after != nil {
				after()
			}
		}
		if !handled && judgeOnlyUndecodableRefused(hook.PromptDialectCursor, body, truncated) {
			return
		}
	}
	if !judgedOnly && g != nil {
		st := hookCaptureStore(database, cfg.Compression.Indexing)
		persist := func(v guard.ActionVerdict) {
			pctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
			defer cancel()
			if _, err := st.PersistGuardVerdicts(pctx, []guard.ActionVerdict{v}); err != nil {
				fmt.Fprintf(os.Stderr, "observer-hook: cursor guard persist: %v\n", err)
			}
			g.MaybeAlert(v)
		}
		// gd starts as a TRUE nil interface (never assigned from a nil
		// *guard.Guard, which would be the classic typed-nil trap -
		// hook.CursorEvaluator's own nil check inside
		// handleCursorPromptSubmit relies on this). beforeSubmitPrompt
		// additionally gates on the [guard.prompt] hook_lane knob
		// (promptGuardEnabled) - a knob the OTHER cursor channels
		// (shell/MCP/file) don't consult at all, so it must not affect
		// their gd.
		var gd hook.CursorEvaluator
		switch {
		case event == cursoradapter.EventBeforeSubmitPrompt && promptGuardEnabled(cfg):
			// The prompt gate also asks the organization's prompt judge
			// (lane adm-2), an optional capability of the evaluator.
			gd = withOrgPromptJudge(g, configPath, cfg)
		case event != cursoradapter.EventBeforeSubmitPrompt:
			gd = g
		}
		// A payload Cursor's gate cannot decode where it reads it was not
		// judged: under enforcement it fails closed (FU-161).
		if gd != nil && hook.CursorPayloadUndecodable(event, body) && hookFailClosed(guardposture.KindUnparseable, body) {
			return
		}
		enrich := securityToolGateEnrich(configPath, models.ToolCursor, event, hookSecurityAliases(cfg, nil))
		// The allow seam writes an allowed agent commit's trailer marker
		// before the reply (lane SEC-F2B, P-078 ruling 3).
		hook.HandleCursorEventGated(event, gd, persist, enrich, provenanceAgentCommitAllowed, st, sc, bytes.NewReader(body), truncated, cursorOut, os.Stderr, cfg.Observer.Hooks.HookTimeout())
	} else if !judgedOnly {
		hook.HandleCursorEvent(event, hookCaptureStore(database, cfg.Compression.Indexing), sc, bytes.NewReader(body), cursorOut, os.Stderr, cfg.Observer.Hooks.HookTimeout())
	}
	// P2-1: both branches above reply on stdout FIRST internally -
	// never let a panic in the pidbridge seed below cause
	// recoverHookPanic to write a second reply on top of it.
	markHookReplied()
	// preCompact (compact_lifecycle) reaches the one compaction recorder
	// after the reply (hook_observe.go).
	recordObserveBinding(ctx, models.ToolCursor, "cursor:"+event, event, body, configPath, os.Stderr)

	// A cursor sessionStart hook runs as a descendant of the cursor
	// process, so the claude-code ancestor-walk resolves cursor's pid
	// verbatim (no pid rides in the payload). Best-effort + fail-open -
	// the reply already went out above.
	seedCursorSessionPidbridge(ctx, event, body, hookContext(ctx).ParentPID(), hookContext(ctx).Ancestors,
		makePidbridgeWriter(configPath), sc, os.Stderr)
	if event == cursoradapter.EventSessionStart && !cursoradapter.IsRemoteAgentPayload(body) {
		recordSessionStartTrust(ctx, models.ToolCursor, body, configPath, os.Stderr)
	}
}

// captureCursorAfterReply runs the cursor capture half (rows, outcomes,
// accounts) for an event whose reply already went out. Best-effort.
func captureCursorAfterReply(ctx context.Context, event string, body []byte, configPath string) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: cursor capture db: %v\n", err)
		return
	}
	defer database.Close()
	st := hookCaptureStore(database, cfg.Compression.Indexing)
	hook.CaptureCursorEvent(event, body, st, scrub.New(), os.Stderr, cfg.Observer.Hooks.HookTimeout())
}

// seedCursorSessionPidbridge writes pidbridge rows for a cursor
// sessionStart hook, ancestor-walking the hook process to reach the
// long-lived cursor pid. It no-ops for every other cursor event and for
// cloud/background-agent sessions (no local process worth seeding).
// Split out so it's unit-testable with an injected ancestors func +
// writer.
//
// conversation_id (== the session id) is decoded via cursor.BuildEvent
// so workspace_roots resolves through the same list/object tolerance the
// ingest path uses. NOTE: this repo has never captured a live
// sessionStart payload, so the conversation_id-present assumption rests
// on the official cursor.com/docs/hooks common-payload contract that the
// seven captured events do follow.
func seedCursorSessionPidbridge(
	ctx context.Context,
	event string,
	body []byte,
	parentPID int,
	ancestors ancestorsFunc,
	writer pidbridgeWriter,
	sc *scrub.Scrubber,
	stderr io.Writer,
) {
	// A Cloud Agent (cursoradapter.IsRemoteAgentPayload: a `bc-` id, or
	// is_background_agent) has no local process to seed: its model traffic
	// runs in Cursor's remote VM and never reaches the local proxy, so the
	// ancestors the walk finds are only the hook bridge's own relay pids.
	// The check must be the adapter's class, not the payload flag alone:
	// Cursor 3.23.12 sends is_background_agent=false for bc- conversations,
	// and the seed then paid two extra config loads, database opens and
	// writes (each with SQLite's 30 s busy timeout and no deadline) for
	// nothing. Those were the only database writes on that sessionStart,
	// and the likely cause of a 19.85 s one on 2026-10-05.
	var flags struct {
		Event string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(body, &flags)
	name := event
	if name == "" {
		name = flags.Event
	}
	if name != cursoradapter.EventSessionStart || cursoradapter.IsRemoteAgentPayload(body) {
		return
	}
	ev, ok, err := cursoradapter.BuildEvent(cursoradapter.EventSessionStart, body, sc)
	if err != nil || !ok {
		return
	}
	registerSessionAncestors(ctx, parentPID, ancestors, ev.SessionID, ev.ProjectRoot,
		models.ToolCursor, writer, stderr, "cursor:session-start")
}
