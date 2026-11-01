//go:build !sbo_omit_adapter_codex && !sbo_omit_adapter_open_interpreter

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	codexadapter "github.com/marmutapp/superbased-observer/internal/adapter/codex"
	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// hook_codex.go is adapter.codex's half of the hook receiver table (lane
// MP-L1D, T-598): a build with sbo_omit_adapter_codex (or the bundled
// sbo_omit_adapter_open_interpreter) leaves this file, internal/hook's
// codex receiver and internal/adapter/codex out, and hook_codex_omit.go
// registers the gate-only receiver instead.
func init() { hookReceivers["codex"] = handleCodexHook }

// handleCodexHook opens the observer DB and dispatches a Codex hook.
// Replies on stdout immediately (inside HandleCodexEvent) so the host
// doesn't wait on the DB insert. Codex's hook event names are
// CamelCase identical to Claude Code's; we forward them as-is to the
// adapter (no kebab-case translation as observer's CLI does for
// claude-code).
func handleCodexHook(ctx context.Context, event, configPath string) {
	if event == "" {
		event = "unknown"
	}
	if b, ok := resolveHookInvocationBinding(models.ToolCodex, event); ok && toolGateServed(b) {
		// The tool gate (hook-parity A1): evaluated and answered BEFORE
		// anything else, with no DB open ahead of the reply; the account
		// evidence this event carries is recorded after it.
		body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
		body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
		runToolGate(models.ToolCodex, "codex:"+event, b, body, truncated, configPath, hookStdout, os.Stderr)
		recordCodexAccountsAfterReply(ctx, event, body, configPath)
		return
	}
	cfg, stop, err := loadGateConfig(configPath, nil, os.Stderr)
	if stop {
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: codex config: %v\n", err)
		// Bare ack via empty JSON object - codex hooks accept this as
		// "no action" across all event classes.
		_ = json.NewEncoder(hookStdout).Encode(struct{}{})
		markHookReplied()
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: codex db: %v\n", err)
		if hookFailClosed(guardposture.KindGuardInit, nil) {
			return
		}
		_ = json.NewEncoder(hookStdout).Encode(struct{}{})
		markHookReplied()
		return
	}
	defer database.Close()

	// Read the body once: HandleCodexEvent needs it for the ingest, and
	// the SessionStart pidbridge seed below needs the session_id + cwd.
	// A raised, truncation-detecting bound (B2, final-fix review):
	// Codex's UserPromptSubmit event shares this same read, so the
	// limit must be sized for a prompt-submit payload, and a payload
	// that DOES exceed it must be flagged rather than silently fed to
	// HandlePromptSubmitGuarded as if it were complete.
	body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	hook.DumpHookShape(models.ToolCodex, event, body)
	noteHookPayload(body)

	sc := scrub.New()
	// Part B: UserPromptSubmit is special-cased to the guarded
	// prompt-submit seam BEFORE HandleCodexEvent's unconditional `{}`
	// reply - Codex's own receiver imports no guard at all and always
	// acks empty (contract §1.2's headline gap: "zero guard wiring on
	// any Codex event"). handled=false (guard off/disabled/misconfigured,
	// or the dispatch decided not to intervene) falls through to the
	// EXISTING unguarded HandleCodexEvent call, byte-identical to
	// before this seam existed.
	handled := false
	if event == codexadapter.HookEventUserPromptSubmit {
		// A prompt is node activity (policy-freshness trigger, P2).
		_ = budgetwarnfile.TouchActivity(cfg.Observer.DBPath)
	}
	if event == codexadapter.HookEventUserPromptSubmit && !truncated && hookPayloadUnparseable(body) &&
		hookFailClosed(guardposture.KindUnparseable, body) {
		return
	}
	if event == codexadapter.HookEventUserPromptSubmit && promptGuardEnabled(cfg) {
		g := buildHookGuard(cfg, os.Stderr)
		if g == nil && hookFailClosed(guardposture.KindGuardInit, body) {
			return
		}
		if g != nil {
			var after func()
			// PromptDialectTopLevelBlock signals a block in its JSON
			// reply ({"decision":"block",…}), which Codex honours per
			// its hook docs; the row's blockExitCode:2 is deliberately
			// NOT applied by this receiver (it keeps ingesting after
			// the reply and exits 0). Live on Codex 0.160.0 (T-048,
			// 2026-10-03): this JSON exit-0 block stops the prompt (the
			// turn ends with zero model tokens), and so does the
			// fail-closed path's exit-2 block, whose stderr carries the
			// same developer-facing reason.
			handled, after, _ = hook.HandlePromptSubmitGuarded(
				models.ToolCodex, hook.PromptDialectTopLevelBlock, event, body, truncated, g,
				makePromptGuardPersist(cfg, g, models.ToolCodex, "codex:"+event, os.Stderr), hookStdout, os.Stderr,
			)
			// FU-161: an undecodable prompt payload fails closed under
			// enforcement instead of reaching the unguarded reply below.
			if !handled && hook.PromptPayloadUndecodable(hook.PromptDialectTopLevelBlock, body) && hookFailClosed(guardposture.KindUnparseable, body) {
				return
			}
			if handled {
				// P2-1: the reply (if this dialect's builder returned
				// one) already went out inside the call above - never
				// let a panic in the ingest/account-capture/pidbridge
				// work below cause recoverHookPanic to write a second
				// one. exitCode is deliberately discarded above (this
				// receiver never exits non-zero - see the comment
				// three lines up), so there is no pending exit code to
				// preserve here, unlike the two Claude Code call sites.
				markHookReplied()
			}
			if after != nil {
				after()
			}
		}
	}
	if handled {
		// Reply already sent by the guard path above - still capture
		// the action row (mirrors HandleCodexEvent's own ingest half,
		// minus the `{}` reply it would otherwise send): capture
		// proceeds regardless of the verdict, a denied attempt is
		// still an attempt worth recording (same posture as Claude
		// Code's and Cursor's guarded receivers).
		if ev, ok, err := codexadapter.BuildHookEvent(event, body, sc); err != nil {
			fmt.Fprintf(os.Stderr, "observer-hook: codex build %s: %v\n", event, err)
		} else if ok && ev.SessionID != "" {
			ictx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
			if _, err := store.New(database).Ingest(ictx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
				fmt.Fprintf(os.Stderr, "observer-hook: codex %s insert: %v\n", event, err)
			}
			cancel()
		}
	} else {
		// HandleCodexEvent replies on stdout FIRST, so the host is
		// unblocked before either the ingest or the seed runs.
		// SessionStart can carry an armed session handoff as
		// hookSpecificOutput.additionalContext (handoff_hook.go).
		codexOut := wrapSessionStartContext(ctx, hookStdout, models.ToolCodex, event, body, configPath)
		// PostToolUse can carry the security feedback lines (lane sec-h,
		// security_feedback.go); unchanged unless security.feedback is
		// selected.
		codexOut = securityPostFeedbackWriter(ctx, codexOut, models.ToolCodex, event, body, configPath)
		hook.HandleCodexEvent(event, store.New(database), sc, bytes.NewReader(body),
			codexOut, os.Stderr, cfg.Observer.Hooks.HookTimeout())
		markHookReplied()
	}
	// PreCompact / PostCompact reach the one compaction recorder after the
	// reply (hook_observe.go).
	recordObserveBinding(ctx, models.ToolCodex, "codex:"+event, event, body, configPath, os.Stderr)

	// Both guarded and unguarded paths have replied. Capture only the login
	// snapshot from the source transcript's profile, with exact turn binding.
	if accounts := hook.LocalAccountObservations(ctx, models.ToolCodex, event, body); len(accounts) > 0 {
		ictx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
		if err := store.New(database).RecordToolAccounts(ictx, accounts); err != nil {
			fmt.Fprintf(os.Stderr, "observer-hook: codex account capture: %v\n", err)
		}
		cancel()
	}
	// A codex SessionStart hook runs as a descendant of the codex
	// process, so the claude-code ancestor-walk resolves the codex pid
	// verbatim - reuse the shared writer. Best-effort + fail-open: the
	// reply already went out above.
	seedCodexSessionPidbridge(ctx, event, body, hookContext(ctx).ParentPID(), hookContext(ctx).Ancestors,
		makePidbridgeWriter(configPath), os.Stderr)
	if event == codexadapter.HookEventSessionStart {
		recordSessionStartTrust(ctx, models.ToolCodex, body, configPath, os.Stderr)
	}
}

// recordCodexAccountsAfterReply records the login snapshot a codex tool
// event carries (hook.LocalAccountObservations), opening the DB only when
// there is evidence to write. Best-effort; the reply already went out.
func recordCodexAccountsAfterReply(ctx context.Context, event string, body []byte, configPath string) {
	accounts := hook.LocalAccountObservations(ctx, models.ToolCodex, event, body)
	if len(accounts) == 0 {
		return
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: codex account capture db: %v\n", err)
		return
	}
	defer database.Close()
	ictx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
	defer cancel()
	if err := store.New(database).RecordToolAccounts(ictx, accounts); err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: codex account capture: %v\n", err)
	}
}

// seedCodexSessionPidbridge writes pidbridge rows for a codex
// SessionStart hook, ancestor-walking the hook process to reach the
// long-lived codex pid (same shape as claude-code). It no-ops for every
// other codex event. Split out from handleCodexHook so it's unit-testable
// with an injected ancestors func + writer.
func seedCodexSessionPidbridge(
	ctx context.Context,
	event string,
	body []byte,
	parentPID int,
	ancestors ancestorsFunc,
	writer pidbridgeWriter,
	stderr io.Writer,
) {
	var meta struct {
		SessionID     string `json:"session_id"`
		Cwd           string `json:"cwd"`
		HookEventName string `json:"hook_event_name"`
	}
	_ = json.Unmarshal(body, &meta)
	name := event
	if name == "" {
		name = meta.HookEventName
	}
	if name != codexadapter.HookEventSessionStart {
		return
	}
	registerSessionAncestors(ctx, parentPID, ancestors, meta.SessionID, meta.Cwd,
		models.ToolCodex, writer, stderr, "codex:session-start")
}
