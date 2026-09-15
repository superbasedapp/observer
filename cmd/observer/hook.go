package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	codexadapter "github.com/marmutapp/superbased-observer/internal/adapter/codex"
	cursoradapter "github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/adapter/hermes"
	"github.com/marmutapp/superbased-observer/internal/compression/indexing"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/intelligence/compaction"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// defaultHookMaxRuntime is the wall-clock budget for a single `observer
// hook` invocation. Hooks that exceed it exit promptly via os.Exit(0)
// (fail-open — a timeout must never block the host tool). The
// 30 s default is generous vs. the typical hook (sub-second to ~3 s
// including db.Open + a single write) but tight enough that a hung hook
// can't pin the host AI tool for minutes. Override with `--max-runtime`
// or `OBSERVER_HOOK_MAX_RUNTIME`. See V3-1 in
// docs/observer-platform-issues-v3.md: pre-fix, a hook subprocess could
// block 20+ minutes waiting on stuck DB / syscall paths because the
// "MUST NEVER block the host" invariant was documented but unenforced.
const defaultHookMaxRuntime = 30 * time.Second

// promptSubmitBodyLimit (B2, final-fix review) is the stdin read bound
// for a hook receiver that can carry a prompt-submit event — larger
// than defaultHookBodyLimit because a prompt-submit payload's size is
// the DEVELOPER's own prompt length, not a bounded tool-output excerpt,
// and a real (if unusually long) prompt must not be truncated into a
// guard bypass just because the read bound was tuned for smaller
// events. 8 MiB comfortably covers a large pasted document while still
// bounding worst-case memory for a single hook invocation.
const promptSubmitBodyLimit = 8 * 1024 * 1024

// defaultHookBodyLimit is the stdin read bound for every hook event
// that never carries a prompt-submit payload (PreToolUse/PostToolUse/
// session lifecycle/etc.) — unchanged from the original bound.
const defaultHookBodyLimit = 2 * 1024 * 1024

// readHookBodyDetectTruncation reads up to limit+1 bytes from r and
// reports whether the input was longer than limit — in which case body
// is exactly limit bytes, NOT the full payload. (B2, final-fix review.)
//
// This exists because plain `io.ReadAll(io.LimitReader(r, limit))`
// (the pre-fix shape used everywhere in this file) is indistinguishable
// from "the payload happened to be exactly limit bytes or shorter" —
// there is no way for a caller to tell whether body is complete. For
// most hook events that ambiguity is harmless (a truncated
// PostToolUse excerpt just captures less); for a prompt-submit event
// it is a silent guard bypass: a truncated body almost always fails
// its dialect's json.Unmarshal, and the pre-fix caller treated that
// parse failure identically to "no prompt-submit guard installed for
// this tool" and fell through to a plain, unaudited approve — see
// hook.HandlePromptSubmitGuarded's bodyTruncated parameter, which
// this return value feeds.
func readHookBodyDetectTruncation(r io.Reader, limit int64) (body []byte, truncated bool) {
	buf, _ := io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(buf)) > limit {
		return buf[:limit], true
	}
	return buf, false
}

// resolveHookMaxRuntime picks the watchdog budget. Precedence: explicit
// --max-runtime flag (when non-zero) > OBSERVER_HOOK_MAX_RUNTIME env >
// defaultHookMaxRuntime. A non-positive value (after parsing) disables
// the watchdog entirely — escape hatch for diagnostics, not the
// production path.
func resolveHookMaxRuntime(flag time.Duration, env string) time.Duration {
	if flag != 0 {
		return flag
	}
	if env != "" {
		if d, err := time.ParseDuration(env); err == nil {
			return d
		}
	}
	return defaultHookMaxRuntime
}

// installHookWatchdog arms a time.AfterFunc that fires exitFn(0) when
// maxRuntime elapses. Returns a stop func to disarm on a clean exit.
// exitFn is injected so unit tests can verify firing without actually
// terminating the test process. In production, callers wire it to
// os.Exit.
//
// **Fail-OPEN on timeout (exit 0, never 2).** A non-zero exit from a
// PreToolUse hook BLOCKS the host tool — so a watchdog that exits 2 turns
// a transient capture stall (e.g. the DB momentarily locked by a daemon
// startup prune/checkpoint on a large DB) into a hard block on the user's
// work, cascading across the session. A watchdog timeout is NOT a deny
// decision; the hook simply didn't finish in time, so it must allow the
// tool through. This upholds the command's "exit 0 on every path"
// invariant (see newHookCmd). The process still terminates promptly, so
// the host tool is never pinned waiting.
func installHookWatchdog(maxRuntime time.Duration, exitFn func(int), stderr io.Writer) func() {
	if maxRuntime <= 0 {
		return func() {}
	}
	timer := time.AfterFunc(maxRuntime, func() {
		fmt.Fprintf(stderr, "observer-hook: max-runtime %v exceeded; allowing the tool (fail-open, exit 0; see V3-1)\n", maxRuntime)
		exitFn(0)
	})
	return func() { timer.Stop() }
}

// newHookCmd implements `observer hook <tool> <event>`. The host AI tool
// invokes this on every fired event with a JSON payload on stdin.
//
// For Claude Code (and any unknown tool) we approve immediately and rely on
// the JSONL watcher for capture. For Cursor — which has no native session
// log — we additionally insert the event into the observer DB before exiting.
//
// The command is intentionally flat rather than a subcommand tree so that
// settings.json / hooks.json can hard-code predictable command strings.
//
// Spec P1: this command MUST exit 0 on every path. Errors are written to
// stderr but never propagate as a non-zero exit. A process-level watchdog
// (`--max-runtime`, default 30 s) is the defensive belt-and-suspenders:
// if any code path blocks (stuck DB write, blocked syscall, anything) the
// AfterFunc calls os.Exit(0) — fail-OPEN, so a transient capture stall
// (e.g. the DB momentarily locked by a daemon startup prune/checkpoint)
// can never block the host tool. The process still terminates promptly.
//
// `--config <path>` propagates the proxy's config to the hook handler so
// the DB write lands on the same observer.db the proxy is using. Without
// it, the hook always reads ~/.observer/config.toml regardless of which
// proxy daemon fired it.
// hookReceivers is the table-driven dispatch for `observer hook <tool>
// <event>` (CLAUDE.md rule 5: decision logic is table-driven, never a
// growing switch/if-else ladder). A tool with NO entry here falls
// through to the unconditional approve-only default in newHookCmd —
// correct for a watcher-only-capture tool, but a BUG for any tool
// whose internal/integration registry row claims a non-zero
// PromptLane (BLOCK-1, phase-2 review): that claim is a promise that
// `observer hook <tool> UserPromptSubmit` actually evaluates the
// guard, and a missing entry here silently breaks that promise no
// matter what the registry/conformance/docs say.
// TestPromptLaneHookRowsHaveAReceiver walks the registry and pins
// every PromptLaneHook row to an entry in this table.
var hookReceivers = map[string]func(ctx context.Context, event, configPath string){
	"cursor":      handleCursorHook,
	"claude-code": handleClaudeCodeHook,
	"codex":       handleCodexHook,
	"hermes":      handleHermesHook,
	"droid": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolDroid, "droid", hook.PromptDialectTopLevelBlock, "UserPromptSubmit", event, configPath)
	},
	"qwen-code": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolQwenCode, "qwen-code", hook.PromptDialectTopLevelBlock, "UserPromptSubmit", event, configPath)
	},
	"gemini-cli": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolGeminiCLI, "gemini-cli", hook.PromptDialectGemini, "BeforeAgent", event, configPath)
	},
	// Part B item 2 (phase-3a, docs/plans/prompt-submit-intervention-
	// exploration-2026-09-07.md §2.1b): the documented long-tail
	// vendors. All five, like droid/qwen-code/gemini-cli above, have
	// no OTHER hook this repo captures — prompt-submit is their entire
	// hook surface.
	"qoder": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolQoder, "qoder", hook.PromptDialectQoder, "UserPromptSubmit", event, configPath)
	},
	"poolside": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolPoolside, "poolside", hook.PromptDialectPoolside, "UserPromptSubmit", event, configPath)
	},
	// zcode's receiver is wired here like every other PromptLaneHook
	// row, but its REGISTRATION writer deliberately does not exist
	// (Hook.AutoWired:false, internal/integration) pending a liveness
	// probe (zai-org/feedback#32) — `observer hook zcode
	// UserPromptSubmit` works today for anyone who wires the config by
	// hand or via `observer doctor --probe-hook zcode`.
	"zcode": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolZcode, "zcode", hook.PromptDialectZcode, "UserPromptSubmit", event, configPath)
	},
	// devin's dispatch tool string covers Windsurf/Devin Desktop
	// Cascade's pre_user_prompt — the CLI's own separate, still-unwired
	// hooks.v1.json is untouched (see internal/integration's devin row).
	"devin": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolDevin, "devin", hook.PromptDialectCascade, "pre_user_prompt", event, configPath)
	},
	// command-code's event name matches the Mods SDK hook name
	// (transformInput) verbatim — the go:embed'd .ts bridge invokes
	// `observer hook command-code transformInput` exactly like every
	// other dialect's argv shape, even though the caller is a Node/jiti
	// process rather than a shell.
	"command-code": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolCommandCode, "command-code", hook.PromptDialectCommandCode, "transformInput", event, configPath)
	},
}

func newHookCmd() *cobra.Command {
	var (
		configPath string
		maxRuntime time.Duration
	)
	cmd := &cobra.Command{
		Use:   "hook <tool> <event>",
		Short: "Handle an AI-tool hook event on stdin and reply on stdout",
		Long: "Invoked by the host AI tool via its hook configuration. Reads a\n" +
			"JSON payload from stdin and replies on stdout. For Cursor, also\n" +
			"records the event in the observer DB. MUST NEVER block the host\n" +
			"tool — errors are logged to stderr and swallowed. A process\n" +
			"watchdog (--max-runtime, default 30s) enforces the invariant.",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			budget := resolveHookMaxRuntime(maxRuntime, os.Getenv("OBSERVER_HOOK_MAX_RUNTIME"))
			stopWatchdog := installHookWatchdog(budget, os.Exit, os.Stderr)
			defer stopWatchdog()

			tool := args[0]
			event := ""
			if len(args) >= 2 {
				event = args[1]
			}
			if fn, ok := hookReceivers[tool]; ok {
				fn(cmd.Context(), event, configPath)
			} else {
				label := tool
				if event != "" {
					label = tool + ":" + event
				}
				hook.HandleApprove(label, os.Stdin, os.Stdout, os.Stderr)
			}
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml — when set, hook DB writes land on the config's observer.db (matches the proxy / MCP server invocations)")
	cmd.Flags().DurationVar(&maxRuntime, "max-runtime", 0, "Hard wall-clock cap on a single hook invocation; on exceedance the process exits(0) FAIL-OPEN so the host AI tool is never pinned or blocked by a timeout (a non-zero exit would itself block PreToolUse-class hooks — see installHookWatchdog). 0 = use OBSERVER_HOOK_MAX_RUNTIME or the 30s default. See docs/observer-platform-issues-v3.md V3-1.")
	return cmd
}

// handleClaudeCodeHook dispatches Claude Code hook events. For PreCompact
// and PostCompact we write to compaction_events; for PreToolUse we may
// rewrite a Bash command to funnel through `observer run`; other events
// fall through to HandleApprove (the JSONL watcher captures them
// out-of-band). Always replies with an approval on stdout — must never
// block the host.
//
// `configPath`, when non-empty, is forwarded to all `config.Load` calls
// so the hook handler reads the same config (and therefore writes to
// the same DB) as whichever proxy daemon launched it.
func handleClaudeCodeHook(ctx context.Context, event, configPath string) {
	label := "claude-code"
	if event != "" {
		label = "claude-code:" + event
	}
	if event == "pre-tool" {
		handleClaudeCodePreTool(os.Stdin, os.Stdout, os.Stderr, label, configPath)
		return
	}
	if event == "post-tool" {
		handleClaudeCodePostTool(os.Stdin, os.Stdout, os.Stderr, label, configPath)
		return
	}
	if event == "session-start" {
		writer := makePidbridgeWriter(configPath)
		handleClaudeCodeSessionStart(ctx, os.Getppid(), defaultAncestors, os.Stdin, os.Stdout, os.Stderr, label, writer)
		return
	}
	// Tier 1 expansion (2026-05): each of these events maps to one row
	// in the actions table via a per-event builder. Shared helper handles
	// stdin → reply → DB open → insert.
	switch event {
	case "session-end":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeSessionEndEvent)
		return
	case "user-prompt-submit":
		handleClaudeCodeUserPromptSubmit(ctx, label, configPath)
		return
	case "post-tool-failure":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudePostToolFailureEvent)
		return
	case "stop-failure":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeStopFailureEvent)
		return
	case "subagent-start":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeSubagentStartEvent)
		return
	case "subagent-stop":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeSubagentStopEvent)
		return
	case "stop":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeStopEvent)
		return
	case "notification":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeNotificationEvent)
		return
	case "cwd-changed":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeCwdChangedEvent)
		return
	case "setup":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeSetupEvent)
		return
	case "user-prompt-expansion":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeUserPromptExpansionEvent)
		return
	case "post-tool-batch":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudePostToolBatchEvent)
		return
	case "permission-request":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudePermissionRequestEvent)
		return
	case "permission-denied":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudePermissionDeniedEvent)
		return
	case "instructions-loaded":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeInstructionsLoadedEvent)
		return
	case "config-change":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeConfigChangeEvent)
		return
	case "worktree-remove":
		handleClaudeCodeActionEvent(ctx, label, configPath, buildClaudeWorktreeRemoveEvent)
		return
	case "worktree-create":
		// Special path: blocking hook that must write the chosen
		// worktree path on stdout (per docs.claude.com/docs/en/hooks
		// reply matrix) — any non-zero exit or empty stdout fails
		// the Agent spawn. NOT registered by default; user opts in
		// per docs/claude-worktree-hook.md.
		handleClaudeCodeWorktreeCreate(ctx, label, configPath, os.Stdin, os.Stdout, os.Stderr)
		return
	}
	if event != "pre-compact" && event != "post-compact" {
		hook.HandleApprove(label, os.Stdin, os.Stdout, os.Stderr)
		return
	}
	// Read stdin first — we need it for both the approval reply (which is
	// stateless) and the compaction handler.
	body, _ := io.ReadAll(io.LimitReader(os.Stdin, defaultHookBodyLimit))
	// Reply immediately; the DB write is best-effort.
	_ = json.NewEncoder(os.Stdout).Encode(hook.Decision{Decision: "approve"})

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

	var payload struct {
		SessionID string `json:"session_id"`
		Cwd       string `json:"cwd"`
		Trigger   string `json:"trigger"`
	}
	_ = json.Unmarshal(body, &payload)
	if payload.SessionID == "" {
		fmt.Fprintf(os.Stderr, "observer-hook: %s no session_id in payload\n", label)
		return
	}

	rec := compaction.New(database)
	switch event {
	case "pre-compact":
		if _, err := rec.Capture(ctx, compaction.CaptureOptions{
			SessionID:   payload.SessionID,
			ProjectRoot: payload.Cwd,
			Tool:        models.ToolClaudeCode,
			Timestamp:   time.Now().UTC(),
			Trigger:     payload.Trigger,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "observer-hook: %s capture: %v\n", label, err)
		}
	case "post-compact":
		if err := rec.Reconcile(ctx, compaction.ReconcileOptions{
			SessionID: payload.SessionID,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "observer-hook: %s reconcile: %v\n", label, err)
		}
	}
}

// pidbridgeWriter is the injected DB-write side of the SessionStart hook,
// split out so tests can substitute an in-memory writer without touching
// the user's config.
type pidbridgeWriter func(ctx context.Context, e pidbridge.Entry) error

// defaultPidbridgeWriter opens the configured observer DB, writes one
// pidbridge entry, and closes the DB. Safe to call concurrently — each
// invocation opens its own *sql.DB.
func defaultPidbridgeWriter(ctx context.Context, e pidbridge.Entry) error {
	return pidbridgeWriterWithConfig(ctx, e, "")
}

// makePidbridgeWriter returns a writer bound to the given configPath.
// Empty configPath produces the default writer (legacy behaviour).
func makePidbridgeWriter(configPath string) pidbridgeWriter {
	if configPath == "" {
		return defaultPidbridgeWriter
	}
	return func(ctx context.Context, e pidbridge.Entry) error {
		return pidbridgeWriterWithConfig(ctx, e, configPath)
	}
}

func pidbridgeWriterWithConfig(ctx context.Context, e pidbridge.Entry, configPath string) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer database.Close()
	return pidbridge.New(database).Write(ctx, e)
}

// ancestorsFunc returns the list of PIDs to register starting from
// parentPID and walking up the process tree. Injected so tests don't
// need to touch /proc.
type ancestorsFunc func(parentPID int) []int

// defaultAncestors is the production resolver: walks /proc from
// parentPID via PPid, returning each non-shell ancestor up to a cap.
func defaultAncestors(parentPID int) []int {
	return collectClaudeCodeAncestors(parentPID, "/proc", 10)
}

// handleClaudeCodeSessionStart writes pidbridge rows linking every
// non-shell ancestor of the hook process to the session_id in the
// payload, so the proxy can attribute incoming TCP requests even if
// the immediate parent (a short-lived Node worker) has exited by the
// time the API call fires. Always replies approve; DB writes are
// best-effort (spec P1).
//
// We register the whole chain (hook's parent → its parent → ...) up
// to the shell because Claude Code routes hook invocations through
// transient Node workers whose PIDs disappear quickly. Registering
// only os.Getppid() led to unresolvable api_turns.session_id values.
//
// parentPID, ancestors and writer are injected for tests; production
// calls via the dispatcher pass os.Getppid(), defaultAncestors, and
// defaultPidbridgeWriter.
func handleClaudeCodeSessionStart(
	ctx context.Context,
	parentPID int,
	ancestors ancestorsFunc,
	stdin io.Reader,
	stdout, stderr io.Writer,
	label string,
	writer pidbridgeWriter,
) {
	body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))

	var payload struct {
		SessionID     string `json:"session_id"`
		Cwd           string `json:"cwd"`
		HookEventName string `json:"hook_event_name"`
		Source        string `json:"source"`
	}
	_ = json.Unmarshal(body, &payload)

	// Reply approve, optionally carrying additionalContext. A hook-armed
	// session handoff (plan §10 inject_hook, `observer handoff --deliver
	// hook`) takes precedence and consumes the whole hook budget; otherwise
	// the advisor digest rides along (plan §15.7; gated by [advisor]
	// session_digest, default OFF). Both are best-effort point-reads — the
	// hook never computes, and any failure degrades to a plain approve (P6),
	// never blocking the session.
	if extra := composeSessionStartContext(ctx, payload.Cwd); extra != "" {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"decision": "approve",
			"hookSpecificOutput": map[string]any{
				"hookEventName":     "SessionStart",
				"additionalContext": extra,
			},
		})
	} else {
		_ = json.NewEncoder(stdout).Encode(hook.Decision{Decision: "approve"})
	}

	registerSessionAncestors(ctx, parentPID, ancestors, payload.SessionID, payload.Cwd,
		models.ToolClaudeCode, writer, stderr, label)
}

// registerSessionAncestors ancestor-walks parentPID and writes one
// pidbridge row per non-shell ancestor, linking them to sessionID under
// tool. It is the shared write core behind every SessionStart hook whose
// process runs as a DESCENDANT of the tool it observes — claude-code,
// codex, cursor, and (via exec'd subprocess) hermes — because the same
// /proc PPid walk resolves the tool's long-lived pid in each case.
//
// Every guard fails open and logs to stderr without touching the host
// reply (the caller has already sent it): an empty sessionID, a
// reparented-to-init parentPID, an empty ancestor walk, or a per-pid
// writer error each degrade to a no-op. pidbridge failure must NEVER
// block a hook (a non-zero PreToolUse exit blocks the tool).
func registerSessionAncestors(
	ctx context.Context,
	parentPID int,
	ancestors ancestorsFunc,
	sessionID, cwd, tool string,
	writer pidbridgeWriter,
	stderr io.Writer,
	label string,
) {
	if sessionID == "" {
		fmt.Fprintf(stderr, "observer-hook: %s no session_id in payload\n", label)
		return
	}
	if parentPID <= 1 {
		fmt.Fprintf(stderr, "observer-hook: %s refusing to register parent pid %d\n", label, parentPID)
		return
	}
	pids := ancestors(parentPID)
	if len(pids) == 0 {
		fmt.Fprintf(stderr, "observer-hook: %s no ancestor pids collected (parent=%d %s)\n",
			label, parentPID, describePID(parentPID))
		return
	}
	fmt.Fprintf(stderr, "observer-hook: %s registering %d pid(s) for session=%s: %v\n",
		label, len(pids), sessionID, pids)
	for _, pid := range pids {
		entry := pidbridge.Entry{
			PID:       pid,
			SessionID: sessionID,
			Tool:      tool,
			CWD:       cwd,
		}
		if err := writer(ctx, entry); err != nil {
			fmt.Fprintf(stderr, "observer-hook: %s pidbridge pid=%d: %v\n", label, pid, err)
		}
	}
}

// describePID returns a compact diagnostic tag "comm=<comm> cmdline=<args>"
// for a PID so stderr logs make failed walks easier to triage. Best-effort —
// missing/unreadable proc entries return "(gone)".
func describePID(pid int) string {
	comm, ok := readComm(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if !ok {
		return "(gone)"
	}
	cmdline, _ := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	args := strings.ReplaceAll(strings.TrimRight(string(cmdline), "\x00"), "\x00", " ")
	if len(args) > 140 {
		args = args[:137] + "..."
	}
	return fmt.Sprintf("comm=%s cmdline=%q", comm, args)
}

// shellComms is the allowlist of /proc/<pid>/comm values that mark the
// boundary between Claude Code's process tree and the user's
// interactive shell. The walker stops at an interactive shell but
// crosses command-shells (bash -c '...' wrappers), because Claude
// Code invokes hooks via `/bin/bash -c` — if we stopped at any bash
// we'd never reach the long-lived main claude process behind it.
var shellComms = map[string]bool{
	"bash": true, "zsh": true, "sh": true, "fish": true,
	"dash": true, "ash": true, "ksh": true,
}

// initComms marks init-class processes: the boundary between user
// session trees and system space. The walker STOPS at one without
// registering it. This matters for wsl.exe-BRIDGED hooks (Windows AI
// tool + WSL daemon): their WSL-side ancestry is relay "init"
// processes up to the distro init at pid 2, none of which correspond
// to the AI tool — registering them poisons the bridge so that every
// later hookless connection (codex exec, third-party clients)
// ancestor-walks into the stale entry and inherits the wrong
// tool/cwd (D17, found during the A3 soak bring-up).
var initComms = map[string]bool{
	"init": true, "systemd": true,
}

// collectClaudeCodeAncestors walks /proc/<pid>/status:PPid from
// startPID upward, returning each non-shell PID encountered. The walk
// handles two kinds of shells differently:
//
//   - Command-shells (`bash -c '...'` and friends) are SKIPPED but do
//     not terminate the walk. Claude Code wraps hook invocations in
//     `/bin/bash -c` so the hook's immediate parent is almost always a
//     transient command-shell; we need to step past it to find the
//     long-lived main claude process.
//   - Interactive shells (no `-c` in cmdline) TERMINATE the walk.
//     This is the user's session shell and we don't want to attribute
//     future unrelated traffic to it.
//
// Caps at maxDepth to guard against cycles or pathological trees. A
// missing /proc/<pid>/comm entry registers cur as a best-effort floor
// and stops; a missing /proc/<pid>/status terminates further walking.
//
// Typical return for a Claude Code SessionStart hook:
//   - [claude-main]                  (hook spawned via `bash -c` → skipped)
//   - [node-worker, claude-main]     (hook spawned directly)
func collectClaudeCodeAncestors(startPID int, procDir string, maxDepth int) []int {
	if startPID <= 1 || maxDepth <= 0 {
		return nil
	}
	var pids []int
	seen := map[int]bool{}
	cur := startPID
	for i := 0; i < maxDepth && cur > 1; i++ {
		if seen[cur] {
			break
		}
		seen[cur] = true

		comm, commOK := readComm(filepath.Join(procDir, strconv.Itoa(cur), "comm"))
		if cur <= 2 || (commOK && initComms[comm]) {
			// Init-class (pid 1/2 or an init/systemd comm anywhere in
			// the chain — WSL relay processes report comm "init" at
			// arbitrary pids). System space: stop without registering.
			break
		}
		if commOK && shellComms[comm] {
			if !isCommandShell(cur, procDir) {
				// Interactive shell — user's terminal. Stop.
				break
			}
			// Command-shell wrapper (`bash -c ...`). Skip it and keep
			// walking to find what spawned it.
			ppid, err := readPPidFromStatus(filepath.Join(procDir, strconv.Itoa(cur), "status"))
			if err != nil || ppid <= 1 {
				break
			}
			cur = ppid
			continue
		}
		if !commOK {
			// /proc entry vanished between exec and our read. Only
			// best-effort register when this is the starting PID — we
			// need *something* in the bridge to preserve the pre-fix
			// floor behaviour. For a dead mid-walk ancestor there's no
			// PPid link to follow anyway, so we just stop.
			if i == 0 {
				pids = append(pids, cur)
			}
			break
		}
		pids = append(pids, cur)

		ppid, err := readPPidFromStatus(filepath.Join(procDir, strconv.Itoa(cur), "status"))
		if err != nil || ppid <= 1 {
			break
		}
		cur = ppid
	}
	return pids
}

// isCommandShell reports whether pid's /proc/<pid>/cmdline contains
// the `-c` flag. A shell with `-c` is a one-shot command wrapper; a
// shell without `-c` is a user's interactive session.
func isCommandShell(pid int, procDir string) bool {
	b, err := os.ReadFile(filepath.Join(procDir, strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return false
	}
	// /proc/<pid>/cmdline is NUL-separated argv. Skip argv[0] (the
	// shell path itself) — `-c` in arg[0] would be pathological.
	parts := strings.Split(string(b), "\x00")
	for i, p := range parts {
		if i == 0 {
			continue
		}
		if p == "-c" {
			return true
		}
	}
	return false
}

// readComm returns the first line of /proc/<pid>/comm, trimmed. The
// bool reports whether the file could be read — a false return
// terminates the ancestor walk.
func readComm(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// readPPidFromStatus parses /proc/<pid>/status for the PPid: line.
// Duplicate of internal/pidbridge.readPPid; kept local so cmd/observer
// doesn't leak an internal helper and the ancestor collector can be
// tested with a fake /proc.
func readPPidFromStatus(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
		return strconv.Atoi(rest)
	}
	return 0, errors.New("no PPid line")
}

// preToolPayload is the slice of Claude Code's PreToolUse payload that we
// care about. Unknown fields are ignored.
type preToolPayload struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
	// Cwd is the host shell's working directory. Its path style (a
	// Windows drive-letter / backslash vs a POSIX slash) reveals which OS
	// the shell runs on — used by the cross-OS rewrite guard below.
	Cwd string `json:"cwd"`
}

// claudecodeEffortPayload is the slice of any tool-context Claude Code
// hook (PreToolUse / PostToolUse / Stop / SubagentStop) that we need to
// persist the per-turn effort level. tool_use_id ties the row back to
// the matching tool-use action emitted by the JSONL adapter
// (actions.source_event_id is set to the Anthropic `toolu_xxx` block
// ID by internal/adapter/claudecode/adapter.go::buildToolUseEvent).
type claudecodeEffortPayload struct {
	SessionID     string `json:"session_id"`
	ToolUseID     string `json:"tool_use_id"`
	HookEventName string `json:"hook_event_name"`
	Effort        struct {
		Level string `json:"level"`
	} `json:"effort"`
}

// preToolReply is the approval reply with an optional updatedInput payload.
// Claude Code ≥0.2 honors hookSpecificOutput.updatedInput to mutate the Bash
// command argv before the tool call fires; older versions ignore the block
// and run the tool as originally requested (safe-by-default degradation).
type preToolReply struct {
	Decision           string             `json:"decision"`
	Continue           bool               `json:"continue"`
	HookSpecificOutput *preToolRewriteOut `json:"hookSpecificOutput,omitempty"`
}

type preToolRewriteOut struct {
	HookEventName      string         `json:"hookEventName"`
	PermissionDecision string         `json:"permissionDecision"`
	UpdatedInput       map[string]any `json:"updatedInput,omitempty"`
}

// handleClaudeCodePreTool reads a PreToolUse payload and emits an approval
// reply that optionally rewrites a Bash command to funnel through
// `observer run`. Any failure falls through to plain approval — this hook
// MUST NEVER block the host tool.
func handleClaudeCodePreTool(stdin io.Reader, stdout, stderr io.Writer, label, configPath string) {
	body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))
	fmt.Fprintf(stderr, "observer-hook: event=%s received bytes=%d at=%s\n",
		label, len(body), time.Now().UTC().Format(time.RFC3339))

	cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: configPath})

	// Guard seam (guard spec §3.2 seam 1, G4): evaluate BEFORE the
	// rewrite decision. A deny/ask emission replaces the reply
	// entirely (HandleGuarded wrote it); an allow/flag emission falls
	// through to the normal approve/rewrite path with the verdict
	// record deferred until after that reply (§6.4 reply-first).
	// Every guard failure path is fail-open: nil guard → unguarded
	// pre-tool, exactly the pre-G4 behavior.
	var recordAfterReply func()
	if cfgErr == nil && cfg.Guard.Enabled && cfg.Guard.Mode != "off" {
		if g := buildHookGuard(cfg, stderr); g != nil {
			var blocked bool
			blocked, recordAfterReply = hook.HandleGuarded(
				label, body, g, makeGuardPersist(cfg, g, label, stderr), stdout, stderr,
			)
			if blocked {
				// Still capture effort — the turn happened even though
				// the tool call was blocked/deferred.
				recordClaudecodeEffort(body, "PreToolUse", label, configPath, stderr)
				return
			}
		}
	}

	binary, binErr := absoluteBinaryPath()
	rewritten, newCmd, reason := decidePreToolRewrite(body, cfg, cfgErr, binary, binErr, runtime.GOOS)

	reply := preToolReply{Decision: "approve", Continue: true}
	if rewritten {
		reply.HookSpecificOutput = &preToolRewriteOut{
			HookEventName:      "PreToolUse",
			PermissionDecision: "allow",
			UpdatedInput:       map[string]any{"command": newCmd},
		}
		fmt.Fprintf(stderr, "observer-hook: %s rewrote bash command (%s)\n", label, reason)
	} else if reason != "" {
		fmt.Fprintf(stderr, "observer-hook: %s bash passthrough (%s)\n", label, reason)
	}
	_ = json.NewEncoder(stdout).Encode(reply)
	if recordAfterReply != nil {
		recordAfterReply()
	}

	// After replying — capture the per-turn effort.level so the
	// dashboard's per-action Effort column can render it for
	// claude-code rows. The JSONL transcript never carries effort
	// (verified against code.claude.com/docs/en/hooks: effort is only
	// emitted to tool-context hooks), so this is the only per-turn
	// capture surface.
	recordClaudecodeEffort(body, "PreToolUse", label, configPath, stderr)
}

// buildHookGuard constructs the guard composition layer for a hook
// invocation. Hook processes are short-lived: the guard (and its user
// policy parse) rebuilds per invocation — construction is table
// validation + one small file read, comfortably inside the §6.4
// latency budget. KnownProjectRoots is deliberately EMPTY here (it
// would need a DB read before the reply); R-151 cross-project bleed
// is therefore watcher-path-only, documented in BuildClaudeCodeEvent's
// boundary notes alongside the ProjectRoot limitation. Returns nil on
// any failure (fail-open at composition — never break the host tool).
func buildHookGuard(cfg config.Config, stderr io.Writer) *guard.Guard {
	home, err := os.UserHomeDir()
	if err != nil {
		home = ""
	}
	g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home, Notifier: notify.NewDesktop()})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: guard construction failed (running unguarded): %v\n", err)
		return nil
	}
	for _, issue := range g.LoadIssues() {
		fmt.Fprintf(stderr, "observer-hook: guard policy issue: %s\n", issue)
	}
	// §6.3 approvals on the hook path: the lookup opens the DB
	// LAZILY and only runs for verdicts that would block (ask/deny —
	// rare by construction), so the common approve path never pays a
	// DB open before its reply. Open failures report false:
	// fail-safe toward enforcement.
	g.SetApprovalLookup(func(ruleID, sessionID, rootHash string) bool {
		database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
		if err != nil {
			return false
		}
		defer database.Close()
		lctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
		defer cancel()
		return store.New(database).ApprovalActiveFor(lctx, ruleID, sessionID, rootHash, time.Now().UTC())
	})
	// Prompt-submit reconsider-once persistence (Part B item 1 — wires
	// guard.PromptReconsiderFuncs, whose zero value fails EVERY
	// ask-once/redact finding closed to block per promptguard.go's own
	// contract; unwired was never a valid production state, only a
	// phase-1-with-no-caller placeholder). Same lazy-per-call DB open
	// as SetApprovalLookup above — the hook process is short-lived and
	// this only runs when EvaluatePrompt actually reaches the
	// ask-once/redact branch (a finding exists), never on the common
	// clean-prompt path.
	g.SetPromptReconsiderStore(guard.PromptReconsiderFuncs{
		Lookup: func(fp string, now time.Time) (time.Time, bool, error) {
			database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return time.Time{}, false, err
			}
			defer database.Close()
			lctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
			defer cancel()
			row, ok, err := store.New(database).LookupPromptReconsider(lctx, fp, now)
			return row.WarnedAt, ok, err
		},
		Record: func(fp, sessionID, tool, detectors string, warnedAt, expiresAt time.Time) error {
			database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return err
			}
			defer database.Close()
			rctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
			defer cancel()
			return store.New(database).RecordPromptWarned(rctx, store.PromptReconsiderRow{
				Fingerprint: fp, SessionID: sessionID, Tool: tool, Detectors: detectors,
				WarnedAt: warnedAt, ExpiresAt: expiresAt,
			})
		},
		Confirm: func(fp string, now time.Time) (bool, error) {
			database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
			if err != nil {
				return false, err
			}
			defer database.Close()
			cctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
			defer cancel()
			return store.New(database).ConfirmPromptReconsider(cctx, fp, now)
		},
	})
	return g
}

// makeGuardPersist returns the lazy persist callback HandleGuarded
// invokes AFTER the reply is on stdout: open the daemon DB
// (no integrity probe — the daemon already probes at startup), write
// one guard_events row through the one-owner store helper, close,
// then fire the [guard.alerts] desktop notification if the verdict
// meets the threshold (also post-reply, so a slow notification
// helper can't delay the host tool). Best-effort end to end; the
// forensics JSONL already has the verdict if this fails.
func makeGuardPersist(cfg config.Config, g *guard.Guard, label string, stderr io.Writer) func(guard.ActionVerdict) {
	return func(v guard.ActionVerdict) {
		database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
		if err != nil {
			fmt.Fprintf(stderr, "observer-hook: %s guard persist db: %v\n", label, err)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
			if _, perr := store.New(database).PersistGuardVerdicts(ctx, []guard.ActionVerdict{v}); perr != nil {
				fmt.Fprintf(stderr, "observer-hook: %s guard persist: %v\n", label, perr)
			}
			cancel()
			database.Close()
		}
		g.MaybeAlert(v)
	}
}

// makePromptGuardPersist returns the lazy persist callback
// hook.HandlePromptSubmitGuarded invokes AFTER the reply is on stdout
// (Part B item 4/5: the guard_events writer + the MaybeAlert bridge
// for prompt-submit verdicts). Mirrors makeGuardPersist's shape
// exactly (lazy DB open, one store.PersistGuardVerdicts call, then
// MaybeAlert, all best-effort) but bridges through
// guard.ActionVerdictFromPrompt first — the ONE place a PromptVerdict
// becomes the general-purpose ActionVerdict the existing store seam
// already knows how to persist. No new table, no new writer.
func makePromptGuardPersist(cfg config.Config, g *guard.Guard, tool, label string, stderr io.Writer) func(pv guard.PromptVerdict, em guard.Emission, sessionID string) {
	return func(pv guard.PromptVerdict, em guard.Emission, sessionID string) {
		av := g.ActionVerdictFromPrompt(pv, em, guard.ActionInput{
			SessionID:  sessionID,
			Tool:       tool,
			ActionType: models.ActionUserPrompt,
			Timestamp:  time.Now().UTC(),
		})
		database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
		if err != nil {
			fmt.Fprintf(stderr, "observer-hook: %s prompt guard persist db: %v\n", label, err)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
			if _, perr := store.New(database).PersistGuardVerdicts(ctx, []guard.ActionVerdict{av}); perr != nil {
				fmt.Fprintf(stderr, "observer-hook: %s prompt guard persist: %v\n", label, perr)
			}
			cancel()
			database.Close()
		}
		g.MaybeAlert(av)
	}
}

// promptGuardEnabled reports whether the prompt-submit hook lane
// should evaluate at all: the general [guard] gate (enabled + not
// off, same gate every other guarded hook channel already checks) AND
// the feature's own [guard.prompt] enabled + hook_lane knobs (CLAUDE.md
// Default-On section: the prompt-submit hook is registered like every
// other observer hook, but only EVALUATES when both gates are set).
func promptGuardEnabled(cfg config.Config) bool {
	return cfg.Guard.Enabled && cfg.Guard.Mode != "off" && cfg.Guard.Prompt.Enabled && cfg.Guard.Prompt.HookLane
}

// handlePromptSubmitOnlyHook is the shared receiver for tools whose
// ONLY guarded hook event is prompt-submit (BLOCK-1, phase-2 review):
// Factory Droid, Qwen Code, and Gemini CLI all have a registry
// PromptLane=PromptLaneHook row and a CanBlock:true conformance row
// (internal/guard/conformance.go) plus a verified wire dialect
// (internal/hook/promptsubmit.go), but before this fix `observer hook
// <tool> <event>` for these three tools had NO case in newHookCmd's
// switch at all — every invocation fell to the unconditional
// approve-only default, which can structurally never block. That made
// the registry/conformance/docs claim of "this harness blocks" false
// for any install that actually registered the hook.
//
// These tools have no other hook-driven capture (their conversation
// capture is watcher/transcript-based — see internal/adapter/droid,
// qwencode, gemini) — so every event OTHER than the one prompt-submit
// event name is byte-identical to the old default-case behavior
// (hook.HandleApprove, which also appends the forensics log row these
// tools always got via the default case).
func handlePromptSubmitOnlyHook(tool, label, dialect, promptEvent, event, configPath string) {
	fullLabel := label
	if event != "" {
		fullLabel = label + ":" + event
	}
	body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	if event != promptEvent {
		hook.HandleApprove(fullLabel, bytes.NewReader(body), os.Stdout, os.Stderr)
		return
	}

	cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: configPath})
	handled := false
	var recordAfterReply func()
	exitCode := 0
	if cfgErr == nil && promptGuardEnabled(cfg) {
		if g := buildHookGuard(cfg, os.Stderr); g != nil {
			handled, recordAfterReply, exitCode = hook.HandlePromptSubmitGuarded(
				tool, dialect, promptEvent, body, truncated, g,
				makePromptGuardPersist(cfg, g, tool, fullLabel, os.Stderr), os.Stdout, os.Stderr,
			)
		}
	}
	if !handled {
		// Guard off/disabled/misconstructed: fall back to the SAME
		// approve-only reply (with forensics) this event always got
		// before a receiver existed for this tool at all.
		hook.HandleApprove(fullLabel, bytes.NewReader(body), os.Stdout, os.Stderr)
	}
	if recordAfterReply != nil {
		recordAfterReply()
	}
	// Part B item 2 (Qoder/Poolside/Cascade): some dialects signal a
	// block via the PROCESS exit code rather than (or in addition to)
	// a JSON stdout reply — see promptDialect.blockExitCode. Exit only
	// AFTER recordAfterReply has run, and only when the guard actually
	// produced a handled, blocking verdict (exitCode is always 0 on
	// the unguarded/fallback path above).
	if handled && exitCode != 0 {
		hookOSExit(exitCode)
	}
}

// hookOSExit is the process-exit seam for the exit-code-signalled
// prompt-submit blocks (Qoder / Poolside / Cascade — and, since the
// 2026-09-07 live correction, Claude Code). Production is os.Exit;
// in-process tests substitute a recorder so a block does not end the
// test binary.
var hookOSExit = os.Exit

// handleClaudeCodeUserPromptSubmit is the guarded counterpart of the
// plain "user-prompt-submit" capture-only path (Part B item 1/2):
// evaluate the prompt via hook.HandlePromptSubmitGuarded BEFORE
// replying when the prompt-submit hook lane is enabled, then run the
// EXISTING capture (buildClaudeUserPromptSubmitEvent → Ingest)
// regardless of the verdict — a denied attempt is still an attempt
// worth recording, the same posture HandleCursorEventGuarded already
// established. When the guard isn't enabled/wired (handled=false),
// this falls through to writing the plain approve reply itself,
// so the observable behavior for a guard-off install is byte-identical
// to before this seam existed.
// NIT (phase-2 review): this handler loads config and builds the whole
// guard engine (buildHookGuard) BEFORE writing anything to stdout —
// unlike every other guard-evaluated receiver in this file (codex,
// cursor), which reply first and do heavier work after. That's not an
// oversight to fix; it's structural. Every OTHER guarded channel's
// reply is a fixed "approve" the capture/ingest work never changes —
// there's something to send immediately regardless of what happens
// next. A prompt-submit reply's CONTENT *is* the verdict: whether to
// allow, ask, or deny the prompt cannot be known until the guard has
// actually evaluated it, so there is no earlier point at which a
// correct reply could be sent. Replying "allow" first and blocking
// after would be a real vulnerability (the host has already let the
// prompt through by the time a late "actually, deny" arrived) — the
// ordering here is required by the security property, not an
// oversight.
func handleClaudeCodeUserPromptSubmit(ctx context.Context, label, configPath string) {
	body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	cfg, cfgErr := config.Load(config.LoadOptions{GlobalPath: configPath})

	handled := false
	var recordAfterReply func()
	exitCode := 0
	if cfgErr == nil && promptGuardEnabled(cfg) {
		if g := buildHookGuard(cfg, os.Stderr); g != nil {
			// LIVE CORRECTION (2026-09-07 operator step-in): Claude
			// Code blocks THIS event only via process exit code 2
			// (its stderr is the user-visible reason); the JSON
			// `permissionDecision:"deny"` this handler used to rely
			// on is PreToolUse-only and was silently ignored — three
			// live secret submissions were logged as blocked by the
			// receiver and still reached the model. The exit happens
			// at the END of this handler, after the capture below has
			// run and closed its DB handle.
			handled, recordAfterReply, exitCode = hook.HandlePromptSubmitGuarded(
				models.ToolClaudeCode, hook.PromptDialectClaudeCode, "UserPromptSubmit",
				body, truncated, g, makePromptGuardPersist(cfg, g, models.ToolClaudeCode, label, os.Stderr), os.Stdout, os.Stderr,
			)
		}
	}
	if !handled {
		// FIX cluster, item 7a: this used to emit the legacy bare
		// {"decision":"approve"} shape — the wrong contract for
		// UserPromptSubmit specifically (Claude Code's modern reply
		// for this event is the hookSpecificOutput envelope
		// HandlePromptSubmitGuarded already builds on a real ALLOW;
		// see hook.ClaudeCodePromptApproveReply's doc comment). Scoped
		// to this ONE prompt-submit fallback only — every other
		// hook.Decision{Decision: "approve"} fallback in this file is
		// a different event with its own established contract and is
		// deliberately left untouched.
		_ = json.NewEncoder(os.Stdout).Encode(hook.ClaudeCodePromptApproveReply())
	}
	if recordAfterReply != nil {
		recordAfterReply()
	}

	// Capture proceeds regardless of the guard verdict (mirrors
	// handleClaudeCodeActionEvent's own shape, minus the reply this
	// function already sent above). Wrapped in a closure so its
	// deferred DB close runs BEFORE the exit-code block below —
	// os.Exit would otherwise skip the defers.
	func() {
		ev, ok := buildClaudeUserPromptSubmitEvent(body)
		if !ok || ev.SessionID == "" {
			return
		}
		if cfgErr != nil {
			return
		}
		database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
		if err != nil {
			fmt.Fprintf(os.Stderr, "observer-hook: %s db: %v\n", label, err)
			return
		}
		defer database.Close()
		insertCtx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
		defer cancel()
		if _, err := store.New(database).Ingest(insertCtx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
			fmt.Fprintf(os.Stderr, "observer-hook: %s insert: %v\n", label, err)
		}
	}()
	// A blocking verdict on Claude Code's dialect is signalled by the
	// process exit code (blockExitCode:2) — only after the capture
	// above, and only when the guard actually handled + blocked.
	if handled && exitCode != 0 {
		hookOSExit(exitCode)
	}
}

// handleClaudeCodePostTool captures effort and local login evidence from a
// PostToolUse payload into their node-local sidecar tables. Replies
// approve fast and never blocks the host (spec P1).
//
// Unlike PreToolUse this handler has no rewrite responsibility; its
// job is context capture. PostToolUse fires after the tool
// finishes; on rare hook-before-JSONL orderings this gives us a second
// chance to capture effort even if the PreToolUse fire was lost.
func handleClaudeCodePostTool(stdin io.Reader, stdout, stderr io.Writer, label, configPath string) {
	body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	_ = json.NewEncoder(stdout).Encode(hook.Decision{Decision: "approve"})

	recordClaudecodeEffort(body, "PostToolUse", label, configPath, stderr)
}

// recordClaudecodeEffort parses (session_id, tool_use_id, effort.level)
// from a tool-context Claude Code hook payload and upserts it into the
// claudecode_effort sidecar. Two no-op cases:
//
//   - effort.level is empty and no exact local login evidence is available.
//     Account capture is independent of model support for effort.
//   - tool_use_id is empty (malformed payload, or a future event class
//     that lost the field). Nothing to key on.
//
// Errors log to stderr; never propagate.
func recordClaudecodeEffort(body []byte, eventName, label, configPath string, stderr io.Writer) {
	var p claudecodeEffortPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return
	}
	accounts := hook.LocalAccountObservations(context.Background(), models.ToolClaudeCode, eventName, body)
	if (p.Effort.Level == "" && len(accounts) == 0) || p.SessionID == "" || p.ToolUseID == "" {
		return
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s effort config: %v\n", label, err)
		return
	}
	// db.Open runs a quick_check integrity probe that competes with the
	// running daemon's WAL holder. Don't fence it with HookTimeout; that
	// budget is for the write side. Mirrors handleCursorHook /
	// handleCodexHook which both pass an unbounded context to db.Open.
	//
	// Cross-OS note: when Claude Code runs in a different OS-context than
	// the daemon (the Windows CC + WSL daemon straddle), the hook is
	// registered as a wsl.exe bridge (see registerClaudeCodeWindows) so it
	// executes INSIDE the daemon's context — this db.Open therefore resolves
	// the daemon's own DB natively. No cross-OS SQLite open is attempted.
	database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s effort db: %v\n", label, err)
		return
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
	defer cancel()
	if err := store.New(database).RecordToolAccounts(ctx, accounts); err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s account capture: %v\n", label, err)
	}
	if p.Effort.Level == "" {
		return
	}
	if err := store.New(database).UpsertClaudecodeEffort(ctx, p.SessionID, p.ToolUseID, p.Effort.Level, eventName); err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s effort upsert: %v\n", label, err)
	}
}

// decidePreToolRewrite is the pure decision function used by
// handleClaudeCodePreTool. Reason "" signals "not a Bash call, nothing to
// consider"; any other reason is a short tag for diagnostic logging.
func decidePreToolRewrite(body []byte, cfg config.Config, cfgErr error, binary string, binErr error, hostOS string) (rewrite bool, newCommand, reason string) {
	var p preToolPayload
	if err := json.Unmarshal(body, &p); err != nil {
		return false, "", ""
	}
	if p.ToolName != "Bash" || p.ToolInput.Command == "" {
		return false, "", ""
	}
	if cfgErr != nil {
		return false, "", "config-error"
	}
	if !cfg.Compression.Shell.Enabled {
		return false, "", "shell-disabled"
	}
	// Cross-OS shell guard (the Windows-CC + WSL-daemon straddle). When
	// Claude Code runs on Windows but the daemon runs in WSL, the hook is
	// registered as a wsl.exe bridge (registerClaudeCodeWindows), so it
	// executes on Linux while the rewritten command runs back in the
	// Windows shell (Git Bash / MSYS). RewriteBash embeds THIS process's
	// own observer path — a `/mnt/...` WSL path that shell can't exec — so
	// the rewritten command would exit 127. The payload cwd reveals the
	// host shell's OS: a Windows-style cwd (drive-letter / backslash) seen
	// by a non-Windows hook binary means the shell is on the other side of
	// the OS boundary. Skip the rewrite — shell-output capture is simply
	// unavailable for that topology. Effort/action capture is unaffected
	// (those hooks don't rewrite the command).
	if hostOS != "windows" && looksWindowsPath(p.Cwd) {
		return false, "", "cross-os-shell"
	}
	if binErr != nil || binary == "" {
		return false, "", "binary-lookup-error"
	}
	newCmd, changed := hook.RewriteBash(binary, p.ToolInput.Command, cfg.Compression.Shell.ExcludeCommands)
	if !changed {
		return false, "", "not-rewritable"
	}
	return true, newCmd, "ok"
}

// looksWindowsPath reports whether p is a Windows-style absolute path — a
// drive-letter prefix (`C:\` or `C:/`) or any backslash separator. Used to
// infer that the host shell which produced the hook payload runs on
// Windows, so a non-Windows (bridged) hook process must not rewrite the
// command with its own filesystem-local observer path.
func looksWindowsPath(p string) bool {
	if len(p) >= 2 && p[1] == ':' &&
		((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) {
		return true
	}
	return strings.Contains(p, `\`)
}

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
		hook.HandleCursorEvent(event, nil, scrub.New(), os.Stdin, os.Stdout, os.Stderr, 0)
		return
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		// Fall back to approve-only — never block the host.
		fmt.Fprintf(os.Stderr, "observer-hook: cursor config: %v\n", err)
		hook.HandleApprove("cursor:"+event, os.Stdin, os.Stdout, os.Stderr)
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: cursor db: %v\n", err)
		hook.HandleApprove("cursor:"+event, os.Stdin, os.Stdout, os.Stderr)
		return
	}
	defer database.Close()

	sc := scrub.New()
	// v1.6.23 audit F3/F4: wire the FTS5 indexer so postToolUse
	// tool_output bodies and beforeReadFile file content land in
	// action_excerpts the same way the daemon's watcher-attached
	// indexer would. Use the configured cap (or DefaultMaxExcerptBytes
	// when zero) — matches main.go's daemon Indexer setup.
	idx := indexing.New(database, cfg.Compression.Indexing.MaxExcerptBytes)

	// Guard seam (G6): cursor's before-events carry documented
	// permission JSON, so the guarded receiver can deny/ask. Nil
	// guard (disabled, mode off, construction failure) degrades to
	// the unguarded receiver — exactly the pre-G6 behavior. The
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
	// this file — see readHookBodyDetectTruncation's doc comment.
	body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	var g *guard.Guard
	if cfg.Guard.Enabled && cfg.Guard.Mode != "off" {
		g = buildHookGuard(cfg, os.Stderr)
	}
	if g != nil {
		st := store.New(database).WithIndexer(idx)
		persist := func(v guard.ActionVerdict) {
			pctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
			defer cancel()
			if _, err := st.PersistGuardVerdicts(pctx, []guard.ActionVerdict{v}); err != nil {
				fmt.Fprintf(os.Stderr, "observer-hook: cursor guard persist: %v\n", err)
			}
			g.MaybeAlert(v)
		}
		// gd starts as a TRUE nil interface (never assigned from a nil
		// *guard.Guard, which would be the classic typed-nil trap —
		// hook.CursorEvaluator's own nil check inside
		// handleCursorPromptSubmit relies on this). beforeSubmitPrompt
		// additionally gates on the [guard.prompt] hook_lane knob
		// (promptGuardEnabled) — a knob the OTHER cursor channels
		// (shell/MCP/file) don't consult at all, so it must not affect
		// their gd.
		var gd hook.CursorEvaluator
		if event != cursoradapter.EventBeforeSubmitPrompt || promptGuardEnabled(cfg) {
			gd = g
		}
		hook.HandleCursorEventGuarded(event, gd, persist, st, sc, bytes.NewReader(body), truncated, os.Stdout, os.Stderr, cfg.Observer.Hooks.HookTimeout())
	} else {
		hook.HandleCursorEvent(event, store.New(database).WithIndexer(idx), sc, bytes.NewReader(body), os.Stdout, os.Stderr, cfg.Observer.Hooks.HookTimeout())
	}

	// A cursor sessionStart hook runs as a descendant of the cursor
	// process, so the claude-code ancestor-walk resolves cursor's pid
	// verbatim (no pid rides in the payload). Best-effort + fail-open —
	// the reply already went out above.
	seedCursorSessionPidbridge(ctx, event, body, os.Getppid(), defaultAncestors,
		makePidbridgeWriter(configPath), sc, os.Stderr)
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
	// Cheap background-agent skip without teaching the cursor adapter a
	// new field: a cloud/background agent has no local process to seed
	// (and upsert-idempotent writes make an accidental over-seed
	// harmless anyway).
	var flags struct {
		Event             string `json:"hook_event_name"`
		IsBackgroundAgent bool   `json:"is_background_agent"`
	}
	_ = json.Unmarshal(body, &flags)
	name := event
	if name == "" {
		name = flags.Event
	}
	if name != cursoradapter.EventSessionStart || flags.IsBackgroundAgent {
		return
	}
	ev, ok, err := cursoradapter.BuildEvent(cursoradapter.EventSessionStart, body, sc)
	if err != nil || !ok {
		return
	}
	registerSessionAncestors(ctx, parentPID, ancestors, ev.SessionID, ev.ProjectRoot,
		models.ToolCursor, writer, stderr, "cursor:session-start")
}

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
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: codex config: %v\n", err)
		// Bare ack via empty JSON object — codex hooks accept this as
		// "no action" across all event classes.
		_ = json.NewEncoder(os.Stdout).Encode(struct{}{})
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: codex db: %v\n", err)
		_ = json.NewEncoder(os.Stdout).Encode(struct{}{})
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

	sc := scrub.New()
	// Part B: UserPromptSubmit is special-cased to the guarded
	// prompt-submit seam BEFORE HandleCodexEvent's unconditional `{}`
	// reply — Codex's own receiver imports no guard at all and always
	// acks empty (contract §1.2's headline gap: "zero guard wiring on
	// any Codex event"). handled=false (guard off/disabled/misconfigured,
	// or the dispatch decided not to intervene) falls through to the
	// EXISTING unguarded HandleCodexEvent call, byte-identical to
	// before this seam existed.
	handled := false
	if event == codexadapter.HookEventUserPromptSubmit && promptGuardEnabled(cfg) {
		if g := buildHookGuard(cfg, os.Stderr); g != nil {
			var after func()
			// PromptDialectTopLevelBlock signals a block in its JSON
			// reply ({"decision":"block",…}), which Codex honours per
			// its hook docs; the row's blockExitCode:2 is deliberately
			// NOT applied by this receiver (it keeps ingesting after
			// the reply and exits 0). The live Codex step-in that
			// would confirm the JSON form is still pending (Batch-4).
			handled, after, _ = hook.HandlePromptSubmitGuarded(
				models.ToolCodex, hook.PromptDialectTopLevelBlock, event, body, truncated, g,
				makePromptGuardPersist(cfg, g, models.ToolCodex, "codex:"+event, os.Stderr), os.Stdout, os.Stderr,
			)
			if after != nil {
				after()
			}
		}
	}
	if handled {
		// Reply already sent by the guard path above — still capture
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
		hook.HandleCodexEvent(event, store.New(database), sc, bytes.NewReader(body),
			os.Stdout, os.Stderr, cfg.Observer.Hooks.HookTimeout())
	}

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
	// verbatim — reuse the shared writer. Best-effort + fail-open: the
	// reply already went out above.
	seedCodexSessionPidbridge(ctx, event, body, os.Getppid(), defaultAncestors,
		makePidbridgeWriter(configPath), os.Stderr)
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

// handleHermesHook dispatches a Hermes Agent hook event delivered by
// the Python plugin bridge at ~/.hermes/plugins/superbased-observer/.
//
// Wire shape per docs/hermes-adapter-plan.md §11.1 + §17.1.F:
// structured JSON on stdin carrying event=tool_call|session_start|
// session_end|api_request|subagent_stop plus tool-specific fields
// (tool_name, args, result, cwd, model, usage, …). Per
// hermes_cli/plugins.py the bridge's subprocess.run wrapper has a
// 0.5 s timeout and swallows exceptions — observer being down or
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

	body, _ := io.ReadAll(io.LimitReader(os.Stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	// Reply approve immediately — host must never wait on the DB
	// path. Bridge accepts "approve" identically to the Claude Code
	// shape; on parse failure it falls back to no-op.
	_ = json.NewEncoder(os.Stdout).Encode(hook.Decision{Decision: "approve"})

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
	seedHermesSessionPidbridge(ctx, event, body, os.Getppid(), defaultAncestors,
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
// register that single pid — it is the process that opens provider API
// sockets. The os.getppid() the plugin also sends is the agent's PARENT
// (usually the user's shell) and is deliberately NOT seeded: registering
// a shell would poison the bridge for later unrelated connections (D17).
//
// Compat both ways: an OLDER plugin sends no pid — we fall back to the
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

// claudeActionBuilder takes a raw Claude Code hook payload and returns a
// ToolEvent ready for insertion. ok=false means "skip this fire" (e.g.
// missing required field). Builders never block — they parse, validate,
// and return.
type claudeActionBuilder func(body []byte) (models.ToolEvent, bool)

// handleClaudeCodeActionEvent is the shared dispatch for Tier 1 hook
// events that ingest one row each. Reads stdin, replies approve, opens
// the configured DB, calls build(body), and inserts the resulting
// ToolEvent. All errors log to stderr and never block the host (spec P1).
func handleClaudeCodeActionEvent(ctx context.Context, label, configPath string, build claudeActionBuilder) {
	body, _ := io.ReadAll(io.LimitReader(os.Stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	_ = json.NewEncoder(os.Stdout).Encode(hook.Decision{Decision: "approve"})

	ev, ok := build(body)
	if !ok {
		return
	}
	if ev.SessionID == "" {
		fmt.Fprintf(os.Stderr, "observer-hook: %s no session_id in payload\n", label)
		return
	}

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

	insertCtx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
	defer cancel()
	hookStore := store.New(database)
	// [tasks].enabled gate: this generic handler also serves the
	// PostToolBatch hook builder — the capture path for the
	// post_tool_batch envelope rows carrying claude-code Task payloads
	// (docs/task-tracking.md; without this, that slice would only ever
	// get decoded by a later `observer backfill --tasks` pass).
	hookStore.SetTasksEnabled(cfg.Tasks.Enabled)
	hookStore.SetTasksOptions(cfg.Tasks.MatchMode, cfg.Tasks.ConcurrentAttribution, cfg.Tasks.IncludeSidechains)
	if _, err := hookStore.Ingest(insertCtx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
		fmt.Fprintf(os.Stderr, "observer-hook: %s insert: %v\n", label, err)
	}
}

// claudeBaseEnvelope captures the universal envelope every Claude Code
// hook payload carries (per docs https://code.claude.com/docs/en/hooks).
// Builders embed this and add event-specific fields. The PermissionMode
// + Effort fields land on every fire (verified via v1.4.45 capture); we
// surface them through ActionMetadata so dashboards can filter by mode.
type claudeBaseEnvelope struct {
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	PermissionMode string `json:"permission_mode"`
	Effort         struct {
		Level string `json:"level"`
	} `json:"effort"`
}

// envelopeMetadata builds an ActionMetadata from the envelope's
// universal fields. Returns nil when no fields apply so callers can
// pass it directly to ev.Metadata without an extra IsZero check.
func envelopeMetadata(env claudeBaseEnvelope) *models.ActionMetadata {
	m := models.ActionMetadata{
		PermissionMode: env.PermissionMode,
		EffortLevel:    env.Effort.Level,
	}
	if m.IsZero() {
		return nil
	}
	return &m
}

// baseToolEvent fills the fields common to every claude-code hook row.
// Sets SourceFile = "claude-code:hook" and routes ProjectRoot from cwd.
// Populates Metadata from the envelope's permission_mode + effort.level
// so per-event builders inherit those fields automatically.
func baseToolEvent(env claudeBaseEnvelope, action, eventName string) models.ToolEvent {
	return models.ToolEvent{
		SourceFile:    "claude-code:hook",
		SourceEventID: env.SessionID + ":" + eventName,
		SessionID:     env.SessionID,
		ProjectRoot:   env.Cwd,
		Timestamp:     time.Now().UTC(),
		Tool:          models.ToolClaudeCode,
		ActionType:    action,
		Success:       true,
		Metadata:      envelopeMetadata(env),
	}
}

func buildClaudeSessionEndEvent(body []byte) (models.ToolEvent, bool) {
	var p struct{ claudeBaseEnvelope }
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionSessionEnd, "session_end")
	ev.Target = "session_ended"
	return ev, true
}

func buildClaudeUserPromptSubmitEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		Prompt string `json:"prompt"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionUserPrompt, "user_prompt_submit")
	// Per-prompt discriminator. baseToolEvent's default id is
	// "<session>:user_prompt_submit" — CONSTANT for the whole session — so
	// with actions' UNIQUE(source_file, source_event_id) every prompt after
	// the FIRST collided and was swallowed by the upsert. Measured on the
	// live DB before this fix: all 515 hook-captured claude-code sessions
	// had exactly 1 user_prompt row, while watcher-captured sessions reached
	// 406. The loss also starved the predictor's turns-per-message ladder,
	// which counts user_prompt boundaries (LoadSessionShape) and so could
	// never leave the 1-message "young session" case.
	//
	// Content hash, NOT a timestamp/nonce: TestClaudeCodeHookDoubleFireIsIdempotent
	// requires the id stay deterministic so double-wired hooks (plugin +
	// settings.json) still collapse to one row. Same convention as :stop:,
	// :post_tool_batch: and :user_prompt_expansion:. Residual, shared with
	// those: the exact same prompt text repeated inside one session collapses
	// to a single row.
	ev.SourceEventID = p.SessionID + ":user_prompt_submit:" + claudeContentHash(body)
	text := scrub.New().String(p.Prompt)
	ev.RawToolInput = text
	ev.Target = previewLine(text, 120)
	return ev, true
}

func buildClaudePostToolFailureEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		ToolName    string          `json:"tool_name"`
		ToolInput   json.RawMessage `json:"tool_input"`
		ToolUseID   string          `json:"tool_use_id"`
		Error       string          `json:"error"`
		IsInterrupt bool            `json:"is_interrupt"`
		DurationMs  int64           `json:"duration_ms"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionToolFailure, "post_tool_failure")
	ev.SourceEventID = p.ToolUseID + ":post_tool_failure"
	ev.Target = p.ToolName
	ev.RawToolName = p.ToolName
	if len(p.ToolInput) > 0 {
		ev.RawToolInput = scrub.New().String(string(p.ToolInput))
	}
	ev.ErrorMessage = p.Error
	ev.DurationMs = p.DurationMs
	ev.Success = false
	if p.IsInterrupt {
		// User-cancelled vs genuine failure surfaces on
		// metadata.is_interrupt (migration 017). Pre-fix this was
		// lossy-encoded as a "[interrupt] " ErrorMessage prefix that
		// dashboards had to string-match on.
		if ev.Metadata == nil {
			ev.Metadata = &models.ActionMetadata{}
		}
		ev.Metadata.IsInterrupt = true
	}
	return ev, true
}

func buildClaudeStopFailureEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		ErrorType            string `json:"error_type"`
		ErrorMessage         string `json:"error_message"`
		Error                string `json:"error"`
		LastAssistantMessage string `json:"last_assistant_message"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	// StopFailure carries the typed error class via either error_type
	// (per docs) or error (observed in real captures); prefer the more
	// specific one.
	cls := p.ErrorType
	if cls == "" {
		cls = p.Error
	}
	msg := p.ErrorMessage
	if msg == "" {
		msg = p.LastAssistantMessage
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionAPIError, "stop_failure")
	// Per-occurrence discriminator — same collapse bug as
	// user_prompt_submit. A session that hits several API errors kept only
	// the first, understating the error rate. Deterministic hash, per the
	// double-fire contract.
	ev.SourceEventID = p.SessionID + ":stop_failure:" + claudeContentHash(body)
	ev.Target = cls
	ev.RawToolName = cls
	ev.ErrorMessage = msg
	ev.Success = false
	return ev, true
}

func buildClaudeSubagentStartEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		AgentID   string `json:"agent_id"`
		AgentType string `json:"agent_type"`
		Prompt    string `json:"prompt"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionSubagentStart, "subagent_start")
	if p.AgentID != "" {
		ev.SourceEventID = p.AgentID + ":subagent_start"
		// Structured sub-agent identity (alongside the legacy RawToolName
		// carry): feeds /api/session/<id>/subagents grouping without
		// raw-field scraping.
		ev.Metadata = &models.ActionMetadata{AgentID: p.AgentID}
	}
	ev.Target = p.AgentType
	ev.RawToolName = p.AgentID
	if p.Prompt != "" {
		ev.RawToolInput = scrub.New().String(p.Prompt)
	}
	ev.IsSidechain = true
	return ev, true
}

func buildClaudeSubagentStopEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		AgentID              string `json:"agent_id"`
		AgentType            string `json:"agent_type"`
		AgentTranscriptPath  string `json:"agent_transcript_path"`
		LastAssistantMessage string `json:"last_assistant_message"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	// Empty-shell suppression: claude-code fires SubagentStop with
	// only agent_id + envelope sometimes (lifecycle marker without
	// payload detail). Verified live: 11 of 12 historical rows on
	// the user's DB had empty target / raw_tool_input — they
	// rendered as blank rows in the dashboard. Suppress when there's
	// nothing the dashboard can show; the loss is just the
	// lifecycle marker, which the JSONL watcher's sidechain capture
	// already covers.
	if p.AgentType == "" && p.LastAssistantMessage == "" && p.AgentTranscriptPath == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionSubagentStop, "subagent_stop")
	if p.AgentID != "" {
		ev.SourceEventID = p.AgentID + ":subagent_stop"
	}
	// Target shows in dashboard listings. Prefer the categorical
	// agent_type ("Explore", "general-purpose", …); fall back to a
	// short preview of the assistant's final message so the row
	// always carries SOMETHING the user can see at a glance.
	switch {
	case p.AgentType != "":
		ev.Target = p.AgentType
	case p.LastAssistantMessage != "":
		ev.Target = previewLine(p.LastAssistantMessage, 120)
	default:
		// Has agent_transcript_path only — surface the basename so
		// the row points at where the data lives.
		ev.Target = filepath.Base(p.AgentTranscriptPath)
	}
	ev.RawToolName = p.AgentID
	if p.AgentID != "" {
		// Structured sub-agent identity (alongside the legacy RawToolName
		// carry): feeds /api/session/<id>/subagents grouping without
		// raw-field scraping.
		ev.Metadata = &models.ActionMetadata{AgentID: p.AgentID}
	}
	if p.LastAssistantMessage != "" {
		// Land the assistant's final message in BOTH
		// raw_tool_input (the dashboard-rendered body) AND
		// ToolOutput (the FTS5 index). Pre-fix the message only
		// went to FTS5, so the dashboard space rendered blank.
		scrubbed := scrub.New().String(p.LastAssistantMessage)
		ev.RawToolInput = scrubbed
		ev.ToolOutput = scrubbed
	}
	ev.IsSidechain = true
	return ev, true
}

// buildClaudeStopEvent handles Claude Code's `Stop` hook, which fires when
// a top-level turn ends (mirroring SubagentStop's role for subagent turns).
// Pre-v1.4.49 the dispatch fell through to the generic approve-reply path,
// so the assistant's final-message text was never landed in a row. This
// builder emits a `claudecode.assistant_text` row carrying the assistant's
// closing utterance, keeping it consistent with the cross-adapter
// convention (Codex/Cline/Roo/Antigravity all emit assistant-text rows
// with ActionTaskComplete + `<source>.assistant_text` RawToolName).
//
// Empty-message suppression: Stop fires on every turn-end, including
// interruptions where there's no model output to record. Returning (zero,
// false) for empty LastAssistantMessage keeps the table free of marker-
// only rows. The lifecycle marker is still observable via the JSONL
// adapter's per-turn task_complete row.
//
// SourceEventID embeds a content hash of the envelope body so replayed
// captures dedupe via the (source_file, source_event_id) UPSERT path —
// observer's hooks share SourceFile="claude-code:hook" across events, so
// the session-id + event + content-hash combo is the dedup key.
//
// No token/cost fields are set even if the envelope grows usage data in
// future Claude Code versions — pricing is attributed via the API proxy
// path, not via the JSONL/hook assistant-text rows.
func buildClaudeStopEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		StopHookActive       bool   `json:"stop_hook_active"`
		LastAssistantMessage string `json:"last_assistant_message"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	if strings.TrimSpace(p.LastAssistantMessage) == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionTaskComplete, "stop")
	ev.SourceEventID = p.SessionID + ":stop:" + claudeContentHash(body)
	preview := previewLine(p.LastAssistantMessage, 200)
	ev.Target = preview
	ev.PrecedingReasoning = preview
	ev.RawToolName = "claudecode.assistant_text"
	scrubbed := scrub.New().String(p.LastAssistantMessage)
	ev.ToolOutput = contentcap.Cap(scrubbed, contentcap.DefaultMaxBytes)
	return ev, true
}

func buildClaudeNotificationEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		NotificationType string `json:"notification_type"`
		Message          string `json:"message"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionNotification, "notification")
	// Per-occurrence discriminator — same collapse bug as
	// user_prompt_submit (a session emits many notifications; the constant
	// id kept only the first). Deterministic hash, per the double-fire
	// contract.
	ev.SourceEventID = p.SessionID + ":notification:" + claudeContentHash(body)
	ev.Target = p.NotificationType
	ev.ErrorMessage = p.Message
	return ev, true
}

func buildClaudeCwdChangedEvent(body []byte) (models.ToolEvent, bool) {
	// Captured payload uses old_cwd / new_cwd (not previous_cwd as the
	// docs claim). Accept both for forward-compat with future Claude
	// Code releases.
	var p struct {
		claudeBaseEnvelope
		OldCwd      string `json:"old_cwd"`
		NewCwd      string `json:"new_cwd"`
		PreviousCwd string `json:"previous_cwd"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	previous := p.OldCwd
	if previous == "" {
		previous = p.PreviousCwd
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionCwdChange, "cwd_changed")
	// Per-occurrence discriminator — same collapse bug as
	// user_prompt_submit. A session can cd many times; the constant id
	// recorded only the first move, so the cwd trail was truncated to one
	// hop. Deterministic hash, per the double-fire contract (an A→B→A
	// round trip re-collapses, matching the convention's accepted residual).
	ev.SourceEventID = p.SessionID + ":cwd_changed:" + claudeContentHash(body)
	ev.Target = p.NewCwd
	if ev.Target == "" {
		ev.Target = p.Cwd
	}
	ev.PrecedingReasoning = previous
	return ev, true
}

// claudeContentHash returns a short stable hex hash of body suitable
// for disambiguating SourceEventIDs when multiple Tier 2/3 hook fires
// per session share an event name (UserPromptExpansion, PostToolBatch,
// PermissionRequest). 8 hex chars from fnv-32a; collision probability
// over a single session is negligible. Deterministic across re-ingest
// so replayed captures dedupe via ON CONFLICT instead of duplicating.
func claudeContentHash(body []byte) string {
	h := fnv.New32a()
	_, _ = h.Write(body)
	return strconv.FormatUint(uint64(h.Sum32()), 16)
}

// buildClaudeSetupEvent handles Claude Code's `Setup` event — fires only
// on `--init-only`, `-p --init`, or `-p --maintenance` runs (not every
// session launch). Payload shape verified against
// docs.claude.com/docs/en/hooks: top-level `trigger` field carries
// "init" | "maintenance".
func buildClaudeSetupEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		Trigger string `json:"trigger"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionSetup, "setup")
	ev.Target = p.Trigger
	if p.Trigger != "" {
		// Trigger discriminates `init` vs `maintenance` if both fire
		// in the same session (rare — they're mutually-exclusive
		// launch modes — but defensive).
		ev.SourceEventID = p.SessionID + ":setup:" + p.Trigger
	}
	return ev, true
}

// buildClaudeUserPromptExpansionEvent handles `UserPromptExpansion` —
// fires AFTER UserPromptSubmit when the input matched a registered
// slash-command or mcp-prompt name. Distinct from UserPromptSubmit's
// free-text capture: this row records the resolved command_name +
// expansion_type, so dashboards can chart slash-command usage. Fields
// verified per docs.
func buildClaudeUserPromptExpansionEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		ExpansionType string `json:"expansion_type"`
		CommandName   string `json:"command_name"`
		CommandArgs   string `json:"command_args"`
		CommandSource string `json:"command_source"`
		Prompt        string `json:"prompt"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionUserPromptExpansion, "user_prompt_expansion")
	ev.SourceEventID = p.SessionID + ":user_prompt_expansion:" + claudeContentHash(body)
	ev.Target = p.CommandName
	ev.RawToolName = p.ExpansionType
	if p.Prompt != "" {
		ev.RawToolInput = scrub.New().String(p.Prompt)
	}
	// command_source + command_args land on PrecedingReasoning as a
	// small JSON blob so analysts can filter on plugin vs user vs
	// project skill provenance without re-scanning the raw prompt.
	if p.CommandSource != "" || p.CommandArgs != "" {
		meta := map[string]string{}
		if p.CommandSource != "" {
			meta["command_source"] = p.CommandSource
		}
		if p.CommandArgs != "" {
			meta["command_args"] = scrub.New().String(p.CommandArgs)
		}
		if b, err := json.Marshal(meta); err == nil {
			ev.PrecedingReasoning = string(b)
		}
	}
	return ev, true
}

// buildClaudePostToolBatchEvent handles `PostToolBatch` — the end-of-
// batch summary after a run of consecutive tool calls. Carries the
// list of tool_calls (their names + serialized tool_responses) so
// analysts can inspect batch composition without joining per-call
// rows. tool_response in this event is the serialized text the model
// SEES (not the structured Output object PostToolUse carries) — for
// Read that means line-number-prefixed text.
func buildClaudePostToolBatchEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		ToolCalls []struct {
			ToolName     string          `json:"tool_name"`
			ToolUseID    string          `json:"tool_use_id"`
			ToolInput    json.RawMessage `json:"tool_input"`
			ToolResponse json.RawMessage `json:"tool_response"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	if len(p.ToolCalls) == 0 {
		// Empty batch is a documented no-op — skip rather than
		// emit a placeholder. Symmetric to the SubagentStop empty-
		// shell suppression in v1.4.47.
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionPostToolBatch, "post_tool_batch")
	ev.SourceEventID = p.SessionID + ":post_tool_batch:" + claudeContentHash(body)
	ev.Target = fmt.Sprintf("%d tool call(s)", len(p.ToolCalls))
	ev.RawToolName = p.ToolCalls[0].ToolName
	// Full tool_calls array lands in RawToolInput as a scrubbed JSON
	// blob. Dashboards render it as the row's "what was in the batch"
	// detail; analysts can json_extract individual entries for
	// per-tool drilldown.
	if raw, err := json.Marshal(p.ToolCalls); err == nil {
		ev.RawToolInput = scrub.New().String(string(raw))
	}
	return ev, true
}

// buildClaudePermissionRequestEvent handles `PermissionRequest` — fires
// when the host asks the user (or auto-mode classifier) to authorize
// a tool call. Distinct from PermissionDenied: the request itself is
// just the prompt; the outcome lands as either continued tool
// execution (PostToolUse) or an ActionPermissionDenied row. Per docs
// PermissionRequest has NO tool_use_id, so we hash the body for
// SourceEventID uniqueness.
func buildClaudePermissionRequestEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		ToolName              string          `json:"tool_name"`
		ToolInput             json.RawMessage `json:"tool_input"`
		PermissionSuggestions json.RawMessage `json:"permission_suggestions"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionPermissionRequest, "permission_request")
	ev.SourceEventID = p.SessionID + ":permission_request:" + claudeContentHash(body)
	ev.Target = p.ToolName
	ev.RawToolName = p.ToolName
	if len(p.ToolInput) > 0 {
		ev.RawToolInput = scrub.New().String(string(p.ToolInput))
	}
	// permission_suggestions (addRules / setMode / etc.) lands on
	// PrecedingReasoning so analysts can see WHAT the host proposed
	// as the resolution path (e.g. "add this rule to localSettings").
	if len(p.PermissionSuggestions) > 0 {
		ev.PrecedingReasoning = string(p.PermissionSuggestions)
	}
	return ev, true
}

// buildClaudePermissionDeniedEvent handles `PermissionDenied` — fires
// only in auto-mode classifier denials. Distinct from ActionToolFailure:
// ToolFailure is the tool itself failing; PermissionDenied is the
// permission layer refusing to dispatch the tool in the first place.
// Has tool_use_id (unlike PermissionRequest) so we key on it
// symmetrically with PostToolUseFailure.
func buildClaudePermissionDeniedEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		ToolName  string          `json:"tool_name"`
		ToolInput json.RawMessage `json:"tool_input"`
		ToolUseID string          `json:"tool_use_id"`
		Reason    string          `json:"reason"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionPermissionDenied, "permission_denied")
	if p.ToolUseID != "" {
		ev.SourceEventID = p.ToolUseID + ":permission_denied"
	}
	ev.Target = p.ToolName
	ev.RawToolName = p.ToolName
	if len(p.ToolInput) > 0 {
		ev.RawToolInput = scrub.New().String(string(p.ToolInput))
	}
	ev.ErrorMessage = p.Reason
	ev.Success = false
	return ev, true
}

// buildClaudeInstructionsLoadedEvent handles `InstructionsLoaded` —
// fires when a CLAUDE.md / instructions file lands in context. Carries
// which file, what memory_type ("User" | "Project" | "Local" |
// "Managed"), why ("session_start" | "nested_traversal" |
// "path_glob_match" | "include" | "compact"), and optional glob /
// trigger / parent path fields for lazy / glob-matched / include loads.
func buildClaudeInstructionsLoadedEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		FilePath        string   `json:"file_path"`
		MemoryType      string   `json:"memory_type"`
		LoadReason      string   `json:"load_reason"`
		Globs           []string `json:"globs"`
		TriggerFilePath string   `json:"trigger_file_path"`
		ParentFilePath  string   `json:"parent_file_path"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionInstructionsLoaded, "instructions_loaded")
	// File_path is the natural per-session discriminator: a session
	// loads each instruction file at most once per load_reason. Same
	// file re-loaded under a different reason updates in place via
	// ON CONFLICT.
	if p.FilePath != "" {
		ev.SourceEventID = p.SessionID + ":instructions_loaded:" + p.FilePath
	}
	ev.Target = p.FilePath
	ev.RawToolName = p.MemoryType
	// load_reason + optional fields land on RawToolInput as a JSON
	// blob so dashboards can render "why this file loaded" without
	// re-parsing the full envelope.
	meta := map[string]any{}
	if p.LoadReason != "" {
		meta["load_reason"] = p.LoadReason
	}
	if len(p.Globs) > 0 {
		meta["globs"] = p.Globs
	}
	if p.TriggerFilePath != "" {
		meta["trigger_file_path"] = p.TriggerFilePath
	}
	if p.ParentFilePath != "" {
		meta["parent_file_path"] = p.ParentFilePath
	}
	if len(meta) > 0 {
		if b, err := json.Marshal(meta); err == nil {
			ev.RawToolInput = string(b)
		}
	}
	return ev, true
}

// buildClaudeConfigChangeEvent handles `ConfigChange` — fires when a
// settings.json mutation is observed by the host. Source discriminates
// the scope (user / project / local / policy / skills). file_path is
// optional (absent for the `skills` source).
func buildClaudeConfigChangeEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		Source   string `json:"source"`
		FilePath string `json:"file_path"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionConfigChange, "config_change")
	// {source}:{file_path} disambiguates one file modified twice in
	// different scopes (e.g. project_settings + local_settings both
	// pointing at .claude/settings.json — rare but documented).
	ev.SourceEventID = p.SessionID + ":config_change:" + p.Source + ":" + p.FilePath
	if p.FilePath != "" {
		ev.Target = p.FilePath
	} else {
		ev.Target = p.Source
	}
	ev.RawToolName = p.Source
	return ev, true
}

// buildClaudeWorktreeRemoveEvent handles `WorktreeRemove` — fires when
// a Claude Code Agent worktree is cleaned up. Non-blocking (per the
// docs reply matrix); the handler just records the event. Target
// carries the worktree_path so dashboards can correlate create / remove
// pairs by path.
func buildClaudeWorktreeRemoveEvent(body []byte) (models.ToolEvent, bool) {
	var p struct {
		claudeBaseEnvelope
		WorktreePath string `json:"worktree_path"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return models.ToolEvent{}, false
	}
	if p.SessionID == "" {
		return models.ToolEvent{}, false
	}
	ev := baseToolEvent(p.claudeBaseEnvelope, models.ActionWorktreeRemove, "worktree_remove")
	// Worktree path is the natural per-session discriminator —
	// removing the same path twice in one session is a no-op for
	// dedup purposes.
	if p.WorktreePath != "" {
		ev.SourceEventID = p.SessionID + ":worktree_remove:" + p.WorktreePath
	}
	ev.Target = p.WorktreePath
	return ev, true
}

// handleClaudeCodeWorktreeCreate is the dedicated handler for the
// `WorktreeCreate` blocking hook. Unlike the standard
// handleClaudeCodeActionEvent flow which always replies
// `{"decision":"approve"}` on stdout, WorktreeCreate must reply with
// the chosen worktree PATH so Claude Code's Agent spawn can proceed.
// The reply shape (per docs.claude.com/docs/en/hooks reply matrix):
//
//	{"hookSpecificOutput": {"worktreePath": "<absolute-path>"}}
//
// Any non-zero exit or absent worktreePath fails the spawn — so this
// handler must always succeed end-to-end. If the payload is malformed
// or missing fields, we fall back to a synthesized name + the
// canonical default location (`~/.claude/worktrees/<name>`) and emit
// the reply anyway. The action-row write is best-effort (spec P1) —
// DB errors log to stderr but the reply still goes out.
//
// NOT registered by default. See docs/claude-worktree-hook.md for the
// opt-in procedure + capture-first verification. stdin/stdout/stderr
// are injected for testability — production callers pass os.Stdin /
// os.Stdout / os.Stderr.
func handleClaudeCodeWorktreeCreate(ctx context.Context, label, configPath string, stdin io.Reader, stdout, stderr io.Writer) {
	body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	worktreePath, ev, hasSession := buildClaudeWorktreeCreateReply(body)

	// Reply on stdout FIRST so Claude Code never blocks on the DB
	// write. Matches the spec P1 reply-first-then-record pattern used
	// by handleClaudeCodeActionEvent.
	reply := map[string]any{
		"hookSpecificOutput": map[string]string{
			"worktreePath": worktreePath,
		},
	}
	_ = json.NewEncoder(stdout).Encode(reply)

	if !hasSession {
		return
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s config: %v\n", label, err)
		return
	}
	database, err := db.Open(ctx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s db: %v\n", label, err)
		return
	}
	defer database.Close()
	insertCtx, cancel := context.WithTimeout(ctx, cfg.Observer.Hooks.HookTimeout())
	defer cancel()
	hookStore := store.New(database)
	hookStore.SetTasksEnabled(cfg.Tasks.Enabled)
	hookStore.SetTasksOptions(cfg.Tasks.MatchMode, cfg.Tasks.ConcurrentAttribution, cfg.Tasks.IncludeSidechains)
	if _, err := hookStore.Ingest(insertCtx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
		fmt.Fprintf(stderr, "observer-hook: %s insert: %v\n", label, err)
	}
}

// buildClaudeWorktreeCreateReply computes the WorktreeCreate reply
// path and the action row for a parsed payload. Pure (no I/O, no
// config) so it's unit-testable. The handler wires it to stdin /
// stdout / DB.
//
// Path resolution rules (in priority order):
//  1. $OBSERVER_CLAUDE_WORKTREE_ROOT/<name> — advanced users with a
//     non-default worktree filesystem.
//  2. ~/.claude/worktrees/<name> — Claude Code's documented default
//     location.
//  3. /tmp/.claude/worktrees/<name> — last-ditch when UserHomeDir
//     fails (the spawn will likely fail to mkdir this on most hosts,
//     but at least we replied with SOMETHING rather than empty stdout
//     which fails 100%).
//
// `name` synthesis: when payload.name is empty (e.g. malformed
// payload, missing field), we synthesize "worktree-<base36 nanos>".
// Better to echo SOMETHING than an empty path.
//
// hasSession reflects whether the payload carried a session_id —
// when false, the action-row write is skipped (matches the standard
// helper's guard).
func buildClaudeWorktreeCreateReply(body []byte) (worktreePath string, ev models.ToolEvent, hasSession bool) {
	var p struct {
		claudeBaseEnvelope
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &p)

	name := p.Name
	if name == "" {
		name = "worktree-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	root := os.Getenv("OBSERVER_CLAUDE_WORKTREE_ROOT")
	if root == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			home = "/tmp"
		}
		root = filepath.Join(home, ".claude", "worktrees")
	}
	worktreePath = filepath.Join(root, name)

	if p.SessionID == "" {
		return worktreePath, models.ToolEvent{}, false
	}
	ev = baseToolEvent(p.claudeBaseEnvelope, models.ActionWorktreeCreate, "worktree_create")
	ev.SourceEventID = p.SessionID + ":worktree_create:" + name
	ev.Target = name
	ev.RawToolName = name
	ev.RawToolInput = worktreePath
	return worktreePath, ev, true
}

func previewLine(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
