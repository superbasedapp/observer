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
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/gitalias"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guard/notify"
	"github.com/marmutapp/superbased-observer/internal/guardposture"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/pidbridge"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// defaultHookMaxRuntime is the wall-clock budget for a single `observer
// hook` invocation. Hooks that exceed it exit promptly: fail-open (exit 0)
// on every hook except a wired gate hook on a node where guard enforcement
// is in force, which answers with the dialect's BLOCK instead (hook-parity
// audit section 5.7; see hookWatchdogFire). The
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

// installHookWatchdog arms a time.AfterFunc that runs hookWatchdogFire
// when maxRuntime elapses. Returns a stop func to disarm on a clean exit.
// exitFn is injected so unit tests can verify firing without actually
// terminating the test process. In production, callers wire it to
// os.Exit.
//
// **Fail-open on timeout, except under enforcement (superseded
// 2026-10-03, hook-parity audit section 5.7).** A non-zero exit from a
// PreToolUse hook BLOCKS the host tool, so for every hook that is not a
// wired gate on an enforcing node the watchdog still exits 0: a transient
// capture stall (e.g. the DB momentarily locked by a daemon startup
// prune/checkpoint on a large DB) must not turn into a hard block on the
// developer's work. A wired gate hook (tool_gate / prompt_gate) on a node
// whose guard-posture.json says enforcement is in force is the one
// exception: there an unevaluated call must not slip through, so the
// watchdog writes the dialect's BLOCK with the reason
// hook.FailClosedTimeoutReason, records the failure for the daemon to
// persist, and exits with the dialect's block code. Either way the process
// terminates promptly, so the host tool is never pinned waiting, and the
// reply goes through the one reply owner (hookReplyMu), so the watchdog
// and the receiver can never both reply.
func installHookWatchdog(maxRuntime time.Duration, exitFn func(int), stderr io.Writer) func() {
	if maxRuntime <= 0 {
		return func() {}
	}
	timer := time.AfterFunc(maxRuntime, func() {
		hookWatchdogFire(maxRuntime, exitFn, stderr)
	})
	return func() { timer.Stop() }
}

// hookReplied / hookPendingExitCode / hookExpectsStdoutReply track this
// invocation's already-decided verdict (P2-1, adversarial review of the
// P1-4 fix, docs/audits/codebase-audit-2026-09-16.md): several
// receivers in this file reply (or decide a process-exit-code verdict)
// FIRST and then do more work that can panic — DB opens, ingests,
// pidbridge seeds. Before this fix, recoverHookPanic always wrote a
// SECOND {"decision":"approve"} object and exited 0 no matter what had
// already happened, which could (a) corrupt the stdout stream with two
// concatenated JSON objects and (b) silently turn an ALREADY-DECIDED
// BLOCK (e.g. Claude Code's UserPromptSubmit dialect, which signals a
// block via process exit code 2 — handleClaudeCodeUserPromptSubmit
// replies + decides exitCode, THEN runs the capture ingest, THEN calls
// hookOSExit) into an ALLOW just because the ingest step panicked.
//
// hookExpectsStdoutReply additionally distinguishes JSON-reply
// dialects (the overwhelming majority — the zero value / default) from
// the two EXIT-CODE-ONLY prompt-submit dialects (Qoder, Cascade — see
// promptDialectsWithoutStdoutReply) whose vendor contract has NO stdout
// JSON channel for this event at all, not even on allow; writing one
// on a pre-reply panic would be unexpected output no such host parses,
// contradicting the (now corrected) claim that "every dialect treats a
// bare decision:approve as an allow".
//
// All three are reset to their zero/default state at the top of
// newHookCmd's Run (the single per-invocation entry point) — a
// production `observer hook` invocation is a fresh, short-lived OS
// process, but test code may drive Run multiple times in one binary,
// so state must not leak across invocations.
var (
	hookReplied            bool
	hookPendingExitCode    int
	hookExpectsStdoutReply = true
)

// markHookReplied records that this invocation has already written its
// hook-protocol reply to stdout (whether a JSON object or, for an
// exit-code-only dialect, deliberately nothing) — see hookReplied.
func markHookReplied() {
	hookReplyMu.Lock()
	hookReplied = true
	hookReplyMu.Unlock()
}

// markHookPendingExit records the process exit code a receiver has
// already decided on (0 for allow, a dialect's blockExitCode for an
// already-decided block) before doing further work that could panic —
// see hookPendingExitCode.
func markHookPendingExit(code int) {
	hookReplyMu.Lock()
	hookPendingExitCode = code
	hookReplyMu.Unlock()
}

// recoverHookPanic is the top-level panic guard for `observer hook`
// (P1-4/RES-2, docs/audits/codebase-audit-2026-09-16.md): every hook
// receiver in hookReceivers, plus HandleApprove's default fallthrough,
// runs beneath this deferred recover in newHookCmd's Run. Without it a
// panic anywhere in a receiver (e.g. handleClaudeCodePreTool's
// hook.RewriteBash over arbitrary developer-typed shell text, or any
// payload decoder) exits the process with status 2, and this repo's
// own standing note is that a non-zero exit from a PreToolUse-class
// hook BLOCKS the host AI tool — inverting the documented fail-open
// contract that installHookWatchdog already upholds for a timeout.
//
// On a recovered panic this: (1) logs the panic value + stack trace to
// STDERR ONLY — stdout is reserved for the hook protocol reply, and
// mixing diagnostics into it would corrupt the JSON the host tool
// parses; (2) writes the SAME {"decision":"approve"} fail-open reply
// hook.HandleApprove already emits as the default path for a tool with
// no registered receiver, but ONLY when nothing has been written yet
// AND the current dialect's wire contract expects stdout JSON at all
// (hookReplied / hookExpectsStdoutReply — P2-1: never invent a SECOND
// reply on top of one a receiver already sent, and never emit JSON an
// exit-code-only dialect doesn't parse); and (3) calls exitFn with
// hookPendingExitCode — 0 when nothing was ever decided (today's
// original fail-open default), or the exit code a receiver had already
// decided on before the panic, so an already-decided BLOCK survives a
// downstream panic instead of silently becoming an ALLOW.
//
// Superseded for one case (2026-10-03, hook-parity audit section 5.7): a
// panic before any reply on a wired gate hook (tool_gate / prompt_gate)
// whose node has guard enforcement in force is answered with the
// dialect's BLOCK (reason hook.FailClosedErrorReason), recorded for the
// daemon, and exits with the dialect's block code, instead of the approve
// above. Every other panic keeps the fail-open behaviour described here.
//
// exitFn is injected — same pattern as installHookWatchdog — so a unit
// test can verify the fail-open reply + the intended exit code without
// actually terminating the test process. Production wires os.Exit.
func recoverHookPanic(label string, stdout, stderr io.Writer, exitFn func(int)) {
	if r := recover(); r != nil {
		fmt.Fprintf(stderr, "observer-hook: PANIC in %s: %v\n%s\n", label, r, debug.Stack())
		hookReplyMu.Lock()
		defer hookReplyMu.Unlock()
		if handled, code := answerFailureLocked(guardposture.KindCrash, "", "", stderr); handled {
			hookFailureExited = true
			exitFn(code)
			return
		}
		if !hookReplied && hookExpectsStdoutReply {
			// stdin may already be partially or fully consumed by the
			// panicking receiver; HandleApprove tolerates an empty/short
			// read (it never depends on the body to reply), so we hand it
			// an empty reader rather than risk re-reading a live os.Stdin.
			// The plan's dialect picks the host's own allow shape
			// (HandlePromptAllow; approve for every dialect without one).
			hook.HandleDialectAllow(currentHookPlan().Dialect, label, strings.NewReader(""), lockedReplyWriter{w: stdout}, stderr)
		}
		exitFn(hookPendingExitCode)
	}
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
// Spec P1 (superseded in part 2026-10-03, hook-parity audit section 5.7):
// errors are written to stderr and a failure ALLOWS the host tool on every
// hook, with one exception. A wired gate hook (tool_gate / prompt_gate) on
// a node where guard enforcement is in force (guard-posture.json, written
// by the daemon) answers a failure (timeout, panic, config error, guard
// that cannot be built, unparseable payload) with the dialect's BLOCK and a
// reason, and records it (guard-hookfail.jsonl -> guard_events). A
// process-level watchdog (`--max-runtime`, default 30 s, capped below the
// host's own hook timeout for gate events) still guarantees the process
// terminates promptly whichever way it answers.
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
	"claude-code": handleClaudeCodeHook,
	"droid": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolDroid, "droid", hook.PromptDialectTopLevelBlock, "UserPromptSubmit", event, configPath)
	},
	// muse (T-479): Muse Code 1.4.3 cancelled the run before any model
	// request on {"decision":"block"} (live, demo node 1, 2026-10-06).
	"muse": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolMuse, "muse", hook.PromptDialectTopLevelBlock, "UserPromptSubmit", event, configPath)
	},
	// kimi-code (T-378): Kimi Code 2.1.1 blocked a prompt on exit 2 with
	// zero model requests (live, demo node 1, 2026-10-07). PreToolUse is
	// served earlier by the binding-driven tool gate (standaloneToolGate).
	"kimi-code": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolKimiCode, "kimi-code", hook.PromptDialectKimiCode, "UserPromptSubmit", event, configPath)
	},
	// kiro-cli (gfiD, 2026-10-15): userPromptSubmit cannot block on kiro-cli
	// 2.28.0 (live), so the dialect only warns the model in plain text.
	// preToolUse is served earlier by the binding-driven tool gate; a V3
	// PascalCase event is folded onto the camelCase binding first
	// (canonicalHookEvent).
	"kiro-cli": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolKiroCLI, "kiro-cli", hook.PromptDialectKiroCLI, "userPromptSubmit", event, configPath)
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
	// antigravity-cli PreInvocation (audit P1; restored by T-476; blocks
	// since the 2026-10-15 guard-enforcement fix): a pre-model-call seam
	// that runs before every model call; the dialect reads the prompt from
	// the session transcript (agy 1.3.x writes the USER_INPUT step before
	// invocationNum 0), judges each prompt once, warns with a userMessage
	// and blocks by aborting the turn (then taints the conversation).
	// (The PreToolUse tool gate, hook-parity Lane A6, is served by the
	// binding route ahead of this receiver.)
	"antigravity-cli": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolAntigravityCLI, "antigravity-cli", hook.PromptDialectAntigravityPreInvocation, "PreInvocation", event, configPath)
	},
	// copilot-cli (guard-fix lane B, live 2026-10-15): userPromptSubmitted
	// blocks with handled + responseContent + modifiedPrompt. preToolUse is
	// served earlier by the binding-driven tool gate (standaloneToolGate).
	"copilot-cli": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolCopilotCLI, "copilot-cli", hook.PromptDialectCopilotCLI, "userPromptSubmitted", event, configPath)
	},
	// cline-cli (guard-fix lane B, live 2026-10-15): the Observer plugin's
	// beforeModel prompt gate. beforeTool and a legacy PreToolUse script are
	// served earlier by the binding-driven tool gate.
	"cline-cli": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolClineCLI, "cline-cli", hook.PromptDialectClinePlugin, "beforeModel", event, configPath)
	},
	"devin": func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(models.ToolDevin, "devin", hook.PromptDialectCascade, "pre_user_prompt", event, configPath)
	},
	// command-code's event name matches the Mods SDK hook name
	// (transformInput) verbatim — the go:embed'd .ts bridge invokes
	// `observer hook command-code transformInput` exactly like every
	// other dialect's argv shape, even though the caller is a Node/jiti
	// process rather than a shell.
	"command-code": func(ctx context.Context, event, configPath string) {
		// beforeToolCall (the plugin tool gate) is served by its dialect.
		if dispatchBindingDialect(ctx, "command-code", event, configPath) {
			return
		}
		handlePromptSubmitOnlyHook(models.ToolCommandCode, "command-code", hook.PromptDialectCommandCode, "transformInput", event, configPath)
	},
	// The 2026-10-21 wave (docs/guard.md "Live grounding: 2026-10-21
	// wave"): each tool's prompt gate; the pre-tool gate is served earlier
	// by the binding-driven tool gate (standaloneToolGate). Kimchi and
	// Cortex Code run Claude Code's own hooks, which the claude-code
	// receiver recognises and re-routes (hook.ClassifyClaudeHookPayload);
	// their entries serve a hand-wired `observer hook <tool>` command.
	"ibm-bob":         wavePromptReceiver(models.ToolIBMBob, hook.PromptDialectClaudeCode, "UserPromptSubmit"),
	"codebuddy":       wavePromptReceiver(models.ToolCodeBuddy, hook.PromptDialectTopLevelBlock, "UserPromptSubmit"),
	"deepagents-code": wavePromptReceiver(models.ToolDeepAgentsCode, hook.PromptDialectClaudeCode, "UserPromptSubmit"),
	"dimcode":         wavePromptReceiver(models.ToolDimCode, hook.PromptDialectKimiCode, "UserPromptSubmit"),
	"dirac":           wavePromptReceiver(models.ToolDirac, hook.PromptDialectDirac, "UserPromptSubmit"),
	"autohand":        wavePromptReceiver(models.ToolAutohand, hook.PromptDialectAutohand, "pre-prompt"),
	"vtcode":          wavePromptReceiver(models.ToolVTCode, hook.PromptDialectKimiCode, "UserPromptSubmit"),
	"kimchi":          wavePromptReceiver(models.ToolKimchi, hook.PromptDialectClaudeCode, "UserPromptSubmit"),
	"cortex-code":     wavePromptReceiver(models.ToolCortexCode, hook.PromptDialectClaudeCode, "UserPromptSubmit"),
	// Surface-gap lane w5-foreign: prompt gates reached through another
	// tool's registration (the antigravity-cli and claude-code receivers
	// serve the replayed payloads, hook_surface.go / foreignhost.go).
	"antigravity": replayPromptReceiver(models.ToolAntigravity, hook.PromptDialectAntigravityPreInvocation, "PreInvocation"),
	"deepseek":    replayPromptReceiver(models.ToolDeepSeek, hook.PromptDialectClaudeCode, "UserPromptSubmit"),
}

// wavePromptReceiver is a hookReceivers entry whose only guarded event of
// its own is the prompt gate promptEvent, evaluated in dialect.
func wavePromptReceiver(tool, dialect, promptEvent string) func(ctx context.Context, event, configPath string) {
	return func(_ context.Context, event, configPath string) {
		handlePromptSubmitOnlyHook(tool, tool, dialect, promptEvent, event, configPath)
	}
}

func newHookCmd() *cobra.Command {
	var (
		configPath     string
		maxRuntime     time.Duration
		bridgeSentinel bool
	)
	cmd := &cobra.Command{
		Use:   "hook <tool> <event>",
		Short: "Handle an AI-tool hook event on stdin and reply on stdout",
		Long: "Invoked by the host AI tool via its hook configuration. Reads a\n" +
			"JSON payload from stdin and replies on stdout. For Cursor, also\n" +
			"records the event in the observer DB. A failure (timeout, crash,\n" +
			"config or guard error, unparseable payload) ALLOWS the host tool,\n" +
			"except on a gate hook (tool/prompt gate) while guard enforcement\n" +
			"is on: then the call is BLOCKED with a reason and the failure is\n" +
			"recorded as a guard event. A process watchdog (--max-runtime,\n" +
			"default 30s) bounds every invocation.",
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// P2-1 (adversarial review of the P1-4 fix): reset the
			// per-invocation verdict-tracking state fresh for THIS
			// call — see hookReplied's doc comment for why this must
			// be the single reset point.
			exit := os.Exit
			if bridgeSentinel {
				// AW-37: started by `observer hook-bridge`, which reads
				// every exit other than 0 and 2 as "the hook did not run"
				// unless it is the sentinel. The invocation's decided exits
				// go through exit or hookOSExit and are mapped here. Two
				// paths are not: a cobra argument or flag error (main
				// exits 1, also what an older WSL observer without this
				// flag answers) and a panic outside recoverHookPanic (the
				// Go runtime exits 2). The bridge blocks on both, which
				// is the fail-closed reading the bridge exists for.
				exit = sentinelExit(os.Exit)
				hookOSExit = exit
			}
			runHookInvocation(cmd.Context(), args, configPath, maxRuntime, exit)
		},
	}
	cmd.Flags().BoolVar(&bridgeSentinel, hookbridgeSentinelFlagName, false, "set by `observer hook-bridge`: map every exit code other than 0 and 2 to the bridge's sentinel (internal/hookbridge)")
	_ = cmd.Flags().MarkHidden(hookbridgeSentinelFlagName)
	cmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml; when set, hook DB writes land on the config's observer.db (matches the proxy / MCP server invocations)")
	cmd.Flags().DurationVar(&maxRuntime, "max-runtime", 0, "Hard wall-clock cap on a single hook invocation; on exceedance the process exits 0 (fail-open) so the host AI tool is never pinned, except a gate hook (tool/prompt gate) while guard enforcement is on, which BLOCKS the call with a reason (see installHookWatchdog). 0 = use OBSERVER_HOOK_MAX_RUNTIME or the 30s default (gate events are also capped below the host's own hook timeout). See docs/observer-platform-issues-v3.md V3-1.")
	return cmd
}

// hookStateDirResolver returns the resolver hook.SetStateDirResolver runs
// for the forensics logs: the Observer home of the config the invocation
// runs under, which is the directory of its [observer] db_path (the
// convention of daemon.log, the delivery credential and the OTLP ingest
// token). "" when the config cannot be loaded, so the hook package falls
// back to ~/.observer and the hook still never fails on a log.
func hookStateDirResolver(configPath string) func() string {
	return func() string {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil || cfg.Observer.DBPath == "" {
			return ""
		}
		return filepath.Dir(cfg.Observer.DBPath)
	}
}

// runHookInvocation is one `observer hook <tool> <event>` invocation.
// exitFn is the process exit for the watchdog and the panic guard (os.Exit
// in production; a recorder in tests).
//
// Ordering (Sol A2-03): the panic guard is installed before any fallible
// work; the deadline is ONE absolute instant from the start of the
// invocation, and the watchdog is armed against it before the posture is
// resolved, with a provisional plan that already fails closed for a wired
// gate (finalizeHookFailurePlan can only open it). A slow or panicking
// posture/config read therefore can neither run on a fail-open zero plan
// nor push the answer past the host's own deadline. T-381: the provisional
// plan holds only across the cheap posture and config reads; after them an
// interim plan from those reads (settleHookFailurePlan) governs until the
// full derivation finishes, so a node that does not enforce is not closed
// by a slow derivation.
func runHookInvocation(ctx context.Context, args []string, configPath string, maxRuntime time.Duration, exitFn func(int)) {
	start := time.Now()
	// P2-1 (adversarial review of the P1-4 fix): reset the
	// per-invocation verdict-tracking state fresh for THIS
	// call — see hookReplied's doc comment for why this must
	// be the single reset point.
	resetHookInvocationState()
	resetHookActivity()
	// The forensics logs follow --config's Observer home (live proof
	// 2026-10-21), resolved lazily on the first log write.
	hook.SetStateDirResolver(hookStateDirResolver(configPath))

	// Inside a sandbox box the invocation goes over the capture relay and
	// never opens a database (hook_relay.go, sandbox plan section 5.2).
	if code, boxed := boxHookRelay(args, os.Stdin, os.Stdout, os.Stderr); boxed {
		exitFn(code)
		return
	}
	// Every exit below writes the armed activity record first (R-188 F4):
	// the watchdog and the panic guard end the process through exitFn.
	exitFn = activityFlushingExit(exitFn)

	tool := args[0]
	event := ""
	if len(args) >= 2 {
		event = canonicalHookEvent(tool, args[1])
	}
	label := tool
	if event != "" {
		label = tool + ":" + event
	}
	// A watchdog that already owns the reply finishes (and exits) before
	// the invocation may return and exit 0.
	defer hookReplyBarrier()
	// P1-4/RES-2 (docs/audits/codebase-audit-2026-09-16.md): a panic
	// anywhere below this point must never surface as a non-zero exit —
	// see recoverHookPanic's doc comment.
	defer recoverHookPanic(label, hookStdout, os.Stderr, exitFn)

	// The hook context seam (internal/hookctx, roadmap F0-3): every
	// process fact and payload-named file the handlers below read comes
	// through this one filled context. The security providers read
	// nothing until an event names a project (hook_security.go).
	//
	// Lane sbx-p2: a relay child of the daemon (an invocation relayed out of
	// a sandbox) fills it through the Daemon entry from the run's channel
	// instead (hook_relay.go); either way the pure builders read it through
	// hookctx.Process.
	hreq := hookctx.Request{Tool: tool, Event: event}
	hc, relayed := relayChildHookContext(ctx, hreq, configPath)
	if !relayed {
		hc = hookctx.Host(ctx, hreq, hostHookSource(), hostHookProviders(configPath))
	}
	hookctx.SetProcess(hc)
	ctx = hookctx.WithContext(ctx, hc)
	setInvocationHookContext(hc, configPath)

	// Hook failure semantics (section 5.7): the provisional plan comes
	// from the registry alone; the gate budget is capped below the host's
	// own hook timeout and measured from start.
	plan := provisionalHookFailurePlan(tool, event, configPath)
	plan.Started = start
	setHookPlan(plan)
	budget := hookGateBudget(resolveHookMaxRuntime(maxRuntime, hc.Getenv("OBSERVER_HOOK_MAX_RUNTIME")), plan)
	stopWatchdog := installHookWatchdog(hookRemaining(start, budget), exitFn, os.Stderr)
	defer stopWatchdog()
	// Hook liveness (OBS-7): ONE DB-free spool record per invocation, after
	// the handler below has replied, while the watchdog is still armed
	// (hook_activity.go). Receivers report the session id they parsed.
	// A block or fail-closed exit (hookExitProcess), the watchdog and the
	// panic guard flush the same armed record before the process ends, once.
	armHookActivity(func() { emitHookActivity(tool, event, configPath, os.Stderr, hookActivityDepsFor(hc.Getenv)) })
	defer flushHookActivity()
	// The posture settles the plan BEFORE stdin is read. T-381: the cheap
	// reads (posture, config) publish an interim plan first, so a slow full
	// derivation on a node that does not enforce fails open, not closed.
	setHookPlan(settleHookFailurePlan(plan, configPath, setHookPlan))
	// D-221 / T-327: under the organization's fail_closed choice, an
	// enforced gate stays closed while the user guard policy does not load
	// (a no-op on every other plan, and on every individual node).
	if hookUserPolicyGate(configPath, os.Stdin) {
		return
	}
	// The L2 adapter gate (hook_components.go): a leftover hook of an
	// inactive adapter allows and records nothing, unless its plan fails
	// closed (guard enforcement keeps deciding).
	if hookAdapterGate(ctx, tool, event, label, configPath, currentHookPlan(), os.Stdin, hookStdout, os.Stderr) {
		return
	}

	if b, ok := standaloneToolGate(tool, event); ok {
		// A wired tool gate with no receiver of its own: the one
		// tool-gate path (hook_toolgate.go), ahead of the tool's
		// prompt-only receiver.
		handleToolGateHook(tool, label, b, os.Stdin, configPath)
	} else if b, ok := lifecycleBinding(tool, event); ok {
		// The ONE lifecycle handler (hook-parity Lane C1): a wired
		// session / turn / sub-agent lifecycle binding is served here for
		// every tool, before the tool's own receiver (hook_lifecycle.go).
		body, _ := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
		body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
		handleLifecycleHook(ctx, tool, label, b, body, configPath, hookStdout, os.Stderr, productionLifecycleDeps(ctx))
	} else if feedbackOptInRoute(tool, event, configPath) {
		// A post-tool event Observer registers only for the security
		// feedback (a RegisterWhen binding), while it is selected: the
		// feedback handler, ahead of the tool's own receiver, which would
		// answer its prompt-only allow and carry nothing
		// (security_feedback.go). Not selected, the event goes to the
		// receiver below exactly as before.
		handlePostFeedbackHook(ctx, tool, event, label, configPath, os.Stdin, hookStdout, os.Stderr)
		markHookReplied()
	} else if fn, ok := hookReceivers[tool]; ok {
		fn(ctx, event, configPath)
	} else {
		dispatchWithoutReceiver(ctx, tool, event, label, configPath)
	}
}

// dispatchWithoutReceiver is runHookInvocation's path for an event no
// hookReceivers entry serves: a binding whose dialect has its own handler,
// the binding's capability receiver, the one binding-driven allow, or the
// plain approve. A receiver that owns only one event of its tool hands every
// other event here (replayPromptReceiver).
func dispatchWithoutReceiver(ctx context.Context, tool, event, label, configPath string) {
	if dispatchBindingDialect(ctx, tool, event, configPath) {
		// A binding whose dialect has its own handler (the plugin hosts,
		// hook_pluginshim.go).
		return
	}
	if b, ok := resolveHookBinding(tool, event); ok {
		// A tool with bindings but no receiver: the binding's capability
		// receiver when one exists (dispatchBindingReceiver), else the one
		// binding-driven allow (hook_binding.go).
		if !dispatchBindingReceiver(ctx, tool, event, configPath, b) {
			handleBindingFallback(tool, label, b, os.Stdin, hookStdout, os.Stderr)
			markHookReplied()
		}
		return
	}
	hook.HandleApprove(label, os.Stdin, hookStdout, os.Stderr)
	markHookReplied()
}

// replayPromptReceiver is the hookReceivers entry of a tool whose prompt gate
// is reached through ANOTHER tool's registration (HookBinding.ReplayedVia:
// the Antigravity App and IDE on antigravity-cli's hooks.json, DeepSeek
// Harness on Observer's Claude Code hooks). That registration's receiver
// serves the replayed payload; this entry serves a hand-wired
// `observer hook <tool> <promptEvent>` the same way, and hands every other
// event to the path it took before the tool had a receiver.
func replayPromptReceiver(tool, dialect, promptEvent string) func(ctx context.Context, event, configPath string) {
	return func(ctx context.Context, event, configPath string) {
		if event != promptEvent {
			label := tool
			if event != "" {
				label = tool + ":" + event
			}
			dispatchWithoutReceiver(ctx, tool, event, label, configPath)
			return
		}
		handlePromptSubmitOnlyHook(tool, tool, dialect, promptEvent, event, configPath)
	}
}

// handleClaudeCodeHook dispatches Claude Code hook events. For PreCompact
// and PostCompact we write to compaction_events; for PreToolUse we may
// rewrite a Bash command to funnel through `observer run`; other events
// fall through to HandleApprove (the JSONL watcher captures them
// out-of-band). Always replies with an approval on stdout — must never
// block the host. The one exception is a payload ANOTHER host sent to a
// Claude Code hook command (cursor-agent runs the user's Claude Code
// hooks with its own payload): hook.ForeignClaudeHookHost recognises it
// from a field it carries and the receiver exits 0 without a reply,
// without ingesting and without evaluating the guard.
//
// `configPath`, when non-empty, is forwarded to all `config.Load` calls
// so the hook handler reads the same config (and therefore writes to
// the same DB) as whichever proxy daemon launched it.
func handleClaudeCodeHook(ctx context.Context, event, configPath string) {
	label := "claude-code"
	if event != "" {
		label = "claude-code:" + event
	}
	stdin, body, verdict := claudeCodeHookPayload(os.Stdin, event, configPath)
	if verdict.Foreign {
		noteForeignHookActivity(verdict, body)
		answerForeignClaudeCodeHook(ctx, label, verdict, body, configPath, hookStdout, os.Stderr)
		return
	}
	noteHookPayload(body)
	dispatchClaudeCodeHook(ctx, event, configPath, stdin)
}

// dispatchClaudeCodeHook is handleClaudeCodeHook's per-event dispatch over
// the already-peeked payload stream (see claudeCodeHookPayload).
func dispatchClaudeCodeHook(ctx context.Context, event, configPath string, stdin io.Reader) {
	label := "claude-code"
	if event != "" {
		label = "claude-code:" + event
	}
	if event == "pre-tool" {
		handleClaudeCodePreTool(stdin, hookStdout, os.Stderr, label, configPath)
		return
	}
	if event == "post-tool" {
		handleClaudeCodePostTool(stdin, hookStdout, os.Stderr, label, configPath)
		return
	}
	if event == "session-start" {
		writer := makePidbridgeWriter(configPath)
		// The body is teed so the skills-history snapshot (S10-SKILLS,
		// hook_skillsnap.go) can run AFTER the session-start reply, on the
		// same payload, without changing the handler's signature.
		var body bytes.Buffer
		hc := hookContext(ctx)
		handleClaudeCodeSessionStart(ctx, hc.ParentPID(), hc.Ancestors, io.TeeReader(stdin, &body), hookStdout, os.Stderr, label, writer)
		recordClaudeSkillSnapshot(body.Bytes(), "SessionStart", label, configPath, os.Stderr)
		// Repository trust's session-start flag (security.trust): after
		// the reply, never blocking.
		recordSessionStartTrust(ctx, models.ToolClaudeCode, body.Bytes(), configPath, os.Stderr)
		return
	}
	// Tier 1 expansion (2026-05): each of these events maps to one row
	// in the actions table via a per-event builder. Shared helper handles
	// stdin → reply → DB open → insert.
	switch event {
	case "session-end":
		// The one lifecycle handler (Lane C1): DB-free spool, because
		// Claude Code's SessionEnd budget is about 1.5 s shared.
		if b, ok := lifecycleBinding(models.ToolClaudeCode, "SessionEnd"); ok {
			body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))
			body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
			handleLifecycleHook(ctx, models.ToolClaudeCode, label, b, body, configPath, hookStdout, os.Stderr, productionLifecycleDeps(ctx))
			return
		}
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeSessionEndEvent)
		return
	case "user-prompt-submit":
		handleClaudeCodeUserPromptSubmitFrom(ctx, stdin, label, configPath)
		return
	case "post-tool-failure":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudePostToolFailureEvent)
		return
	case "stop-failure":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeStopFailureEvent)
		return
	case "subagent-start":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeSubagentStartEvent)
		return
	case "subagent-stop":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeSubagentStopEvent)
		return
	case "stop":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeStopEvent)
		return
	case "notification":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeNotificationEvent)
		return
	case "cwd-changed":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeCwdChangedEvent)
		return
	case "setup":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeSetupEvent)
		return
	case "user-prompt-expansion":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeUserPromptExpansionEvent)
		return
	case "post-tool-batch":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudePostToolBatchEvent)
		return
	case "permission-request":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudePermissionRequestEvent)
		return
	case "permission-denied":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudePermissionDeniedEvent)
		return
	case "instructions-loaded":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeInstructionsLoadedEvent)
		return
	case "config-change":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeConfigChangeEvent)
		return
	case "worktree-remove":
		handleClaudeCodeActionEvent(ctx, stdin, label, configPath, buildClaudeWorktreeRemoveEvent)
		return
	case "task-created", "task-completed":
		// task_observe (hook-parity Lane E): capture only. The reply is
		// the plain approve, never a decision: exit 2 here would roll back
		// the developer's task creation / completion.
		handleObserveOnlyHook(ctx, models.ToolClaudeCode, label, event, configPath, stdin)
		return
	case "worktree-create":
		// Special path: blocking hook that must write the chosen
		// worktree path on stdout (per docs.claude.com/docs/en/hooks
		// reply matrix) — any non-zero exit or empty stdout fails
		// the Agent spawn. NOT registered by default; user opts in
		// per docs/claude-worktree-hook.md.
		handleClaudeCodeWorktreeCreate(ctx, label, configPath, stdin, hookStdout, os.Stderr)
		return
	}
	if event != "pre-compact" && event != "post-compact" {
		hook.HandleApprove(label, stdin, hookStdout, os.Stderr)
		markHookReplied()
		return
	}
	// PreCompact / PostCompact: the ONE compaction recorder every
	// compact_lifecycle binding reaches (hook_observe.go), after the reply.
	handleObserveOnlyHook(ctx, models.ToolClaudeCode, label, event, configPath, stdin)
}

// handleObserveOnlyHook answers an observe-family Claude-shaped hook with
// the plain approve FIRST (the DB write is best-effort and never delays or
// changes the reply), then records the payload through the binding's
// capability recorder (recordObserveBinding).
func handleObserveOnlyHook(ctx context.Context, tool, label, event, configPath string, stdin io.Reader) {
	body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	_ = json.NewEncoder(hookStdout).Encode(hook.Decision{Decision: "approve"})
	markHookReplied()
	recordObserveBinding(ctx, tool, label, event, body, configPath, os.Stderr)
}

// claudeCodeHookPayload reads the Claude Code hook payload ONCE (up to
// the largest bound any claude-code handler reads, plus one byte) to ask
// hook.ClassifyClaudeHookPayload whether another host sent it, and returns a
// stream that replays those bytes followed by whatever is left, so every
// handler still reads - and still detects truncation - exactly as before.
// An over-bound payload is never classified (its tail, where Cursor puts
// cursor_version, is not in hand) and takes the normal path.
//
// A leading UTF-8 BOM (a .NET / PowerShell stdin writer on a UTF-8 console
// prepends one) is stripped ONCE, here, from the stream itself (FU-161):
// every handler reads the same BOM-free bytes the classifier judged, so no
// handler decodes an untrimmed copy, fails, and approves unevaluated. The
// handlers' truncation detection then measures the payload without the
// BOM, which is the payload.
func claudeCodeHookPayload(r io.Reader, event, configPath string) (stdin io.Reader, body []byte, verdict hook.ForeignVerdict) {
	buf, _ := io.ReadAll(io.LimitReader(r, promptSubmitBodyLimit+1))
	over := int64(len(buf)) > promptSubmitBodyLimit
	buf = bytes.TrimPrefix(buf, []byte{0xEF, 0xBB, 0xBF})
	stdin = io.MultiReader(bytes.NewReader(buf), r)
	if over {
		return stdin, nil, hook.ForeignVerdict{}
	}
	body = buf
	hook.DumpHookShape(models.ToolClaudeCode, event, body)
	// The host environment through the hook context (a relayed event reads
	// the run's declared environment, never the daemon's), and the host's
	// own registration probe for a row that answers neutral only while
	// Observer's own hook for the host sees the call (G2).
	return stdin, body, hook.ClassifyClaudeHookPayloadHost(body, hook.ForeignHostEnv{
		Getenv:            hookctx.Process().Getenv,
		OwnGateRegistered: ownGateRegisteredProbe(configPath),
	})
}

// ownGateRegisteredProbe is hook.OwnGateRegistered for this hook process:
// the registry the hook would have been written by, at the home and with
// the relocation variables the hook context supplies (hookctx.Process; the
// pinned-home rule's isolation still reads no variable). It answers false,
// so the replay is judged, when the binary path or the home cannot be
// resolved and always on the relay path (hookctx.PathDaemon): there the
// hook context is the sandbox run's, and the daemon host's own Copilot home
// says nothing about whether the run's Copilot has Observer's hook.
func ownGateRegisteredProbe(configPath string) func(tool, step string) bool {
	return func(tool, step string) bool {
		hc := hookctx.Process()
		if hc.Path() != hookctx.PathHost {
			return false
		}
		home := hookProcessHome(hc, runtime.GOOS)
		if home == "" {
			return false
		}
		bin, err := absoluteBinaryPath()
		if err != nil {
			return false
		}
		getenv := hc.Getenv
		if crossmount.IsolationReason() != "" {
			getenv = crossmount.NoEnv
		}
		return hook.OwnGateRegistered(hook.Options{BinaryPath: bin, ConfigPath: configPath, HomeDir: home, Getenv: getenv})(tool, step)
	}
}

// hookProcessHome is the hook process's home as os.UserHomeDir reads it
// (USERPROFILE on Windows, HOME elsewhere), through the hook context's
// environment rather than the operating system's.
func hookProcessHome(hc *hookctx.Context, goos string) string {
	if goos == "windows" {
		return hc.Getenv("USERPROFILE")
	}
	return hc.Getenv("HOME")
}

// answerForeignClaudeCodeHook is the claude-code receiver's answer to a
// payload another host sent (hook.ClassifyClaudeHookPayload). Nothing is
// ever recorded or evaluated as Claude Code. Per the verdict:
//
//   - ForeignDispatch (a host with no Observer hook of its own, e.g. Grok
//     Build): the host's own lifecycle binding for the event is served by
//     the one lifecycle handler under the HOST's tool id; any other event is
//     answered with the host's neutral reply (Lane C3 dispatches lifecycle
//     only; a gate binding stays unhandled, so unknown is an allow);
//   - ForeignNeutral (the host's own Observer hook already sees the call,
//     e.g. cursor-agent, or the Copilot CLI runtime while Observer's
//     copilot-cli registration is in place): the host's neutral reply for
//     the step (T-034h: an EMPTY stdout is logged by cursor-agent as a failed
//     hook);
//   - ForeignReroute (the host runs Claude Code's hooks as its own gate, or
//     its own Observer hook is absent): served by the host's binding for the
//     event under the host's tool id (rerouteForeignHook);
//   - ForeignNoop (recognisably foreign, unidentified): nothing on stdout.
func answerForeignClaudeCodeHook(ctx context.Context, label string, v hook.ForeignVerdict, body []byte, configPath string, stdout, stderr io.Writer) {
	host := v.Host
	if host == "" {
		host = "an unidentified host"
	}
	hook.RecordForeignReplay(label, v, len(body))
	if v.Action == hook.ForeignReroute && rerouteForeignHook(ctx, v, body, configPath, stdout, stderr) {
		return
	}
	if v.Action == hook.ForeignDispatch {
		if b, ok := lifecycleBinding(v.Tool, v.Step); ok {
			fmt.Fprintf(stderr, "observer-hook: %s payload from %s; dispatched to %s %s\n", label, host, v.Tool, v.Step)
			handleLifecycleHook(ctx, v.Tool, label, b, body, configPath, stdout, stderr, productionLifecycleDeps(ctx))
			return
		}
	}
	if (v.Action == hook.ForeignNeutral || v.Action == hook.ForeignDispatch || v.Action == hook.ForeignReroute) && len(v.Reply) > 0 {
		_, _ = stdout.Write(v.Reply)
		markHookReplied()
		fmt.Fprintf(stderr, "observer-hook: %s payload from %s (runs Claude Code hooks); neutral reply, nothing recorded\n", label, host)
		return
	}
	setHookExpectsStdoutReply(false)
	fmt.Fprintf(stderr, "observer-hook: %s payload from %s (runs Claude Code hooks); no-op\n", label, host)
}

// rerouteServe is how the host's binding serves a rerouted payload.
type rerouteServe int

const (
	// rerouteUnserved: the host has no served binding for the event, so
	// the payload gets the host's neutral reply and is not counted as the
	// host's call (a Copilot runtime UserPromptSubmit replay: copilot-cli
	// has no Claude prompt replay binding).
	rerouteUnserved rerouteServe = iota
	rerouteLifecycle
	rerouteToolGate
	reroutePromptGate
)

// foreignReroute resolves the host binding a ForeignReroute payload is
// served by. rerouteForeignHook serves through it and
// noteForeignHookActivity counts through it, so a reroute nothing serves is
// never counted as the host's call.
func foreignReroute(v hook.ForeignVerdict) (rerouteServe, integration.HookBinding) {
	if b, ok := lifecycleBinding(v.Tool, v.Step); ok {
		return rerouteLifecycle, b
	}
	b, ok := replayHookBinding(v.Tool, v.Step)
	if !ok || !b.Wired {
		return rerouteUnserved, integration.HookBinding{}
	}
	switch {
	case b.Cap == integration.HookCapToolGate && toolGateServed(b):
		return rerouteToolGate, b
	case b.Cap == integration.HookCapPromptGate && hook.KnownPromptDialect(b.Dialect):
		return reroutePromptGate, b
	}
	return rerouteUnserved, integration.HookBinding{}
}

// replayHookBinding is the binding of tool a payload replayed through
// Observer's Claude Code hooks is served by: the tool's binding for step
// that declares it is reached through claude-code (ReplayedVia), when the
// tool has one beside a registered binding of the same event (cursor's
// preToolUse, FU-122), else the tool's binding for step.
func replayHookBinding(tool, step string) (integration.HookBinding, bool) {
	if c, ok := integration.For(tool); ok {
		for _, b := range c.Hook.Bindings {
			if b.NativeEvent == step && b.ReplayedVia == models.ToolClaudeCode {
				return b, true
			}
		}
	}
	return resolveHookBinding(tool, step)
}

// rerouteForeignHook serves a ForeignReroute payload as the HOST's own hook
// call: its wired tool gate, prompt gate or lifecycle binding for the event,
// under the host's tool id. It reports false when the host has no served
// binding for the event (the caller then writes the neutral reply).
func rerouteForeignHook(ctx context.Context, v hook.ForeignVerdict, body []byte, configPath string, stdout, stderr io.Writer) bool {
	label := v.Tool + ":" + v.Step
	kind, b := foreignReroute(v)
	switch kind {
	case rerouteLifecycle:
		handleLifecycleHook(ctx, v.Tool, label, b, body, configPath, stdout, stderr, productionLifecycleDeps(ctx))
		return true
	case rerouteToolGate:
		fmt.Fprintf(stderr, "observer-hook: claude-code payload from %s; served as %s\n", v.Host, label)
		setHookExpectsStdoutReply(hook.ToolGateAllowWritesStdout(b.Dialect))
		runToolGate(v.Tool, label, b, body, false, configPath, stdout, stderr)
		return true
	case reroutePromptGate:
		fmt.Fprintf(stderr, "observer-hook: claude-code payload from %s; served as %s\n", v.Host, label)
		evaluatePromptSubmitBody(v.Tool, v.Tool, b.Dialect, v.Step, v.Step, configPath, body, false, stdout)
		return true
	}
	return false
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
// calls via the dispatcher pass the hook context's ParentPID and Ancestors
// (internal/hookctx: os.Getppid and defaultAncestors on the host path) and
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
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

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
	markHookReplied()

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
	b, err := os.ReadFile(path) //nolint:gosec // G703: reads the user's own local file with the user's own rights
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
// `observer run`. Any failure falls through to plain approval, except under
// guard enforcement, where a failure (config, unparseable payload, guard
// that cannot be built) blocks with a reason (hookFailClosed, section 5.7).
func handleClaudeCodePreTool(stdin io.Reader, stdout, stderr io.Writer, label, configPath string) {
	// SR27-D2: a PreToolUse body carries the tool's whole input (a Write's
	// file content, an Edit's new_string), so it can legitimately exceed
	// the default bound. Read with the larger prompt-submit bound AND
	// detect truncation: a truncated body fails to parse, and an
	// unparseable body must never reach the guard's approve-if-unevaluable
	// path while the guard is enforcing.
	body, truncated := readHookBodyDetectTruncation(stdin, promptSubmitBodyLimit)
	// The one trim of this receiver's bytes (FU-161; claudeCodeHookPayload
	// already strips it from the stream, a direct caller may not): the
	// bytes the guard decodes are the bytes judged valid below.
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	fmt.Fprintf(stderr, "observer-hook: event=%s received bytes=%d truncated=%v at=%s\n",
		label, len(body), truncated, time.Now().UTC().Format(time.RFC3339))

	// Section 5.7: under enforcement an unreadable or missing explicit
	// config fails closed (FU-185).
	cfg, stop, cfgErr := loadGateConfig(configPath, body, stderr)
	if stop {
		return
	}

	if truncated {
		enforcing := cfgErr == nil && cfg.Guard.Enabled && cfg.Guard.Mode == "enforce"
		if hook.HandleTruncatedPreTool(label, enforcing, stdout, stderr) {
			markHookReplied()
			return
		}
	}
	if hookPayloadUnparseable(body) && hookFailClosed(guardposture.KindUnparseable, body) {
		return
	}

	// Guard seam (guard spec §3.2 seam 1, G4): evaluate BEFORE the
	// rewrite decision. A deny/ask emission replaces the reply
	// entirely (HandleGuarded wrote it); an allow/flag emission falls
	// through to the normal approve/rewrite path with the verdict
	// record deferred until after that reply (§6.4 reply-first).
	// A nil guard is fail-open (unguarded pre-tool, the pre-G4
	// behavior) unless this invocation's plan fails closed (guard
	// enforcement in force, section 5.7): then it blocks with a reason.
	var recordAfterReply func()
	// A flag's developer notice rides the approve/rewrite reply below
	// (the binding's WarnField: Claude Code's systemMessage).
	var warnField, warn string
	if cfgErr == nil && cfg.Guard.Enabled && cfg.Guard.Mode != "off" {
		if g := buildHookGuard(cfg, stderr); g != nil {
			// Review M2-11: a block is marked decided right after its reply
			// and before persist, so a panic in persist can never add an
			// allow on top of it.
			// The security pillar's facts and the dirty-marker raise, as
			// on every other tool gate (hook_security.go; lane sec-gate2).
			enrich := securityToolGateEnrich(configPath, models.ToolClaudeCode, "PreToolUse", hookSecurityAliases(cfg, cfgErr))
			res := hook.HandleGuardedEnriched(
				label, body, g, makeGuardPersist(cfg, g, label, stderr), markHookDecided, enrich, stdout, stderr,
			)
			recordAfterReply, warnField, warn = res.RecordAfterReply, res.WarnField, res.Warn
			// JSON whose fields the gate reads do not decode cannot be
			// judged: under enforcement it fails closed here, never the
			// approve below (FU-161).
			if res.Undecodable && hookFailClosed(guardposture.KindUnparseable, body) {
				return
			}
			if res.Replied {
				// P2-1: HandleGuarded already wrote the block/ask
				// reply above (its own doc comment: "reply went out
				// first") — mark it so a panic in the effort capture
				// below can never make recoverHookPanic write a
				// second JSON object on top of it.
				markHookReplied()
				// Still capture effort — the turn happened even though
				// the tool call was blocked/deferred.
				recordClaudecodeEffort(body, "PreToolUse", label, configPath, stderr)
				return
			}
		} else if hookFailClosed(guardposture.KindGuardInit, body) {
			return
		}
	}
	// Guard and the commit gate allowed the call: an agent commit's trailer
	// marker is written now, before the reply lets the commit run (audit
	// finding F3; a no-op unless the enrich step held one).
	provenanceAgentCommitAllowed()

	binary, binErr := absoluteBinaryPath()
	rewritten, newCmd, reason := decidePreToolRewrite(body, cfg, cfgErr, binary, binErr, runtime.GOOS)
	if rewritten && hookctx.Process().Path() == hookctx.PathDaemon {
		// A command relayed out of a sandbox box runs IN the box, where
		// `observer run` has no database to record into (the capture relay,
		// lane sbx-p2): pass it through unwrapped.
		rewritten, newCmd, reason = false, "", "sandboxed-relay"
	}

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
	_ = json.NewEncoder(stdout).Encode(hook.WithWarnField(reply, warnField, warn))
	markHookReplied()
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
	// Section 5.7: [guard].strict is implied for a gate hook under
	// enforcement, so the guard's own internal-error wrapper denies too.
	if hookPlanFailsClosed() {
		cfg.Guard.Strict = true
	}
	g, err := hookGuardNew(guard.Options{Config: cfg.Guard, Home: home, Notifier: notify.NewDesktop(), PackRules: securityRulesWithSwitches(cfg.Security, securityHookPackRules(hookSecurityConfigPath))})
	if err != nil {
		fmt.Fprintf(stderr, "observer-hook: guard construction failed (running unguarded): %v\n", err)
		return nil
	}
	for _, issue := range g.LoadIssues() {
		fmt.Fprintf(stderr, "observer-hook: guard policy issue: %s\n", issue)
	}
	// Agent Access P4 hook deny (doc3 §12.6): answer R-306/R-307 from the
	// compiled node table the daemon cached beside the org-bundle cache —
	// one file read, no DB, no org fetch; absent/disabled = no lookup
	// (fail-open, exactly the pre-P4 hook).
	if fn := hookMCPAccessLookup(cfg); fn != nil {
		g.SetMCPAccessLookup(fn)
	}
	// R-112 to R-114 (D-761): git aliases resolve from the table the daemon
	// publishes beside the DB (one file read, only when a git command names
	// a subcommand that is not a git builtin); the hook never runs git.
	g.SetGitAliasLookup(fileGitAliasLookup(gitalias.Path(cfg.Observer.DBPath), nil))
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
	// Org access grants (request-grants G3): the org's signed, time-bound
	// exceptions, read from the SAME re-verified cache the daemon reads and
	// counted through the same conditional UPDATE, so a hook process and
	// the daemon racing on a grant's last use cannot both win. Lazy DB open
	// on the blocking path only; any failure is "no grant".
	g.SetOrgGrantClaim(newOrgGrantClaim(hookOrgGrantOpener(cfg.Observer.DBPath), cfg.Observer.Hooks.HookTimeout()))
	// Request-grants G4: the org-locked deny line links the node request
	// form under the dashboard origin (the daemon's guard stamps the same).
	g.SetRequestAccessBase(requestAccessBase(cfg))
	// T-519: an exhausted managed budget stops this hook's prompt or tool
	// call, from the decision the daemon publishes beside the DB (one file
	// read; no DB, no spend measured here). Fail open on the transport only.
	// A node whose [org_client] is off has no publisher (start.go builds the
	// budget service only with an org client), so a file beside its DB is a
	// leftover and is not read at all (D-359, review P3-05).
	if cfg.OrgClient.Enabled {
		g.SetHookBudgetLookup(hookBudgetAdmissionLookup(cfg.Observer.DBPath, stderr))
	}
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
	// Pre-send marks (guard.PromptAlreadyJudged): a repeating prompt seam
	// (agy PreInvocation, before every model call) judges each prompt
	// once. Same lazy DB open; it only runs when the prompt has a finding.
	g.SetPromptPreSendLookup(func(sessionID, digest string, at time.Time) bool {
		database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
		if err != nil {
			return false
		}
		defer database.Close()
		lctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
		defer cancel()
		judged, err := store.New(database).PreSendPromptJudged(lctx, sessionID, digest, at)
		return err == nil && judged
	})
	// Stopped-conversation taint (guard.PromptSessionStopped): a seam whose
	// stop leaves the prompt in the conversation (agy PreInvocation abort)
	// asks it before every model call. Same lazy DB open; a failure is a
	// miss (the turn is judged on its own prompt).
	g.SetPromptSessionStopLookup(func(tool, sessionID string) []guard.PromptSessionStop {
		database, err := db.Open(context.Background(), db.Options{Path: cfg.Observer.DBPath})
		if err != nil {
			return nil
		}
		defer database.Close()
		lctx, cancel := context.WithTimeout(context.Background(), cfg.Observer.Hooks.HookTimeout())
		defer cancel()
		stops, err := store.New(database).PromptSessionStops(lctx, tool, sessionID)
		if err != nil {
			return nil
		}
		out := make([]guard.PromptSessionStop, 0, len(stops))
		for _, sp := range stops {
			out = append(out, guard.PromptSessionStop{RuleID: sp.RuleID, Severity: sp.Severity})
		}
		return out
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

// promptDialectsWithoutStdoutReply mirrors internal/hook/promptsubmit.go's
// promptDialect.reply==nil rows (Qoder, Cascade — see that file's
// promptDialects table doc comment): those two dialects signal a
// prompt-submit block PURELY via the process exit code and have NO
// stdout JSON channel for this event at all, not even on allow.
// recoverHookPanic (P2-1) consults this so a panic before any reply is
// written on one of these dialects leaves stdout empty instead of
// emitting a bare {"decision":"approve"} no such host parses — which
// is also why CLAUDE.md's "every dialect treats a bare decision:approve
// as an allow" over-claimed before this fix. Table-driven (CLAUDE.md
// rule 5) rather than a growing if/else so a future nil-reply dialect
// is a one-line addition.
var promptDialectsWithoutStdoutReply = map[string]bool{
	hook.PromptDialectQoder:   true,
	hook.PromptDialectCascade: true,
	// Kimi Code: exit-code block, EMPTY stdout on allow (any stdout is
	// appended to the model context).
	hook.PromptDialectKimiCode: true,
	// Kiro CLI: an exit-0 stdout is added to the model context, so a
	// recovered panic must leave stdout empty (the warn is plain text).
	hook.PromptDialectKiroCLI: true,
	// Dirac: an allow is an empty stdout (exit 0); a block is the cancel
	// object, written only when the guard blocks.
	hook.PromptDialectDirac: true,
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
	// A second prompt event on the same tool (Devin: Desktop Cascade's
	// pre_user_prompt AND the Devin CLI's UserPromptSubmit) is evaluated in
	// ITS binding's dialect, resolved from the registry (capability shape,
	// never the tool name).
	if event != promptEvent {
		if b, ok := resolveHookBinding(tool, event); ok && b.Cap == integration.HookCapPromptGate && hook.KnownPromptDialect(b.Dialect) {
			dialect, promptEvent = b.Dialect, event
		}
	}
	body, truncated := readHookBodyDetectTruncation(os.Stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	hook.DumpHookShape(tool, event, body)
	noteHookPayload(body)
	// Another surface that runs this tool's registration (the Antigravity
	// App and IDE on the agy hooks.json) is judged and recorded as its own
	// call (hook_surface.go, surface-gap W-2c).
	if rb, ok := resolveHookBinding(tool, event); ok && event == promptEvent {
		if surface, _, ok := hookSurfaceBinding(tool, rb, body); ok {
			tool, label = surface, surface
		}
	}
	evaluatePromptSubmitBody(tool, label, dialect, promptEvent, event, configPath, body, truncated, hookStdout)
}

// evaluatePromptSubmitBody is handlePromptSubmitOnlyHook over a payload
// already in hand (a rerouted foreign payload, rerouteForeignHook), replying
// on out.
func evaluatePromptSubmitBody(tool, label, dialect, promptEvent, event, configPath string, body []byte, truncated bool, out io.Writer) {
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	fullLabel := label
	if event != "" {
		fullLabel = label + ":" + event
	}
	if event != promptEvent {
		hook.HandlePromptAllow(dialect, fullLabel, bytes.NewReader(body), out, os.Stderr)
		markHookReplied()
		// Observe-family events (compaction, task) on this mechanism are
		// recorded after the allow reply (hook_observe.go).
		recordObserveBinding(context.Background(), tool, fullLabel, event, body, configPath, os.Stderr)
		return
	}

	// P2-1: from here on this invocation is evaluating dialect's own
	// prompt-submit contract — flip hookExpectsStdoutReply for the two
	// exit-code-only dialects so a pre-reply panic's recover doesn't
	// emit JSON such a host never parses (see
	// promptDialectsWithoutStdoutReply's doc comment).
	setHookExpectsStdoutReply(!promptDialectsWithoutStdoutReply[dialect])

	cfg, stop, cfgErr := loadGateConfig(configPath, body, os.Stderr)
	if stop {
		return
	}
	if !truncated && hookPayloadUnparseable(body) && hookFailClosed(guardposture.KindUnparseable, body) {
		return
	}
	// The next-prompt org budget notice rides this dialect's user-visible
	// reply field when it has one (hook_budgetnotice.go).
	var stdout io.Writer = out
	if cfgErr == nil {
		stdout = wrapBudgetNotice(out, dialect, cfg.Observer.DBPath, time.Now())
		// A prompt is node activity: the daemon's policy-freshness
		// checker watches this stamp (P2, nodeactivity.go).
		_ = budgetwarnfile.TouchActivity(cfg.Observer.DBPath)
	}
	handled := false
	var recordAfterReply func()
	exitCode := 0
	if cfgErr == nil && promptGuardEnabled(cfg) {
		if g := buildHookGuard(cfg, os.Stderr); g != nil {
			handled, recordAfterReply, exitCode = hook.HandlePromptSubmitGuarded(
				tool, dialect, promptEvent, body, truncated, g,
				makePromptGuardPersist(cfg, g, tool, fullLabel, os.Stderr), stdout, os.Stderr,
			)
			// A prompt payload the dialect cannot decode was not judged:
			// under enforcement it fails closed, never the allow below
			// (FU-161).
			if !handled && hook.PromptPayloadUndecodable(dialect, body) && hookFailClosed(guardposture.KindUnparseable, body) {
				return
			}
			if handled {
				// P2-1: whatever this dialect's wire contract required
				// (a JSON reply, or deliberately nothing) has ALREADY
				// happened synchronously inside the call above, and
				// exitCode is now the fully-decided verdict — record
				// both BEFORE recordAfterReply/hookOSExit so a panic
				// in either can never overwrite a decided block with
				// an allow, nor double-write a reply on top of one
				// already sent.
				markHookDecided(exitCode)
			}
		} else if hookFailClosed(guardposture.KindGuardInit, body) {
			return
		}
	}
	if !handled {
		// Guard off/disabled/misconstructed, or no prompt found: the
		// dialect's own allow reply (with forensics). For most dialects
		// that is the approve-only reply this event always got; a host
		// with a strict output schema gets its own shape.
		hook.HandlePromptAllow(dialect, fullLabel, bytes.NewReader(body), stdout, os.Stderr)
		markHookReplied()
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
		hookExit(exitCode)
	}
}

// hookOSExit is the process-exit seam for the exit-code-signalled
// prompt-submit blocks (Qoder / Poolside / Cascade — and, since the
// 2026-09-07 live correction, Claude Code). Production is os.Exit;
// in-process tests substitute a recorder so a block does not end the
// test binary.
var hookOSExit = os.Exit

// hookExitProcess is the one way a decided verdict ends the process: it
// writes the invocation's armed activity record (flushHookActivity), which
// os.Exit would otherwise skip, and exits through hookOSExit. A blocking or
// fail-closed call therefore still counts as hook activity (R-188 F4).
func hookExitProcess(code int) {
	flushHookActivity()
	hookOSExit(code)
}

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
	handleClaudeCodeUserPromptSubmitFrom(ctx, os.Stdin, label, configPath)
}

// handleClaudeCodeUserPromptSubmitFrom is handleClaudeCodeUserPromptSubmit
// over an explicit payload stream (the dispatcher's peeked stdin).
func handleClaudeCodeUserPromptSubmitFrom(ctx context.Context, stdin io.Reader, label, configPath string) {
	body, truncated := readHookBodyDetectTruncation(stdin, promptSubmitBodyLimit)
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	cfg, stop, cfgErr := loadGateConfig(configPath, body, os.Stderr)
	if stop {
		return
	}
	if !truncated && hookPayloadUnparseable(body) && hookFailClosed(guardposture.KindUnparseable, body) {
		return
	}
	// The next-prompt org budget notice (hook_budgetnotice.go): Claude Code
	// renders the reply's top-level systemMessage to the user.
	var stdout io.Writer = hookStdout
	if cfgErr == nil {
		stdout = wrapBudgetNotice(hookStdout, hook.PromptDialectClaudeCode, cfg.Observer.DBPath, time.Now())
		// A prompt is node activity (policy-freshness trigger, P2).
		_ = budgetwarnfile.TouchActivity(cfg.Observer.DBPath)
	}

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
				body, truncated, g, makePromptGuardPersist(cfg, g, models.ToolClaudeCode, label, os.Stderr), stdout, os.Stderr,
			)
			// FU-161: an undecodable prompt payload fails closed under
			// enforcement instead of reaching the approve below.
			if !handled && hook.PromptPayloadUndecodable(hook.PromptDialectClaudeCode, body) && hookFailClosed(guardposture.KindUnparseable, body) {
				return
			}
			if handled {
				// P2-1 (docs/audits/codebase-audit-2026-09-16.md
				// adversarial review): record the reply + the decided
				// exit code BEFORE recordAfterReply and the capture
				// closure below, both of which can panic. Without
				// this, a panic in the capture closure hit
				// recoverHookPanic's OLD unconditional exitFn(0) and
				// silently turned an already-decided BLOCK
				// (exitCode==2, its JSON reply already on stdout)
				// into an ALLOW.
				markHookDecided(exitCode)
			}
		} else if hookFailClosed(guardposture.KindGuardInit, body) {
			return
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
		_ = json.NewEncoder(stdout).Encode(hook.ClaudeCodePromptApproveReply())
		markHookReplied()
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
		st := store.New(database)
		// The same prompt typed again later in the session is its own row;
		// the same event delivered again is not (B7, promptOccurrenceID).
		ev.SourceEventID = resolvePromptOccurrence(insertCtx, st, ev.SourceFile, ev.SourceEventID, ev.Timestamp)
		if _, err := st.Ingest(insertCtx, []models.ToolEvent{ev}, nil, store.IngestOptions{}); err != nil {
			fmt.Fprintf(os.Stderr, "observer-hook: %s insert: %v\n", label, err)
		}
	}()
	// A blocking verdict on Claude Code's dialect is signalled by the
	// process exit code (blockExitCode:2) — only after the capture
	// above, and only when the guard actually handled + blocked.
	if handled && exitCode != 0 {
		hookExit(exitCode)
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
	// The security feedback seam (lane sec-h, security_feedback.go): while
	// security.feedback is not selected the reply is the bare approve,
	// byte for byte.
	reply, _ := json.Marshal(hook.Decision{Decision: "approve"})
	reply = append(reply, '\n')
	securityPostFeedback(context.Background(), stdout, models.ToolClaudeCode, "PostToolUse", body, reply, configPath)
	markHookReplied()

	recordClaudecodeEffort(body, "PostToolUse", label, configPath, stderr)
	// S10-SKILLS: a Skill-tool invocation snapshots the invoked SKILL.md
	// (a no-op for every other tool; see hook_skillsnap.go).
	recordClaudeSkillSnapshot(body, "PostToolUse", label, configPath, stderr)
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
	// Defence in depth (FU-161): the receiver strips the BOM, a direct
	// caller may not.
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF}), &p); err != nil {
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
	// FU-163: a native Windows hook skips the rewrite. Claude Code runs the
	// rewritten command in Git Bash (MSYS). The native backslash binary path
	// is read there as escapes (`C:\Users\...\observer.exe` became
	// `C:Users...observer.exe`, so every rewritten call exited 127), and
	// the slash form, although it execs, does not keep the command's argv:
	// observer.exe re-encodes the arguments as a Windows command line and an
	// MSYS child (printf, grep, cat, sh) re-parses it with its own quoting
	// and glob rules, so `printf '%s|' "c'd" '*.go'` reached printf as one
	// mangled argument, and a shell script (`./build.sh`) cannot be exec'd
	// by observer.exe at all (127). Checked from Git Bash 5.2 on Windows 11
	// on 2026-10-29. Shell-output compression is unavailable there; capture
	// and the guard are unaffected (they do not rewrite the command).
	//
	// FU-186: a Windows-to-WSL twin (claude-code-wsl) runs this Windows
	// observer.exe from a distro's Linux bash through WSL interop, so the
	// shell is not Git Bash: the payload cwd is a POSIX path. The rewrite is
	// skipped there too (the command would name observer.exe, which bash
	// runs only as a Windows program through interop, with the same argv
	// re-encoding), but the reason says which case it is.
	if hostOS == "windows" {
		if strings.HasPrefix(p.Cwd, "/") && !looksWindowsPath(p.Cwd) {
			return false, "", "wsl-interop"
		}
		return false, "", "windows-shell"
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

// claudeActionBuilder takes a raw Claude Code hook payload and returns a
// ToolEvent ready for insertion. ok=false means "skip this fire" (e.g.
// missing required field). Builders never block — they parse, validate,
// and return.
type claudeActionBuilder func(body []byte) (models.ToolEvent, bool)

// handleClaudeCodeActionEvent is the shared dispatch for Tier 1 hook
// events that ingest one row each. Reads stdin, replies approve, opens
// the configured DB, calls build(body), and inserts the resulting
// ToolEvent. All errors log to stderr and never block the host (spec P1).
func handleClaudeCodeActionEvent(ctx context.Context, stdin io.Reader, label, configPath string, build claudeActionBuilder) {
	body, _ := io.ReadAll(io.LimitReader(stdin, defaultHookBodyLimit))
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})
	_ = json.NewEncoder(hookStdout).Encode(hook.Decision{Decision: "approve"})
	markHookReplied()

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
	// to a single row HERE; the prompt handler then numbers a later repeat
	// (resolvePromptOccurrence, B7), so only a re-delivery collapses.
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
		// MHC-4: tool_input is a JSON object — RawJSON scrubs each
		// string value in isolation and re-marshals, so redaction can
		// never corrupt the stored JSON the way String's line-oriented
		// regexes can on compact JSON (see scrub.ScrubForward's doc
		// comment for the failure mode this avoids).
		ev.RawToolInput = scrub.New().RawJSON(p.ToolInput)
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
	// per-tool drilldown. RawJSON (not String) so redaction can't
	// corrupt this structurally-nested JSON (MHC-4).
	if raw, err := json.Marshal(p.ToolCalls); err == nil {
		ev.RawToolInput = scrub.New().RawJSON(raw)
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
		// RawJSON, not String — tool_input is JSON (MHC-4).
		ev.RawToolInput = scrub.New().RawJSON(p.ToolInput)
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
		// RawJSON, not String — tool_input is JSON (MHC-4).
		ev.RawToolInput = scrub.New().RawJSON(p.ToolInput)
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
	markHookReplied()

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
	// No context reaches this pure reply builder (its golden test calls it
	// with the payload alone): the host default of the seam is what the
	// hook process read before it.
	root := hookctx.Process().Getenv("OBSERVER_CLAUDE_WORKTREE_ROOT")
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
