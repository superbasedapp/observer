package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Part B item 3 (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §10 item 11, phase-2 review): `observer doctor <tool> --probe-hook`.
// Fires a synthetic, obviously-fake secret-shaped prompt through the
// REGISTERED hook command exactly as the host tool would invoke it —
// `<this binary> hook <tool> <event> [--config <path>]`, the same
// argv register.go writes — and reports what actually came back:
// blocked (guard evaluated and denied/asked, as PromptLaneHook
// claims), allowed (either the guard is off/misconfigured, or this
// tool has no wired receiver at all — the BLOCK-1 failure class this
// whole build exists to catch), or no-dialect (this tool has no known
// prompt-submit wire shape to probe).
//
// probeHookSpecs is table-driven (CLAUDE.md rule 5), keyed by the
// hookReceivers dispatch tool string — mirrors cmd/observer/hook.go's
// own dispatch table without importing it circularly (hook.go's table
// is unexported and lives in `main` already; this file is also
// `main`, so it reads that same table directly — no duplication).

// probeHookPayload builds the synthetic JSON body for one dialect. The
// fake secret ("sk-ant-api03-DOCTORPROBEFAKEKEYNEVERUSED...") is
// obviously non-functional — never a real credential shape reused
// anywhere else, so a probe can never be mistaken for live traffic in
// any log it touches.
const probeFakeSecret = "sk-ant-api03-DOCTORPROBEFAKEKEYNEVERUSEDXXXXXXXXXXXXXXXX" //nolint:gosec // G101: an obviously-fake, non-functional probe marker never used as a real credential — this doc comment and the const name both say so.

func probeHookSessionID() string {
	return "observer-doctor-probe-" + time.Now().UTC().Format("20060102T150405.000000000Z")
}

func probeHookPayload(dialect, sessionID string) []byte {
	prompt := "please use this test key: " + probeFakeSecret
	switch dialect {
	case hook.PromptDialectClaudeCode:
		body, _ := json.Marshal(map[string]string{
			"session_id": sessionID, "user_prompt": prompt, "hook_event_name": "UserPromptSubmit",
		})
		return body
	case hook.PromptDialectCursor:
		body, _ := json.Marshal(map[string]string{
			"conversation_id": sessionID, "prompt": prompt,
		})
		return body
	case hook.PromptDialectCascade:
		// Windsurf/Devin Desktop Cascade: nested tool_info.user_prompt,
		// no session_id field at all — trajectory_id is the
		// session-scoping key (see extractCascadePrompt).
		body, _ := json.Marshal(map[string]any{
			"agent_action_name": "pre_user_prompt",
			"trajectory_id":     sessionID,
			"tool_info":         map[string]string{"user_prompt": prompt},
		})
		return body
	case hook.PromptDialectCommandCode:
		// commandcode's Mods SDK transformInput carries no session id
		// at all — only {text} (see extractCommandCodePrompt).
		body, _ := json.Marshal(map[string]string{"text": prompt})
		return body
	default: // PromptDialectTopLevelBlock, PromptDialectGemini, PromptDialectQoder, PromptDialectPoolside, PromptDialectZcode: {"prompt","session_id"}
		body, _ := json.Marshal(map[string]string{
			"session_id": sessionID, "prompt": prompt,
		})
		return body
	}
}

// probeHookOutcome classifies the subprocess's stdout reply against
// its own dialect's documented blocking shape (internal/hook/promptsubmit.go).
// NOT called for a dialect in probeHookExitCodeDialects (Qoder,
// Cascade, Claude Code) — those write no stdout reply on a block; runProbeHook checks
// the process EXIT CODE for them instead, before ever reaching here.
func probeHookOutcome(dialect string, stdout []byte) (blocked bool, detail string) {
	var reply map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(stdout), &reply); err != nil {
		return false, fmt.Sprintf("reply is not valid JSON: %v (%q)", err, string(stdout))
	}
	switch dialect {
	case hook.PromptDialectClaudeCode:
		// LIVE CORRECTION 2026-09-07: Claude Code blocks UserPromptSubmit
		// via exit code 2 only (probeHookExitCodeDialects), so runProbeHook
		// never reaches here for a block; a stdout reply on this dialect is
		// by construction the allow/warn envelope. `permissionDecision` is
		// PreToolUse-only and must never be read as a block signal.
		return false, "hookSpecificOutput allow/warn envelope (a block is exit code 2, checked before stdout)"
	case hook.PromptDialectCursor:
		cont, hasCont := reply["continue"].(bool)
		return hasCont && !cont, fmt.Sprintf("continue=%v", cont)
	case hook.PromptDialectGemini:
		decision, _ := reply["decision"].(string)
		return decision == "deny", "decision=" + decision
	case hook.PromptDialectZcode:
		cont, hasCont := reply["continue"].(bool)
		return hasCont && !cont, fmt.Sprintf("continue=%v", cont)
	case hook.PromptDialectCommandCode:
		action, _ := reply["action"].(string)
		return action == "handled", "action=" + action
	default: // PromptDialectTopLevelBlock, PromptDialectPoolside: both use {"decision":"block",...}
		decision, _ := reply["decision"].(string)
		return decision == "block", "decision=" + decision
	}
}

// hookMechanismDialect maps a registry HookMechanism (internal/
// integration) to the wire DIALECT + EVENT `observer hook <tool>
// <event>` speaks for it — DATA, not a tool-name switch (CLAUDE.md
// rule 3/5). B3 (phase-3a review) replaced the old
// `switch tool { case "codex", "droid", "qwen-code": ... }` dispatch
// with this table: a probe candidate is now "this tool's registry row
// names a mechanism this table has a wired dialect for", the same
// shape-not-identity discipline hookSupported/mcpSupported/
// routeSupported already use (cmd/observer/init.go) — a future
// adapter that reuses an EXISTING mechanism (e.g. a 4th
// top-level-block vendor) gets probing for free with no edit here.
// Kept in sync by hand with internal/hook/promptsubmit.go's own
// promptDialects table and cmd/observer/hook.go's hookReceivers
// dispatch (there is no single source of truth today spanning all
// three — a documented, not automated, invariant).
type hookDialectEntry struct {
	dialect string
	// cliEvent is the argv event `observer hook <tool> <event>` the
	// REGISTERED command actually invokes — what runProbeHook execs.
	cliEvent string
	// registryEvent is the key the writer's own hooks-block/AlreadySet
	// bookkeeping uses — identical to cliEvent for every mechanism
	// except Claude Code, whose CLI arg is KEBAB-case (hookEventArg's
	// translation — CLAUDE.md notes Codex forwards CamelCase as-is,
	// "no kebab-case translation as observer's CLI does for
	// claude-code") even though the JSON hooks."UserPromptSubmit" key
	// and registerClaudeCode's own AlreadySet entries stay PascalCase.
	// checkHookRegistration must compare against THIS field, or a
	// genuinely-registered Claude Code hook would never match and every
	// probe would misreport NOT REGISTERED.
	registryEvent string
}

// hookMechanismDialect maps a registry HookMechanism (internal/
// integration) to the wire shape `observer hook <tool> <event>` speaks
// for it — DATA, not a tool-name switch (CLAUDE.md rule 3/5). B3
// (phase-3a review) replaced the old
// `switch tool { case "codex", "droid", "qwen-code": ... }` dispatch
// with this table: a probe candidate is now "this tool's registry row
// names a mechanism this table has a wired dialect for", the same
// shape-not-identity discipline hookSupported/mcpSupported/
// routeSupported already use (cmd/observer/init.go) — a future
// adapter that reuses an EXISTING mechanism (e.g. a 4th
// top-level-block vendor) gets probing for free with no edit here.
// Kept in sync by hand with internal/hook/promptsubmit.go's own
// promptDialects table and cmd/observer/hook.go's hookReceivers
// dispatch (there is no single source of truth today spanning all
// three — a documented, not automated, invariant).
var hookMechanismDialect = map[integration.HookMechanism]hookDialectEntry{
	integration.HookClaudeSettings: {hook.PromptDialectClaudeCode, "user-prompt-submit", "UserPromptSubmit"},
	integration.HookCodexConfig:    {hook.PromptDialectTopLevelBlock, "UserPromptSubmit", "UserPromptSubmit"},
	integration.HookFactoryJSON:    {hook.PromptDialectTopLevelBlock, "UserPromptSubmit", "UserPromptSubmit"},
	integration.HookQwenSettings:   {hook.PromptDialectTopLevelBlock, "UserPromptSubmit", "UserPromptSubmit"},
	integration.HookGeminiSettings: {hook.PromptDialectGemini, "BeforeAgent", "BeforeAgent"},
	integration.HookCursor:         {hook.PromptDialectCursor, "beforeSubmitPrompt", "beforeSubmitPrompt"},
	// Part B item 2 (phase-3a): the documented long-tail vendors.
	integration.HookQoderJSON:      {hook.PromptDialectQoder, "UserPromptSubmit", "UserPromptSubmit"},
	integration.HookPoolsideYAML:   {hook.PromptDialectPoolside, "UserPromptSubmit", "UserPromptSubmit"},
	integration.HookCascadeJSON:    {hook.PromptDialectCascade, "pre_user_prompt", "pre_user_prompt"},
	integration.HookCommandCodeMod: {hook.PromptDialectCommandCode, "transformInput", "transformInput"},
	// zcode: AutoWired stays false on its registry row (no register*
	// writer exists), so runProbeHook never reaches the registration
	// check for it — but the dialect/event ARE known (receiver built
	// and tested), so it still belongs in this table; the AutoWired
	// gate in runProbeHook is what renders it "documented, not
	// auto-wired" instead of silently no-dialect.
	integration.HookZcodeJSON: {hook.PromptDialectZcode, "UserPromptSubmit", "UserPromptSubmit"},
}

// probeHookDialectFor resolves the (dialect, cliEvent) pair a tool
// speaks for THIS build's --probe-hook, off the tool's OWN registry
// row (internal/integration) rather than a bespoke tool-name switch.
// ok=false means either the tool has no registry row at all, or its
// Hook.Mechanism has no entry in hookMechanismDialect — this build
// has no known prompt-submit wire shape for it (PromptLaneNone/
// ProbeRequired/ProxyOnly rows, or Mechanism==HookNone) — the probe
// cannot run, and doctor reports that honestly rather than guessing a
// shape.
func probeHookDialectFor(tool string) (dialect, event string, ok bool) {
	c, ok := integration.For(tool)
	if !ok {
		return "", "", false
	}
	d, ok := hookMechanismDialect[c.Hook.Mechanism]
	if !ok {
		return "", "", false
	}
	return d.dialect, d.cliEvent, true
}

// hookRegistrationState is checkHookRegistration's verdict on a
// tool's CURRENT on-disk hook config.
type hookRegistrationState int

const (
	// hookRegRegistered: the exact command this probe is about to run
	// is ALREADY the one registered in the vendor's own config file
	// (or the tool is covered another way this repo recognizes, e.g.
	// the Claude Code plugin skip path).
	hookRegRegistered hookRegistrationState = iota
	// hookRegNotRegistered: nothing observer-owned occupies this event
	// yet (a fresh install, or the operator never ran `observer
	// init`/hasn't restarted the daemon since this tool was detected).
	hookRegNotRegistered
	// hookRegConflict: a non-observer hook already occupies the event
	// slot — observer's own hook is therefore also NOT registered, but
	// the remedy is different (needs --force to take over the slot).
	hookRegConflict
)

// checkHookRegistration reports whether tool's prompt-submit hook is
// ACTUALLY registered in its own config file today, by asking the
// SAME writer `observer init`/the auto-register loop would use
// (hook.Registry.Register) in DryRun mode — nothing is written to
// disk. This is the seam B3 (phase-3a review) closes: before this fix,
// runProbeHook invoked `observer hook <tool> <event>` unconditionally,
// which exercises the in-process receiver directly regardless of
// whether the vendor's own config file would ever call it — a false
// green for a host that was never registered at all (a hand-authored
// probe config, or simply a tool `observer init` was never run
// against, reported "BLOCKED — the guard is live" exactly like a
// genuinely wired one). Reusing Register's own conflict/idempotency
// logic — rather than re-parsing each vendor's file format here —
// keeps this correct for every writer shape (JSON/TOML/YAML/an
// embedded TS module) without duplicating per-format parsing; the
// registered command it confirms is byte-identical to
// `<binary> hook <tool> <event> [--config <path>]` because that
// equality is exactly what populates Register's own AlreadySet list.
//
// registryEvent (NOT the CLI-invocation event) is what's compared
// against Register's AlreadySet — see hookDialectEntry's doc comment
// for why those two differ for Claude Code.
func checkHookRegistration(binary, configPath, tool, registryEvent string) (state hookRegistrationState, detail string, err error) {
	reg, regErr := hook.NewRegistry(hookRegistrationOptions(binary, configPath))
	if regErr != nil {
		return hookRegNotRegistered, "", regErr
	}
	res := reg.Register(tool)
	switch {
	case res.Skipped:
		return hookRegRegistered, "already covered by " + res.SkipReason, nil
	case res.Error != nil:
		return hookRegConflict, res.Error.Error(), nil
	case containsString(registryEvent, res.AlreadySet):
		return hookRegRegistered, res.ConfigPath, nil
	default:
		return hookRegNotRegistered, res.ConfigPath, nil
	}
}

// hookHomeCheck is checkHookRegistrationHomes' per-home result: tool's
// registration state as seen from ONE config-file home — either
// "native" (the daemon's own OS, checkHookRegistration(tool, ...)) or
// "bridge" (the cross-OS "<tool>-windows" target, a WSL daemon writing
// into a Windows-side .claude/.cursor/.codex/etc — see CLAUDE.md's
// "Don't try to bridge cross-OS hook capture at the storage layer").
//
// B4 fix (docs review finding): before this type existed,
// checkHookRegistration's callers only ever asked Register about the
// BASE tool id — never its "-windows" bridge variant — so on the very
// shape this repo is built to run on (a WSL daemon with the AI tool
// itself running Windows-native), `observer guard prompt status` and
// `observer doctor <tool> --probe-hook` could only ever see the
// NATIVE config location, which usually doesn't exist or doesn't hold
// the bridge command, and would misreport a correctly cross-OS-wired
// tool as NOT REGISTERED or CONFLICT.
type hookHomeCheck struct {
	// home is "native" or "bridge".
	home string
	// tool is the exact hook.Registry.Register target this check asked
	// about: the base tool id for home=="native", tool+"-windows" for
	// home=="bridge".
	tool   string
	state  hookRegistrationState
	detail string
	err    error
}

// checkHookRegistrationHomes iterates every home checkHookRegistration
// can meaningfully probe for tool: the native target always, plus the
// cross-OS "<tool>-windows" bridge target when it is BOTH a real,
// AutoWired, CrossOSBridge-capable registry row (hookSupported, the
// exact predicate `observer init` itself uses to decide whether it can
// write that target — reused here rather than hand-rolled per
// CLAUDE.md module-boundary rule 1) AND plausibly reachable from this
// process (windowsHookHomeDetected).
func checkHookRegistrationHomes(binary, configPath, tool, registryEvent string) []hookHomeCheck {
	homes := []hookHomeCheck{checkHookRegistrationHome("native", tool, binary, configPath, registryEvent)}
	winTool := tool + "-windows"
	if hookSupported(winTool) && windowsHookHomeDetected(binary, winTool) {
		homes = append(homes, checkHookRegistrationHome("bridge", winTool, binary, configPath, registryEvent))
	}
	return homes
}

func checkHookRegistrationHome(home, tool, binary, configPath, registryEvent string) hookHomeCheck {
	state, detail, err := checkHookRegistration(binary, configPath, tool, registryEvent)
	return hookHomeCheck{home: home, tool: tool, state: state, detail: detail, err: err}
}

// hookRegistrationOptions builds the hook.Options checkHookRegistration
// and windowsHookHomeDetected use to construct their hook.Registry — a
// seam (package var, mirroring internal/hook's own allHomes /
// homeOwnedByCurrentWindowsUser test vars and
// internal/platform/crossmount's windowsUserProbe / windowsUserIsWSL)
// so tests can inject explicit HomeDir / WindowsClaudeHome /
// WindowsCursorHome / WindowsCodexHome / WSLDistro overrides that drive
// the cross-OS bridge branch deterministically. Real crossmount
// ownership auto-detection only ever succeeds from INSIDE WSL
// (internal/platform/crossmount's WindowsUserName shells out to the
// Windows-side cmd.exe over the WSL interop bind — always "" on a
// native Windows or Linux process), so a test running on this
// repo's own dev box (native Windows) cannot otherwise exercise that
// branch at all. Production leaves every override unset — pure
// auto-detect, exactly like `observer init`/the auto-register loop —
// and DryRun stays hardcoded true unconditionally regardless of what a
// test overrides, so this seam can never turn the probe into a writer.
var hookRegistrationOptions = func(binary, configPath string) hook.Options {
	return hook.Options{BinaryPath: binary, ConfigPath: configPath, DryRun: true}
}

// windowsHookHomeDetected reports whether hook.Registry can actually
// resolve a Windows-side config directory for winTool (e.g.
// "claude-code-windows") on THIS host — i.e. whether the cross-OS
// bridge target is not just capability-advertised but genuinely
// reachable: a crossmount-detected, ownership-verified Windows home,
// AND a resolvable WSL distro (the same Options.WSLDistro ->
// $WSL_DISTRO_NAME fallback every registerXWindows uses). Both gates
// matter: crossmount ownership succeeding says nothing about whether a
// distro name is available to build the `wsl.exe -d <distro> --`
// prefix with — a real WSL daemon started as a systemd user unit (see
// CLAUDE.md) may not inherit $WSL_DISTRO_NAME even though the cmd.exe
// interop probe that proves ownership works independently of it, and
// registerXWindows would then fail with "WSL distro unknown" — a
// precondition failure, not a real conflict — which checkHookRegistration
// would otherwise fold into a scary, misleading hookRegConflict.
//
// Reuses Registry.Installed() (the same detection `observer init`'s own
// target list and hook.Registry itself already trust) rather than
// re-deriving the per-vendor detectWindowsXHome logic here. Read-only:
// Installed() only stats directories, matching the DryRun contract this
// whole probe/status path must uphold.
func windowsHookHomeDetected(binary, winTool string) bool {
	opts := hookRegistrationOptions(binary, "")
	if opts.WSLDistro == "" && os.Getenv("WSL_DISTRO_NAME") == "" {
		return false
	}
	reg, err := hook.NewRegistry(opts)
	if err != nil {
		return false
	}
	return containsString(winTool, reg.Installed())
}

// hookHomeOverallState picks ONE overall verdict across every home
// checkHookRegistrationHomes probed for a tool, for callers (like
// runProbeHook) that need a single go/no-go rather than a per-home
// report. A tool wired through EITHER its native config or its
// cross-OS bridge is genuinely wired, so Registered on ANY home wins
// outright; otherwise Conflict beats NotRegistered (a real foreign
// hook is worse news than simply nothing being there yet); an error on
// one home never masks a good verdict on another.
func hookHomeOverallState(homes []hookHomeCheck) hookHomeCheck {
	rank := func(h hookHomeCheck) int {
		if h.err != nil {
			return -1
		}
		switch h.state {
		case hookRegRegistered:
			return 2
		case hookRegConflict:
			return 1
		default:
			return 0
		}
	}
	best := homes[0]
	for _, h := range homes[1:] {
		if rank(h) > rank(best) {
			best = h
		}
	}
	return best
}

// formatHookHomeVerdict renders one hookHomeCheck's verdict as
// human-readable text, shared by `observer guard prompt status`'s
// wired-clients section and `observer doctor --probe-hook`'s
// registration messaging. A tool wired ONLY through its cross-OS
// "-windows" bridge (the common WSL-daemon + Windows-native-tool
// shape) reads distinctly as "REGISTERED (bridge)", never collapsing
// into the same verdict text a native registration would produce.
func formatHookHomeVerdict(h hookHomeCheck) string {
	switch {
	case h.err != nil:
		return fmt.Sprintf("could not determine registration: %v", h.err)
	case h.state == hookRegRegistered && h.home == "bridge":
		return fmt.Sprintf("REGISTERED (bridge) at %s", h.detail)
	case h.state == hookRegRegistered:
		return fmt.Sprintf("REGISTERED (%s)", h.detail)
	case h.state == hookRegConflict:
		return fmt.Sprintf("CONFLICT — a non-observer hook occupies this event: %s", h.detail)
	default:
		return fmt.Sprintf("NOT REGISTERED (%s)", h.detail)
	}
}

// hookHomesSummary joins every home's formatHookHomeVerdict into one
// "<home>: <verdict>; <home>: <verdict>" string for messages that
// report on the whole set at once (runProbeHook's single diag.Check).
func hookHomesSummary(homes []hookHomeCheck) string {
	parts := make([]string, len(homes))
	for i, h := range homes {
		parts[i] = h.home + ": " + formatHookHomeVerdict(h)
	}
	return strings.Join(parts, "; ")
}

// probeHookExitCodeDialects names every dialect whose BLOCK signal is
// a bare process exit code with NO stdout reply at all (see
// promptDialect.blockExitCode, internal/hook/promptsubmit.go) — the
// value is the exit code a genuine block produces. runProbeHook must
// check the subprocess's exit code for these BEFORE treating a
// non-nil exec error as "probe failed to invoke": a legitimate block
// on one of these dialects IS a non-zero exit, which is otherwise
// indistinguishable from a real invocation failure.
var probeHookExitCodeDialects = map[string]int{
	hook.PromptDialectQoder:   2,
	hook.PromptDialectCascade: 2,
	// LIVE CORRECTION 2026-09-07: Claude Code ignores a JSON
	// `permissionDecision` on UserPromptSubmit; its block IS exit 2.
	hook.PromptDialectClaudeCode: 2,
}

// runProbeHook executes the doctor --probe-hook check for tool. binary
// is THIS process's own resolved path (absoluteBinaryPath) — the
// probe necessarily runs the CURRENT binary, which is what a fresh
// `observer init`/auto-register would have written into the tool's
// hook config; a stale registration pointing at a DIFFERENT binary
// path is a separate, already-covered concern (hook_checksums drift,
// `observer doctor hooks`), not this probe's job.
func runProbeHook(ctx context.Context, binary, configPath, tool string) diag.Check {
	name := "guard.prompt.probe:" + tool
	dialect, event, ok := probeHookDialectFor(tool)
	if !ok {
		return diag.Check{
			Name: name, Status: diag.StatusWarn,
			Message: fmt.Sprintf("no known prompt-submit dialect for %q — nothing to probe (see `observer adapters` PROMPT column)", tool),
		}
	}

	// B3 (phase-3a review): a mechanism whose registry row is
	// AutoWired:false (zcode today) has a tested receiver/dialect but
	// genuinely NO writer to check registration against — `observer
	// init` never reaches it (hookSupported requires AutoWired), so
	// "would the registered command block" is not a question this
	// probe can answer. Report that honestly as documented-but-not-
	// wired rather than either skipping silently or invoking the
	// receiver directly (which would be exactly the false green B3
	// closes).
	capRow, _ := integration.For(tool) // guaranteed ok: probeHookDialectFor already required it
	if !capRow.Hook.AutoWired {
		return diag.Check{
			Name: name, Status: diag.StatusWarn,
			Message: fmt.Sprintf("%s: prompt-submit dialect is built and tested, but documented, not auto-wired — no registration writer exists to check a live install against", tool),
		}
	}

	// B3: only invoke the hook receiver when the vendor's OWN config
	// file actually points at it — see checkHookRegistration's doc
	// comment for why this replaces the old "always invoke" behavior.
	// registryEvent (not the CLI-invocation event) is the bookkeeping
	// key Register's AlreadySet uses — see hookDialectEntry.
	//
	// B4: checked across every home checkHookRegistrationHomes can
	// probe (native + the cross-OS "-windows" bridge target), not just
	// the base tool id — a tool wired ONLY through its bridge config
	// (the common WSL-daemon + Windows-native-tool shape this repo
	// itself runs on) must read as genuinely registered, never a false
	// NOT REGISTERED/CONFLICT from a native-only check.
	registryEvent := hookMechanismDialect[capRow.Hook.Mechanism].registryEvent
	homes := checkHookRegistrationHomes(binary, configPath, tool, registryEvent)
	winner := hookHomeOverallState(homes)
	if winner.err != nil {
		return diag.Check{
			Name: name, Status: diag.StatusFail,
			Message: fmt.Sprintf("%s: could not determine hook registration status: %v", tool, winner.err),
		}
	}
	switch winner.state {
	case hookRegNotRegistered:
		return diag.Check{
			Name: name, Status: diag.StatusFail,
			Message: fmt.Sprintf("%s: NOT REGISTERED — no observer hook wired for %s on any checked home, so the prompt-submit guard never sees this tool's prompts (%s)", tool, event, hookHomesSummary(homes)),
			Details: []string{"remedy: " + autoRegisterRemediation(tool)},
		}
	case hookRegConflict:
		return diag.Check{
			Name: name, Status: diag.StatusFail,
			Message: fmt.Sprintf("%s: NOT REGISTERED — a non-observer hook already occupies %s on at least one checked home (%s)", tool, event, hookHomesSummary(homes)),
			Details: []string{"remedy: observer init --all --force (or the equivalent per-tool target) to take over the slot, then re-run this probe"},
		}
	}

	sessionID := probeHookSessionID()
	payload := probeHookPayload(dialect, sessionID)

	args := []string{"hook", tool, event}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := exec.CommandContext(probeCtx, binary, args...)
	c.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	runErr := c.Run()

	if probeCtx.Err() != nil {
		return diag.Check{
			Name: name, Status: diag.StatusFail,
			Message: fmt.Sprintf("probe timed out invoking `%s %s` — the hook receiver may be hung", binary, strings.Join(args, " ")),
		}
	}

	// Part B item 2 (phase-3a): an exit-code-only dialect (Qoder,
	// Cascade, and Claude Code since the 2026-09-07 live correction)
	// signals a block via the PROCESS exit code alone — a
	// non-nil runErr here is the EXPECTED shape of a genuine block,
	// not an invocation failure, so it must be checked before the
	// generic "runErr + empty stdout = failed to invoke" branch below
	// (which exists for the JSON-stdout dialects, where a non-zero
	// exit really would mean the receiver crashed).
	if wantCode, isExitCodeDialect := probeHookExitCodeDialects[dialect]; isExitCodeDialect {
		gotCode := 0
		var exitErr *exec.ExitError
		switch {
		case runErr == nil:
			gotCode = 0
		case errors.As(runErr, &exitErr):
			gotCode = exitErr.ExitCode()
		default:
			return diag.Check{
				Name: name, Status: diag.StatusFail,
				Message: fmt.Sprintf("probe failed to invoke `%s %s`: %v", binary, strings.Join(args, " "), runErr),
				Details: []string{"stderr: " + stderr.String()},
			}
		}
		if gotCode == wantCode {
			return diag.Check{
				Name: name, Status: diag.StatusOK,
				Message: fmt.Sprintf("%s: BLOCKED a synthetic secret (exit code %d) — the prompt-submit guard is live", tool, gotCode),
			}
		}
		remedy := "remedy: `observer init --all` (or the equivalent per-tool target) to register the hook, then re-run this probe. If already registered, check [guard]/[guard.prompt] with `observer guard prompt status`."
		return diag.Check{
			Name: name, Status: diag.StatusFail,
			Message: fmt.Sprintf("%s: ALLOWED a synthetic secret through (exit code %d, want %d) — the hook either isn't registered, or the guard isn't evaluating it", tool, gotCode, wantCode),
			Details: []string{remedy, "stdout: " + stdout.String(), "stderr: " + stderr.String()},
		}
	}

	if runErr != nil && stdout.Len() == 0 {
		return diag.Check{
			Name: name, Status: diag.StatusFail,
			Message: fmt.Sprintf("probe failed to invoke `%s %s`: %v", binary, strings.Join(args, " "), runErr),
			Details: []string{"stderr: " + stderr.String()},
		}
	}

	blocked, detail := probeHookOutcome(dialect, stdout.Bytes())
	if blocked {
		return diag.Check{
			Name: name, Status: diag.StatusOK,
			Message: fmt.Sprintf("%s: BLOCKED a synthetic secret (%s) — the prompt-submit guard is live", tool, detail),
		}
	}
	remedy := "remedy: `observer init --all` (or the equivalent per-tool target) to register the hook, then re-run this probe. If already registered, check [guard]/[guard.prompt] with `observer guard prompt status`."
	return diag.Check{
		Name: name, Status: diag.StatusFail,
		Message: fmt.Sprintf("%s: ALLOWED a synthetic secret through (%s) — the hook either isn't registered, or the guard isn't evaluating it", tool, detail),
		Details: []string{remedy, "stderr: " + stderr.String()},
	}
}

// probeHookToolCandidates is the set of tools `observer doctor
// --probe-hook` (with no tool argument) walks — every registry row
// PromptLane==Hook, sorted for stable output.
func probeHookToolCandidates() []string {
	var tools []string
	for _, c := range integration.Capabilities() {
		if c.PromptLane == integration.PromptLaneHook {
			tools = append(tools, c.Tool)
		}
	}
	return tools
}
