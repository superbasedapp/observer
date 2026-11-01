package integration

import "time"

// --- 2026-10-21 wave: the ten capture adapters' hook surfaces --------------
//
// Every vendor surface below was probed LIVE on 2026-10-21 (WSL Ubuntu and
// Windows 11) with probe hooks: the payload, the reply forms that block, the
// failure semantics and the shell that runs the command
// (docs/guard.md "Live grounding: 2026-10-21 wave"). A binding the vendor
// fired live carries live grounding. A binding Observer REGISTERS carries
// the probe as doc-kind grounding until Observer's own writer and receiver
// pass an end-to-end live run (D-043, the Kiro precedent): `observer start`
// writes a mechanism only once every registered binding is live.

const hookWaveDate = "2026-10-21"

// Live hook probes (vendor semantics, probe hooks, not Observer's writer).
const (
	hookProbeIBMBob     = "hook probe 2026-10-21: bobshell 2.0.6 `bob chat` driven through a pty on WSL Ubuntu and Windows 11, probe hooks in ~/.bob/settings/settings.json and a trusted project .bob/settings.json (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeCodeBuddy  = "hook probe 2026-10-21: codebuddy 2.171.0 -p and --input-format stream-json on WSL Ubuntu and Windows 11 against a loopback mock model, probe hooks in a project .codebuddy/settings.json (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeDeepAgents = "hook probe 2026-10-21: deepagents-code (dcode) 0.1.87 `dcode -n` on WSL Ubuntu and Windows 11, probe hooks in a project .deepagents/hooks.json with --trust-project-hooks (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeDimCode    = "hook probe 2026-10-21: dimcode 0.5.21 `dim exec --json` on WSL Ubuntu and Windows 11, probe hooks in a project .dimcode/hooks.json (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeDirac      = "hook probe 2026-10-21: dirac-cli 0.5.22 headless runs on Windows 11 (PowerShell 5.1) and WSL Ubuntu, probe scripts in a --hooks-dir matching the global-hooks path rule (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeAutohand   = "hook probe 2026-10-21: autohand-cli 0.9.8 on Windows 11 (model turns) and WSL Ubuntu (prompt events only: the account is disabled), probe hooks in a trusted project .autohand/config.json (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeVTCode     = "hook probe 2026-10-21: vtcode-core 0.180.2 interactive TUI on WSL Ubuntu and Windows 11, probe hooks in the user-level vtcode.toml (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeKimchi     = "hook probe 2026-10-21: kimchi 1.17.0 `kimchi -p --approve` on WSL Ubuntu and Windows 11, probe hooks in a project .kimchi/hooks.json, the bash pre-gate in ~/.config/kimchi/harness/hooks/bash (WSL) and the claude-code-hook-adapter under a throwaway HOME (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	hookProbeCortexCode = "hook probe 2026-10-21: cortex 1.2.18 on WSL Ubuntu and Windows 11 running the probe hooks of ~/.claude/settings.json (docs/guard.md \"Live grounding: 2026-10-21 wave\")"
	// hookSrcWaveVendor is the shipped-build reading of a vendor event that
	// did not fire in the probe.
	hookSrcVTCodeStrings = "vtcode-core 0.180.2 binary strings and config schema (event not fired in the 2026-10-21 probe)"
)

// Reply dialects new in the 2026-10-21 wave (internal/hook toolgate.go and
// promptsubmit.go).
const (
	// hookDialectClaudeWirePreTool: the Claude-shaped JSON tool gate whose
	// tool names may be Claude Code's wire spellings (Bash, Read, Edit)
	// rather than the host's own (Deep Agents, Kimchi, Cortex Code).
	hookDialectClaudeWirePreTool = "claude-wire-pretool"
	// hookDialectVTCodePreTool: Claude JSON permissionDecision, but the
	// allow is an EMPTY stdout (VT Code echoes any stdout into its TUI).
	hookDialectVTCodePreTool = "vtcode-pretool"
	// hookDialectDiracPreTool / hookDialectDiracPrompt: Dirac's
	// {cancel, errorMessage} reply over preToolUse.parameters /
	// userPromptSubmit.prompt.
	hookDialectDiracPreTool = "dirac-pretool"
	hookDialectDiracPrompt  = "dirac"
	// hookDialectAutohandPreTool / hookDialectAutohandPrompt: Autohand's
	// top-level decision reply; the prompt is "instruction".
	hookDialectAutohandPreTool = "autohand-pretool"
	hookDialectAutohandPrompt  = "autohand"
	// hookDialectKimchiBashPreTool: Kimchi's bash pre-gate script
	// ({tool_name: "bash", input: {command}, cwd}; exit 2 blocks).
	hookDialectKimchiBashPreTool = "kimchi-bash-pretool"
)

// Timeouts Observer registers on the 2026-10-21 writers, and the vendor
// timeouts that bound them.
const (
	hookIBMBobRegisteredTimeout     = 30 * time.Second
	hookCodeBuddyRegisteredTimeout  = 60 * time.Second
	hookDeepAgentsRegisteredTimeout = 30 * time.Second
	hookDimCodeRegisteredTimeout    = 30 * time.Second
	hookDiracHostTimeout            = 10 * time.Second
	hookAutohandRegisteredTimeout   = 30 * time.Second
	hookVTCodeRegisteredTimeout     = 30 * time.Second
	hookKimchiBashHostTimeout       = 5 * time.Second
	hookKimchiHostTimeout           = 60 * time.Second
	hookCortexHostTimeout           = 60 * time.Second
)

// waveLive builds a binding the 2026-10-21 probe fired live; waveSrc builds
// one grounded on the shipped build only. withSess marks a payload that
// carries the session id.
func waveLive(src string, withSess bool) func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
	return func(c HookCap, phase, event string, opts ...hbOpt) HookBinding {
		base := []hbOpt{proc(ProcDescendant)}
		if withSess {
			base = append(base, sess())
		}
		return hb(c, phase, event, hgLive(src, hookWaveDate), append(base, opts...)...)
	}
}

// waveRegistered marks a binding Observer registers whose grounding is the
// vendor probe (doc-kind) until Observer's own writer passes an end-to-end
// live run (then the binding carries liveAt).
func waveRegistered(src string) hbOpt {
	return func(b *HookBinding) { b.Grounding = hgSourceAt(src, hookWaveDate) }
}

// waveE2E marks a registered binding whose OWN writer passed the live
// end-to-end run (Observer's writer into the real vendor home, a headless
// session blocked by the guard, the guard_events row under the tool, and a
// byte-identical unregister).
func waveE2E(src string) hbOpt {
	return func(b *HookBinding) { b.Grounding = hgLive(src, hookWaveDate) }
}

// The live end-to-end runs of 2026-10-21 (WSL Ubuntu, a throwaway Observer
// config and database; docs/guard.md "Live grounding: 2026-10-21 wave"),
// and of 2026-10-22 for the "-windows" wsl.exe bridges: the Windows build
// of the vendor, Observer's writer registering through the live WSL
// daemon's /api/setup/hooks, guard in observe mode, a guard_events row
// with no action_id (the hook path) under the tool's own id and session.
// The Windows runs exercised the allow path of the prompt gate only (the
// submit went through); no Windows prompt block was run.
const (
	hookE2EIBMBob     = "live E2E 2026-10-21: Observer's writer into ~/.bob/settings/settings.json, `bob chat` (bobshell 2.0.6) blocked execute_command (U-901) and a github_pat prompt (R-172), rows under ibm-bob, unregister restored the hooks member; Windows bridge 2026-10-22: ibm-bob-windows (cmd.exe /d /s /c running wsl.exe) under `bob chat` 2.0.6 on Windows 11 through a pty, R-110 flagged on `git push --force origin main` through the hook, turn completed"
	hookE2ECodeBuddy  = "live E2E 2026-10-21: Observer's writer into ~/.codebuddy/settings.json (spliced), `codebuddy -p` 2.171.0 against a loopback mock blocked Bash (U-901) and a github_pat prompt (R-172), rows under codebuddy, byte-identical unregister; Windows bridge 2026-10-22: codebuddy-windows (Git Bash, MSYS_NO_PATHCONV=1 wsl.exe; the writer now emits the portable AP-119 bridge, not yet re-run live) under `codebuddy -p -y` 2.171.0 on Windows 11 against a loopback mock, R-110 flagged on Bash `git push --force origin main` through the hook, turn completed"
	hookE2EDeepAgents = "live E2E 2026-10-21: Observer's writer into ~/.deepagents/hooks.json, `dcode -n` 0.1.87 blocked Bash (U-901) and a github_pat prompt (R-172), rows under deepagents-code, byte-identical unregister; Windows bridge 2026-10-22: deepagents-code-windows (cmd.exe /c running wsl.exe) under `dcode -n -S all` 0.1.87 on Windows 11 (LOG_COLOR=false workaround), R-110 flagged on `git push --force origin main` through the hook, turn completed"
	hookE2EDimCode    = "live E2E 2026-10-21: Observer's writer into ~/.dimcode/v2/hooks.json, `dim exec --json` 0.5.21 blocked exec (U-901) and a github_pat prompt (R-172) with no trust step, rows under dimcode, byte-identical unregister; Windows bridge 2026-10-22: dimcode-windows (cmd.exe /d /s /c running wsl.exe) under `dim exec --json` 0.5.21 on Windows 11, R-110 flagged on `git push --force origin main` through the hook, turn completed"
	hookE2EDirac      = "live E2E 2026-10-21: Observer's sh scripts in ~/.dirac/Hooks, `dirac -y --json` 0.5.22 cancelled the task on execute_command (U-901) and on a github_pat prompt (R-172, no model request), rows under dirac keyed by taskId, scripts removed on unregister; Windows bridge 2026-10-22: dirac-windows (<Event>.ps1 under PowerShell 5.1 starting wsl.exe) under `dirac -y --json` 0.5.22 on Windows 11, R-110 flagged on execute_command `git push --force origin main` through the hook, turn completed"
	hookE2EVTCode     = "live E2E 2026-10-21: Observer's groups in the user vtcode.toml, the vtcode 0.180.2 TUI blocked exec_command (U-901) and a github_pat prompt (R-172, no model call), rows under vtcode, byte-identical unregister; Windows bridge 2026-10-22: vtcode-windows (Git sh, MSYS_NO_PATHCONV=1 wsl.exe; the writer now emits the portable AP-119 bridge, not yet re-run live) in the vtcode 0.180.2 TUI on Windows 11 against a loopback mock, R-153 flagged on exec_command `cat .env` through the hook, turn completed (VT Code's own preflight rejects `git push --force` before PreToolUse, so R-110 cannot reach the hook)"
	hookE2EAutohand   = "live E2E 2026-10-22: Observer's writer into hooks.hooks[] of ~/.autohand/config.json (credential-file splice), `autohand -p -y` 0.9.8 on WSL Ubuntu (a new signed-in account, MiniMax over OpenRouter) blocked shell `echo observer-e2e-forbidden` (U-901, the model quoted the reason; a row under autohand with no session id, the pre-tool payload carries none) and a github_pat prompt (R-172, before any model call, a row under the session id), byte-identical unregister within a 30 s window, the Windows config's hooks member unchanged; Linux shape only (the Windows CLI was signed out; its native writer round-trip and receiver replies were checked without a vendor session)"
	hookE2EKimchi     = "live E2E 2026-10-21: Observer's bash pre-gate in ~/.config/kimchi/harness/hooks/bash, `kimchi -p --approve` 1.17.0 blocked `echo observer-e2e-forbidden` (U-901, the model quoted the reason), a row under kimchi with no session id, script removed on unregister"
)

// waveSrc is a binding grounded on the vendor's shipped build or schema
// (not fired in the probe).
func waveSrc(src string) hbOpt {
	return func(b *HookBinding) { b.Grounding = hgSourceAt(src, hookWaveDate) }
}

// replayedVia marks a binding Observer acts on through ANOTHER tool's hook
// registration: the host runs the hooks of that tool's config and the
// receiver routes its payload here (internal/hook foreignhost.go).
func replayedVia(tool string) hbOpt { return func(b *HookBinding) { b.ReplayedVia = tool } }

// standsInFor names the tool's own registered gate a replayed binding
// stands in for (HookBinding.StandsInFor).
func standsInFor(event string) hbOpt { return func(b *HookBinding) { b.StandsInFor = event } }

var (
	ibmBobB     = waveLive(hookProbeIBMBob, true)
	codeBuddyB  = waveLive(hookProbeCodeBuddy, true)
	deepAgentsB = waveLive(hookProbeDeepAgents, true)
	dimCodeB    = waveLive(hookProbeDimCode, true)
	diracB      = waveLive(hookProbeDirac, true)
	autohandB   = waveLive(hookProbeAutohand, false)
	vtCodeB     = waveLive(hookProbeVTCode, true)
	kimchiB     = waveLive(hookProbeKimchi, true)
	cortexB     = waveLive(hookProbeCortexCode, true)
)

// hookBindingsIBMBob: Claude-shaped hooks in ~/.bob/settings/settings.json,
// run by Node child_process.exec (/bin/sh on Linux, cmd.exe on Windows).
var hookBindingsIBMBob = []HookBinding{
	// W-1 (surface-gap arc, lane w2-c): the Bob IDE reads the same hooks file
	// but IGNORES PreToolUse stdout; only exit 2 blocks there
	// (bob.ibm.com/docs/ide/configuration/lifecycle-hooks). So Observer
	// answers with the exit-code dialect (exit 2, the reason on stderr, a
	// silent allow), which also blocked live on Bob Shell. The IDE half held
	// live in live check 17 (Bob IDE 1.126.0+bob2.2.3, 2026-10-25).
	ibmBobB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectKimiPreTool), wired(), waveE2E(hookE2EIBMBob),
		host(hookIBMBobRegisteredTimeout, HostProceeds), dec(decDeny...),
		adminCaveat("Bob IDE runs these hooks too, and its exit-2 block held live in the IDE (live check 17, Bob IDE 1.126.0+bob2.2.3, 2026-10-25), but IDE sessions are not captured: the adapter reads only Bob Shell's ~/.bob/db/bob.db."),
		note("stdin {session_id (= bob.db tasks.id), cwd, hook_event_name, tool_name, tool_input, tool_use_id}; exit 2 with the stderr reason, and hookSpecificOutput.permissionDecision deny (hookEventName must equal the event), both blocked live on Bob Shell and the model read the reason. Observer answers with exit 2 and the reason on stderr after \"Blocked by Observer guard:\" on one first line (DEC-1: without it the model read the bare stderr reason as the tool's output), and an empty stdout as the allow, because the Bob IDE reads the same settings.json hooks but ignores PreToolUse stdout and blocks only on exit 2 (vendor doc bob.ibm.com/docs/ide/configuration/lifecycle-hooks; the IDE block held live in live check 17, 2026-10-25). permissionDecision ask is IGNORED (the call went to Bob's own approval prompt), so an enforced ask is a deny. Every failure (crash, exit 1, timeout, bad JSON) lets the call run. "+
			"Observer writes one matcher group {hooks:[{type:command, command, timeout:30}]} under \"hooks\" in ~/.bob/settings/settings.json (user hooks need no folder trust; a disableGlobalHooks the user set is honoured and nothing is written). Windows runs the command under cmd.exe")),
	ibmBobB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectClaudeCode), wired(), waveE2E(hookE2EIBMBob),
		host(hookIBMBobRegisteredTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		note("exit 2 with the stderr reason blocked live: nothing reaches the model and the developer sees \"Prompt blocked by hook\" with the reason; hookSpecificOutput.additionalContext reached the model. No ask")),
	ibmBobB(HookCapToolObserve, HookPhasePost, "PostToolUse", dec(decContext...), note("not fired for a tool error; tool_response is a string")),
	ibmBobB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...), note("fires on the first message of a task, not at process start; source startup (resume per the vendor code)")),
	ibmBobB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", note("last_assistant_message; cannot block")),
	ibmBobB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", dec(decDeny...), note("fired live via /compact (trigger manual); the exit-2 block is vendor code only")),
	ibmBobB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", note("trigger, compact_summary; cannot block")),
}

// hookBindingsCodeBuddy: Claude-Code-compatible settings.json hooks; Windows
// runs every hook command under Git Bash.
var hookBindingsCodeBuddy = []HookBinding{
	codeBuddyB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectClaudeJSONPreTool), wired(), waveE2E(hookE2ECodeBuddy),
		host(hookCodeBuddyRegisteredTimeout, HostProceeds), dec(decDenyModify...),
		note("fires BEFORE CodeBuddy's own permission check; hookSpecificOutput.permissionDecision deny, exit 2 with stderr and top-level decision block all blocked live (the model saw \"Error: <reason>\"); allow + updatedInput rewrote the command; an ask ran the command headless (interactive ask not probed), so an enforced ask is a deny. A crash or exit 1 lets the call run, but a hook TIMEOUT blocks it: Observer registers timeout 60 (the vendor default) so its own watchdog answers first. "+
			"Observer writes one matcher group under \"hooks\" in ~/.codebuddy/settings.json, no matcher, so Bash and the Windows PowerShell tool are both gated. Windows runs the command under Git Bash (bash quoting, forward slashes; the WSL bridge is the portable AP-119 form: `//` paths and a `; exit $LASTEXITCODE` trailer, no MSYS_NO_PATHCONV prefix)")),
	codeBuddyB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectTopLevelBlock), wired(), waveE2E(hookE2ECodeBuddy),
		host(hookCodeBuddyRegisteredTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		note("the top-level-block dialect: {\"decision\":\"block\",\"reason\"} with exit 2 blocked live with a clean reason and no model call; additionalContext and plain stdout reach the model as a system reminder; a timeout blocks the prompt")),
	codeBuddyB(HookCapEnvironmentObserve, HookPhaseNone, "Setup", note("trigger init, before SessionStart")),
	codeBuddyB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", note("source startup, model; NO cwd key (the process cwd / CODEBUDDY_PROJECT_DIR is the project)")),
	codeBuddyB(HookCapToolObserve, HookPhasePost, "PostToolUse", dec(decContext...), note("only for calls that ran; additionalContext reaches the model")),
	codeBuddyB(HookCapPermissionObserve, HookPhasePost, "PermissionDenied"),
	codeBuddyB(HookCapPermissionObserve, HookPhasePre, "PermissionRequest", note("fires only under --input-format stream-json; a decision.behavior deny blocked live")),
	codeBuddyB(HookCapNotificationObserve, HookPhaseNone, "Notification", func(b *HookBinding) { b.SessionKey = false }, note("no session_id and an empty transcript_path")),
	codeBuddyB(HookCapEnvironmentObserve, HookPhaseNone, "CwdChanged"),
	codeBuddyB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
	codeBuddyB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", waveSrc(hookSrcCodeBuddyBundle), note("not fired in -p or stream-json runs")),
	codeBuddyB(HookCapToolFailureObserve, HookPhasePost, "PostToolUseFailure", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapTurnLifecycle, HookPhaseEnd, "StopFailure", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapEnvironmentObserve, HookPhaseNone, "WorktreeCreate", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapEnvironmentObserve, HookPhaseNone, "WorktreeRemove", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapEnvironmentObserve, HookPhaseNone, "InstructionsLoaded", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapEnvironmentObserve, HookPhaseNone, "ConfigChange", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapEnvironmentObserve, HookPhaseNone, "FileChanged", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapTaskObserve, HookPhaseStart, "TaskCreated", waveSrc(hookSrcCodeBuddyBundle)),
	codeBuddyB(HookCapTaskObserve, HookPhaseEnd, "TaskCompleted", waveSrc(hookSrcCodeBuddyBundle)),
}

// hookSrcCodeBuddyBundle is CodeBuddy's shipped hook-event enum and type
// definitions (types/codebuddy-code.d.ts).
const hookSrcCodeBuddyBundle = "CodeBuddy Code 2.171.0 bundle hook-event enum and types/codebuddy-code.d.ts (event registered without error in the 2026-10-21 probe, not fired)"

// hookBindingsDeepAgents: Hooks v2, Claude-compatible envelope, user-level
// ~/.deepagents/hooks.json (the project file is trust-gated).
var hookBindingsDeepAgents = []HookBinding{
	deepAgentsB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectClaudeWirePreTool), wired(), waveE2E(hookE2EDeepAgents),
		host(hookDeepAgentsRegisteredTimeout, HostProceeds), dec(decDenyContext...),
		note("tool names are Claude Code wire names for seven tools (execute -> Bash, read_file -> Read, write_file -> Write, edit_file -> Edit, glob, grep, ls -> LS) and native names for the rest, so the gate reads both vocabularies. exit 2, hookSpecificOutput deny and top-level decision block all blocked live (the model saw \"Bash blocked by hook: <reason>\"); updatedInput is ignored (no modify); additionalContext reached the model; an ask is a TUI-only interrupt that headless runs auto-approve, so an enforced ask is a deny. A crash, exit 1 or timeout lets the call run. "+
			"Observer writes one matcher group under \"hooks\" in ~/.deepagents/hooks.json ($DEEPAGENTS_HOME), user level only (no trust step there); a legacy list-shaped file is left for dcode to migrate. Windows runs the command under cmd.exe")),
	deepAgentsB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectClaudeCode), wired(), waveE2E(hookE2EDeepAgents),
		host(hookDeepAgentsRegisteredTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		note("exit 2 with stderr, decision block and continue:false all blocked live with no model call (\"Operation stopped by hook: <reason>\"); additionalContext reached the model. No ask")),
	deepAgentsB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...), note("source startup, model, session_title; session_id == the LangGraph thread_id")),
	deepAgentsB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", note("reason prompt_input_exit")),
	deepAgentsB(HookCapToolObserve, HookPhasePost, "PostToolUse", note("tool_response is the LangChain ToolMessage dict, plus duration_ms")),
	deepAgentsB(HookCapToolFailureObserve, HookPhasePost, "PostToolUseFailure", note("fires on a non-zero shell exit")),
	deepAgentsB(HookCapPermissionObserve, HookPhasePre, "PermissionRequest", note("fires headless too; decision.behavior is source-only")),
	deepAgentsB(HookCapNotificationObserve, HookPhaseNone, "Notification"),
	deepAgentsB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...), note("decision block continues the turn (up to 8 continuations, source)")),
	deepAgentsB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", note("fired on WSL through the task tool; agent_id, agent_type, agent_transcript_path")),
	deepAgentsB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	deepAgentsB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", waveSrc(hookSrcDeepAgentsSource), note("source says it can deny; not provoked in the probe")),
}

// hookSrcDeepAgentsSource is the shipped hooks source of deepagents-code.
const hookSrcDeepAgentsSource = "deepagents-code 0.1.87 hooks/loading.py + hooks/models (event not fired in the 2026-10-21 probe)"

// hookBindingsDimCode: Claude-style command hooks in hooks.json; no trust
// step (a `dim hooks disable` deny-list keyed by command hash is the only
// switch).
var hookBindingsDimCode = []HookBinding{
	dimCodeB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectKimiPreTool), wired(), waveE2E(hookE2EDimCode),
		host(hookDimCodeRegisteredTimeout, HostProceeds), dec(decDeny...),
		note("exit 2 with the stderr reason blocked live and the model read the reason verbatim as the tool result (JSON permissionDecision deny, decision block and continue:false block too); an ask RAN the command (only PermissionRequest can ask), so an enforced ask is a deny; plain stdout becomes model context, so the allow is silence. A crash, exit 1 or timeout lets the call run. "+
			"Observer writes one matcher group {hooks:[{type:command, command, timeout:30}]} under \"hooks\" in ~/.dimcode/v2/hooks.json ($DIMCODE_HOME, with v2 appended unless it already ends in v2), only supported event names (an unknown one makes the whole file unloadable). There is NO trust step; `dim hooks disable` can switch Observer's hook off by command hash, and a changed command re-enables it. Windows runs the command under cmd.exe")),
	dimCodeB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectKimiCode), wired(), waveE2E(hookE2EDimCode),
		host(hookDimCodeRegisteredTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		note("exit 2 with the stderr reason blocked live: no model call, `dim exec` fails with the reason as the session error and the prompt is not stored; additionalContext reached the model. No ask")),
	dimCodeB(HookCapToolObserve, HookPhasePost, "PostToolUse", note("tool_response {content, isError, structuredContent{exitCode, wallTimeMs}}; not fired for a blocked call")),
	dimCodeB(HookCapPermissionObserve, HookPhasePre, "PermissionRequest", dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny), note("fires only when the permission policy asks (workspace-write); the only native ask lane")),
	dimCodeB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", note("source startup; no run_id/turn_id")),
	dimCodeB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", note("once per run")),
	dimCodeB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", note("the child session id is subagent_<ms>_<rand>")),
	dimCodeB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop"),
	dimCodeB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", waveSrc(hookSrcDimCodeSource)),
	dimCodeB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", waveSrc(hookSrcDimCodeSource)),
}

// hookSrcDimCodeSource is DimCode's bundled hook dispatcher source.
const hookSrcDimCodeSource = "dimcode 0.5.21 bundled source (event not fired in the 2026-10-21 probe)"

// hookBindingsDirac: the LEGACY Cline-extension file-per-event runtime,
// renamed (not the Cline SDK runtime cline-pretool was grounded on).
var hookBindingsDirac = []HookBinding{
	diracB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectDiracPreTool), wired(), waveE2E(hookE2EDirac),
		host(hookDiracHostTimeout, HostProceeds), dec(decDeny...),
		adminCaveat("a block cancels the whole Dirac task, not one call"),
		note("stdin {diracVersion, hookName, timestamp, taskId (== the task directory, the session id), workspaceRoots, userId, model, preToolUse{toolName, parameters}}; parameters is a string map (every value stringified; edit_file's target arrives as \"[object Object]\", so a path rule cannot see an edit target). The ONLY block is {\"cancel\":true,\"errorMessage\":...}: it cancels the whole TASK, the command does not run and the model never sees the reason (Observer also writes the reason to stderr, which Dirac echoes into its transcript). No ask, no modify. exit 2, exit 1, a crash and the 10 s timeout all fail OPEN. "+
			"Observer writes ~/.dirac/Hooks/PreToolUse (an executable sh script; the CLI runs only hooks under a path matching .dirac/Hooks or Dirac/Hooks) or PreToolUse.ps1 on Windows (PowerShell 5.1 reading stdin with [Console]::In.ReadToEnd())")),
	diracB(HookCapContextInject, HookPhasePre, "PreToolUse", dec(decContext...), note("contextModification is injected as <hook_context source=\"PreToolUse\">; the model quoted it")),
	diracB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectDiracPrompt), wired(), waveE2E(hookE2EDirac),
		host(hookDiracHostTimeout, HostProceeds), dec(decDeny...),
		adminCaveat("a block cancels the whole Dirac task"),
		note("awaited before the model call: {\"cancel\":true} cancelled the task with zero API requests on both OSes. It fires before EVERY API request of a task (twice with the initial prompt, then with prompt \"\" per tool-result turn): the dialect judges a non-empty prompt once and lets empty ones pass. No redact (contextModification only appends)")),
	diracB(HookCapContextInject, HookPhasePre, "UserPromptSubmit", dec(decContext...), note("contextModification injected as <hook_context source=\"UserPromptSubmit\">")),
	diracB(HookCapToolObserve, HookPhasePost, "PostToolUse", note("result (full tool output), success, executionTimeMs")),
	diracB(HookCapSessionLifecycle, HookPhaseStart, "TaskStart"),
	diracB(HookCapSessionLifecycle, HookPhaseStart, "TaskResume", note("fired on WSL with -T <id>")),
	diracB(HookCapTurnLifecycle, HookPhaseEnd, "TaskComplete"),
	diracB(HookCapTurnLifecycle, HookPhaseEnd, "TaskCancel", note("fires after EVERY headless run (the CLI disposes the task), so it is not a user cancel")),
	diracB(HookCapNotificationObserve, HookPhaseNone, "Notification"),
	diracB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", waveSrc("dirac-cli 0.5.22 bundle dist/cli.mjs (not fired in the 2026-10-21 probe)")),
}

// hookBindingsAutohand: config.json hooks.hooks[] (an ARRAY of entries
// carrying their own event); tool events carry NO session id.
var hookBindingsAutohand = []HookBinding{
	autohandB(HookCapToolGate, HookPhasePre, "pre-tool", reg(hookDialectAutohandPreTool), wired(), waveE2E(hookE2EAutohand),
		host(hookAutohandRegisteredTimeout, HostBlocks), dec(HookDecisionDeny, HookDecisionModify, HookDecisionContext),
		note("stdin {cwd, hook_event_name, tool_name, tool_input, tool_use_id, file_path?}: NO session id (tool_use_id joins it to the transcript). Top-level {decision deny|block, reason}, continue:false and exit 2 blocked live on Windows and the model read the reason; the Claude hookSpecificOutput form is IGNORED; updatedInput rewrites. The allow is {}: an explicit {\"decision\":\"allow\"} would skip Autohand's own permission prompt. An ask auto-approved headless, so an enforced ask is a deny. The host fails CLOSED: a crash, a timeout or malformed JSON blocks the call. "+
			"Observer writes {event, command, description, timeout:30000} into hooks.hooks[] of ~/.autohand/config.json, a file that also holds provider keys and the account token (credential-file exception: only the hooks key is touched). `observer init` only, never `observer start`: Autohand's device sync mirrors the hooks key between devices, so a command written for one OS reaches the other, where a missing binary would block every tool (fail-closed)")),
	autohandB(HookCapPromptGate, HookPhasePre, "pre-prompt", sess(), reg(hookDialectAutohandPrompt), wired(), waveE2E(hookE2EAutohand),
		host(hookAutohandRegisteredTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		note("the prompt is \"instruction\"; top-level decision deny|block, continue:false and exit 2 blocked live on Windows and WSL before any model call, the reason printed to the developer (never the model); additionalContext reaches the model. A crash or timeout lets the prompt through")),
	autohandB(HookCapPermissionObserve, HookPhasePre, "permission-request", note("fires on decision ask and on approval prompts (permission_type tool_approval); reply decisions are source-only")),
	autohandB(HookCapToolObserve, HookPhasePost, "post-tool", note("no post-tool for a blocked call")),
	autohandB(HookCapEnvironmentObserve, HookPhaseNone, "file-modified"),
	autohandB(HookCapTurnLifecycle, HookPhaseEnd, "stop", sess(), note("post-response is an alias of stop, not its own event; tokens_used, turn_duration")),
	autohandB(HookCapSessionLifecycle, HookPhaseStart, "session-start", sess(), note("session_id == the session directory name <uuid>-<epoch-ms>")),
	autohandB(HookCapSessionLifecycle, HookPhaseEnd, "session-end", sess(), note("reason exit or error")),
	autohandB(HookCapNotificationObserve, HookPhaseNone, "session-error", sess(), note("fired on WSL (account disabled)")),
	autohandB(HookCapNotificationObserve, HookPhaseNone, "notification"),
	autohandB(HookCapNotificationObserve, HookPhaseNone, "rate-limit", waveSrc(hookSrcAutohandSource)),
	autohandB(HookCapPermissionObserve, HookPhasePost, "permission-denied", waveSrc(hookSrcAutohandSource)),
	autohandB(HookCapSubagentLifecycle, HookPhaseStart, "subagent-start", waveSrc(hookSrcAutohandSource)),
	autohandB(HookCapSubagentLifecycle, HookPhaseEnd, "subagent-stop", waveSrc(hookSrcAutohandSource)),
	autohandB(HookCapCompactLifecycle, HookPhasePost, "context:compact", waveSrc(hookSrcAutohandSource)),
}

// hookSrcAutohandSource is Autohand's shipped HookManager source.
const hookSrcAutohandSource = "autohand-cli 0.9.8 HookManager (installed npm package; event not fired in the 2026-10-21 probe)"

// hookBindingsVTCode: [[hooks.lifecycle.<snake_event>]] in the user-level
// vtcode.toml; the payload and the reply use the PascalCase event name.
var hookBindingsVTCode = []HookBinding{
	vtCodeB(HookCapToolGate, HookPhasePre, "PreToolUse", reg(hookDialectVTCodePreTool), wired(), waveE2E(hookE2EVTCode),
		host(hookVTCodeRegisteredTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionAsk, HookDecisionDeny, HookDecisionModify),
		adminCaveat("interactive TUI sessions only: exec, --full-auto and -p run no hooks"),
		note("hookSpecificOutput.permissionDecision deny and exit 2 blocked live on both OSes; the reason is shown to the developer and the model gets VT Code's fixed \"denied by PreToolUse hook\" error. ask raises VT Code's own approval modal with the reason; allow does not skip VT Code's prompt; updatedInput rewrites. Any stdout is echoed into the TUI, so the allow is an EMPTY stdout. A crash or non-2 exit lets the call run, but a TIMEOUT blocks it. Hooks fire ONLY in the interactive TUI (exec, --full-auto and -p ran no hook). "+
			"Observer writes [[hooks.lifecycle.pre_tool_use]] {hooks = [{type = command, command, timeout_seconds = 30}]} into the user-level vtcode.toml (~/.config/vtcode/vtcode.toml, %APPDATA%\\vinhnx\\vtcode\\config\\vtcode.toml), editing only its own tables; never the workspace file (approval modal). Windows runs the command under Git for Windows' sh (the WSL bridge is the portable AP-119 form: `//` paths and a `; exit $LASTEXITCODE` trailer, no MSYS_NO_PATHCONV prefix)")),
	vtCodeB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", reg(hookDialectKimiCode), wired(), waveE2E(hookE2EVTCode),
		host(hookVTCodeRegisteredTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		adminCaveat("interactive TUI sessions only"),
		note("exit 2 with the stderr reason blocked live on both OSes (the reason shown, the prompt never reached the model and was written to events.jsonl as an interjected event); decision block and continue:false block too; additionalContext reached the model. The allow is an empty stdout (any stdout is echoed). No ask")),
	vtCodeB(HookCapPermissionObserve, HookPhasePre, "PermissionRequest", dec(decDeny...), note("runs after PreToolUse, before VT Code's approval modal; a decision.behavior deny denied the call (WSL); no tool_call_id")),
	vtCodeB(HookCapToolObserve, HookPhasePost, "PostToolUse", note("only for an executed call")),
	vtCodeB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", note("session_id == the <ws>/.vtcode/sessions/<id> directory and the --resume id")),
	vtCodeB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", note("reason exit")),
	vtCodeB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...), note("decision block with stop_hook_active false kept the turn going (WSL)")),
	vtCodeB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", func(b *HookBinding) {
		b.Grounding = Grounding{Kind: GroundingInferred, Source: hookSrcVTCodeStrings, Date: hookWaveDate}
	}),
	vtCodeB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", waveSrc(hookSrcVTCodeStrings)),
	vtCodeB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop", waveSrc(hookSrcVTCodeStrings)),
	vtCodeB(HookCapNotificationObserve, HookPhaseNone, "Notification", waveSrc(hookSrcVTCodeStrings)),
}

// hookBindingsKimchi: Kimchi's native event hooks are PROJECT-scoped only
// (<project>/.kimchi/hooks.json, trust-gated), so Observer has no global
// writer for them. Its one user-level hook is the bash pre-gate directory,
// which Observer writes; the Claude-dialect events reach Observer only
// through Kimchi's claude-code-hook-adapter (default off), which replays
// ~/.claude/settings.json and is routed to these bindings by the
// claude-code receiver.
var hookBindingsKimchi = []HookBinding{
	kimchiB(HookCapToolGate, HookPhasePre, "tool_call", reg(hookDialectKimchiBashPreTool), wired(), waveE2E(hookE2EKimchi),
		func(b *HookBinding) { b.SessionKey = false }, host(hookKimchiBashHostTimeout, HostProceeds), dec(decDeny...),
		adminCaveat("bash tool only (and the developer's ! commands); no session id"),
		note("the user-level bash pre-gate: every *.sh under ~/.config/kimchi/harness/hooks/bash ($KIMCHI_CODING_AGENT_DIR/hooks/bash) runs as `bash <file>` before the bash tool (and a developer's ! command) with stdin {tool_name: bash, input: {command}, cwd} and env KIMCHI_HOOK_EVENT=tool_call: NO session id. exit 2 with the stderr reason blocked live on WSL and the model read the reason; JSON {decision: block|deny} blocks too. Any other failure and the 5 s timeout fail open. "+
			"Observer writes superbased-observer.sh there (Linux and macOS: Windows runs the dir with whatever bash is first on PATH, often the WSL launcher, so it is not written)")),
	kimchiB(HookCapToolGate, HookPhasePre, "PreToolUse", dialectOnly(hookDialectClaudeWirePreTool), wired(), replayedVia(replayClaudeCode),
		host(hookKimchiHostTimeout, HostProceeds), dec(HookDecisionDeny, HookDecisionModify, HookDecisionContext),
		note("project-scoped only (<project>/.kimchi/hooks.json, trusted project), so Observer has no global writer; served when Kimchi's claude-code-hook-adapter (default OFF) replays ~/.claude/settings.json: the claude-code receiver recognises the payload (transcript_path null, KIMCHI_HOOK_EVENT, a UUIDv7 session id) and gates it as kimchi. Tool names are Claude-style (Bash, Read, Edit) over Kimchi's native input keys. exit 2, hookSpecificOutput deny, decision block and continue:false all blocked live; an ask is treated as allow (the command ran), so an enforced ask is a deny; updatedInput rewrites. Every failure fails open")),
	kimchiB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", dialectOnly(hookDialectClaudeCode), wired(), replayedVia(replayClaudeCode),
		host(hookKimchiHostTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		note("project-scoped natively; served through the claude-code-hook-adapter replay like PreToolUse. exit 2, hookSpecificOutput deny and decision block blocked live with no model call; the blocked prompt is NOT written to the transcript; an ask is an allow")),
	kimchiB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart", dec(decContext...), note("source startup|resume|reload|compact; session_id (UUIDv7) == the session file's id; transcript_path always null")),
	kimchiB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd", note("only on a clean process exit")),
	kimchiB(HookCapTurnLifecycle, HookPhaseStart, "TurnStart"),
	kimchiB(HookCapTurnLifecycle, HookPhaseEnd, "Stop", dec(decDeny...)),
	kimchiB(HookCapTaskObserve, HookPhaseEnd, "TaskCompleted"),
	kimchiB(HookCapToolObserve, HookPhasePost, "PostToolUse"),
	kimchiB(HookCapToolObserve, HookPhasePost, "PostToolBatch"),
	kimchiB(HookCapModelCallObserve, HookPhasePre, "MessageStart"),
	kimchiB(HookCapModelCallObserve, HookPhasePost, "MessageEnd"),
	kimchiB(HookCapSubagentLifecycle, HookPhaseStart, "SubagentStart", note("fired on WSL through the Agent tool")),
	kimchiB(HookCapSubagentLifecycle, HookPhaseEnd, "SubagentStop", waveSrc(hookSrcKimchiBundle)),
	kimchiB(HookCapTurnLifecycle, HookPhaseEnd, "StopFail", waveSrc(hookSrcKimchiBundle)),
	kimchiB(HookCapToolFailureObserve, HookPhasePost, "PostToolUseFailure", waveSrc(hookSrcKimchiBundle)),
	kimchiB(HookCapCompactLifecycle, HookPhasePre, "PreCompact", waveSrc(hookSrcKimchiBundle)),
	kimchiB(HookCapCompactLifecycle, HookPhasePost, "PostCompact", waveSrc(hookSrcKimchiBundle)),
	kimchiB(HookCapNotificationObserve, HookPhaseNone, "Notification", waveSrc(hookSrcKimchiBundle)),
}

// hookSrcKimchiBundle is Kimchi's shipped hook-adapter source.
const hookSrcKimchiBundle = "kimchi 1.17.0 bundle (FULL_COMMAND_HOOK_EVENTS; event not fired in the 2026-10-21 probe)"

// replayClaudeCode is the claude-code registry id, spelled here because
// this package imports nothing project-internal (ReplayedVia names the
// tool whose config the host replays).
const replayClaudeCode = "claude-code"

// cortexIDEUngatedCaveat is the W-7 admin caveat on Cortex's gates (live
// check LC18, partly done 2026-10-26): the Cortex Code IDE's Agent tab ran
// no hook from a user ~/.snowflake/cortex/hooks.json and none from
// ~/.claude/settings.json, so it is ungated, a vendor limit. The Desktop
// sidecar and the VS Code ACP path are still owed; Claude managed settings
// are not known to reach Cortex, so no managed hook layer is emitted for it.
const cortexIDEUngatedCaveat = "CLI only: the Cortex Code IDE's Agent tab runs no hook (neither its own hooks.json nor Claude's), so its calls are not gated; " +
	"disableAllHooks in any of Cortex's six hook sources turns the CLI gate off too (user-revocable)."

// hookBindingsCortexCode: Cortex Code (built on the Claude Agent SDK) runs
// Claude Code's ~/.claude/settings.json hooks with a Claude-shaped payload
// whose transcript_path is the Cortex conversation file. The claude-code
// receiver recognises it and routes it here (internal/hook foreignhost.go),
// so Observer gates Cortex through its Claude Code registration.
//
// The two gates name the event they stand in for (FU-141): Observer's own
// writer for Cortex's hooks.json (built, switched off behind LC18) registers
// PreToolUse and UserPromptSubmit there with `observer hook cortex-code`
// commands. The switch-on commit adds those as registered bindings listed
// before these, and ReplayFallback then holds for both: the replay answers
// neutral while that registration is present. Until then no registered own
// gate exists, ReplayFallback is false, and the replay is the gate.
var hookBindingsCortexCode = []HookBinding{
	cortexB(HookCapToolGate, HookPhasePre, "PreToolUse", dialectOnly(hookDialectClaudeWirePreTool), wired(), replayedVia(replayClaudeCode), standsInFor("PreToolUse"),
		host(hookCortexHostTimeout, HostProceeds), dec(HookDecisionDeny, HookDecisionAsk, HookDecisionModify, HookDecisionContext),
		adminCaveat(cortexIDEUngatedCaveat),
		note("reached through Observer's Claude Code hooks: Cortex merges ~/.claude/settings.json (with ~/.snowflake/cortex/hooks.json, ~/.cortex/settings.json and the project .claude/ and .cortex/ settings; disableAllHooks: true in any of them turns every hook off) and sends session_id (== the cortex conversation id), transcript_path <data home>/conversations/<id>.json (never Claude's projects/<slug>/<id>.jsonl, and no prompt_id) and Claude-style tool names (Read, Bash, Edit); the claude-code receiver recognises the transcript path and gates the call as cortex-code. On WSL exit 2 and permissionDecision deny blocked (the model reads \"[Hook] Blocked: <reason>\"), ask is Cortex's own prompt, updatedInput rewrites; crash and timeout fail open. Windows runs hook commands under powershell.exe -NoProfile -Command, where exit 2 becomes exit 1 and the Claude Code bridge's MSYS_NO_PATHCONV=1 prefix does not run at all (AP-119), so the Windows lane is not served yet")),
	cortexB(HookCapPromptGate, HookPhasePre, "UserPromptSubmit", dialectOnly(hookDialectClaudeCode), wired(), replayedVia(replayClaudeCode), standsInFor("UserPromptSubmit"),
		host(hookCortexHostTimeout, HostProceeds), dec(HookDecisionAllow, HookDecisionDeny, HookDecisionContext),
		adminCaveat(cortexIDEUngatedCaveat),
		note("reached through Observer's Claude Code hooks like PreToolUse; judged as cortex-code. Block and additionalContext live on WSL; the Windows PowerShell lane waits on AP-119")),
	cortexB(HookCapSessionLifecycle, HookPhaseStart, "SessionStart"),
	cortexB(HookCapToolObserve, HookPhasePost, "PostToolUse"),
	cortexB(HookCapPermissionObserve, HookPhasePre, "PermissionRequest"),
	cortexB(HookCapNotificationObserve, HookPhaseNone, "Notification"),
	cortexB(HookCapTurnLifecycle, HookPhaseEnd, "Stop"),
	cortexB(HookCapTurnLifecycle, HookPhaseEnd, "StopFailure"),
	cortexB(HookCapSessionLifecycle, HookPhaseEnd, "SessionEnd"),
}

// Honest-zero note for the one 2026-10-21 row with no hook surface.
const hookNoteStakpak = "no hook surface: stakpak 0.3.88 --help lists no hooks command and the binary carries no hook strings; tool control is per-profile allowed_tools / auto_approve"
