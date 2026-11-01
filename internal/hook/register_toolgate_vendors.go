package hook

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/hook/commandcodemod"
)

// Tool-gate registrations for the hook-parity Lane A6 vendors that speak a
// JSON hooks file (register_jsonhooks.go). Each is a jsonHooksTarget row:
// the file, where its event map sits, the entry shape and the handler. The
// event lists are the registry rows' Registered bindings (pinned by the
// hook-parity event_lists golden).

// installedToolGateDirs is the install signal of each Lane A6 target: the
// vendor's own state directories under the home (any one present), the
// same config-directory convention Installed() uses for every other tool.
var installedToolGateDirs = []struct {
	tool string
	dirs [][]string
}{
	{"grok", [][]string{{".grok"}}},
	{"copilot-cli", [][]string{{".copilot"}}},
	{"goose", [][]string{{".config", "goose"}, {".local", "share", "goose"}}},
	{"junie", [][]string{{".junie"}}},
	{"crush", [][]string{{".config", "crush"}, {".local", "share", "crush"}}},
	{"open-interpreter", [][]string{{".openinterpreter"}}},
	{"zcode", [][]string{{".zcode"}}},
	{"mistral-code", [][]string{{".vibe"}}},
	{"cline-cli", [][]string{{".cline"}}},
	{"muse", [][]string{{".config", "muse"}}},
	{"kimi-code", [][]string{{".kimi-code"}}},
	{"kiro-cli", [][]string{{".kiro"}}},
	// The 2026-10-21 wave: each vendor's own home (the default location;
	// an env-relocated home is not an install signal of its own).
	{"ibm-bob", [][]string{{".bob"}}},
	{"codebuddy", [][]string{{".codebuddy"}}},
	{"deepagents-code", [][]string{{".deepagents"}}},
	{"dimcode", [][]string{{".dimcode"}}},
	{"dirac", [][]string{{".dirac"}}},
	{"autohand", [][]string{{".autohand"}}},
	{"vtcode", [][]string{{".config", "vtcode"}, {"AppData", "Roaming", "vinhnx", "vtcode"}}},
	{"kimchi", [][]string{{".config", "kimchi"}}},
	// Surface-gap W-2a: Cortex Code, detected only through the
	// cortex-code/user-hooks artifact's directory (homeArtifacts), so
	// CORTEX_HOME / SNOWFLAKE_HOME move the signal with the file (its hook
	// writer refuses until live check LC18, so detection only makes init
	// say so).
	{"cortex-code", nil},
}

// Handler timeouts Observer registers where the vendor default is too
// tight for a process spawn plus a guard evaluation (Grok 5 s, Junie 2 s).
const (
	grokHookTimeoutSeconds  = 10
	junieHookTimeoutSeconds = 10
)

// commandHandler is the {type: command, command, timeout?} handler most
// JSON hooks files share; timeoutKey/timeout add the vendor's timeout field
// when non-zero.
func commandHandler(timeoutKey string, timeout int) func(string) map[string]any {
	return func(cmd string) map[string]any {
		h := map[string]any{"type": "command", "command": cmd}
		if timeoutKey != "" && timeout > 0 {
			h[timeoutKey] = timeout
		}
		return h
	}
}

// grokHooksTarget: Grok Build loads every ~/.grok/hooks/*.json (always
// trusted); Observer owns one file there. The directory is the grok/user-hooks
// artifact, so GROK_HOME moves it (S-17, CLI-4).
func (r *Registry) grokHooksTarget() jsonHooksTarget {
	dir, err := r.artifactDir("grok/user-hooks")
	return jsonHooksTarget{
		dirErr: err,
		tool:   "grok", dir: dir, file: "superbased-observer.json",
		eventsPath: []string{"hooks"}, events: []string{"PreToolUse"},
		grouped: true, handler: commandHandler("timeout", grokHookTimeoutSeconds), commandKey: "command",
		dedicated: true, errPrefix: "hook.registerGrok",
	}
}

// copilotCLIHooksTarget: Copilot CLI loads every ~/.copilot/hooks/*.json
// (version 1); the handler's shell command is the "bash" field, plus the
// "powershell" field when this Observer runs on Windows (a Windows-native
// observer.exe writing the Windows ~/.copilot).
func (r *Registry) copilotCLIHooksTarget() jsonHooksTarget {
	var ps func(event string) string
	if r.hostGOOS() == "windows" {
		ps = func(event string) string { return r.copilotPowerShellCommand("& ", event) }
	}
	// The hooks directory sits in the Copilot home beside settings.json, so
	// it follows COPILOT_HOME with the copilot-cli/user-settings artifact
	// (CLI-4; no hooks-directory row is catalogued yet).
	home, err := r.artifactDir("copilot-cli/user-settings")
	t := r.copilotCLIHooksTargetAt(filepath.Join(home, "hooks"), "", "", "hook.registerCopilotCLI", ps)
	t.dirErr = err
	return t
}

// copilotCLIWindowsHooksTarget is the copilot-cli-windows bridge: a WSL
// daemon writing the Windows-side ~/.copilot/hooks file, each command
// running `observer hook copilot-cli <event>` inside the daemon's distro.
// The bash field carries the Git Bash spelling every other "-windows" bridge
// uses (ownership is read from it); the powershell field, the one Copilot
// CLI actually runs on Windows, uses `wsl.exe -e` so a Linux path argument
// with a space survives (PowerShell 5.1 strips the quotes, and `--` would
// re-split it in the Linux shell; `-e` executes without a shell).
func (r *Registry) copilotCLIWindowsHooksTarget(copilotDir, distro string) jsonHooksTarget {
	ps := func(event string) string {
		return r.copilotPowerShellCommand("wsl.exe -d "+psQuoteIfNeeded(distro)+" -e ", event)
	}
	return r.copilotCLIHooksTargetAt(filepath.Join(copilotDir, "hooks"), "copilot-cli-windows", gitBashWrapper(distro), "hook.registerCopilotCLIWindows", ps)
}

// copilotCLIHooksTargetAt is the one Copilot CLI hooks-file row, at dir.
// label and wrapper make it the cross-OS bridge. psCommand, when non-nil,
// adds the handler's "powershell" field: Copilot CLI on Windows runs a
// hook's powershell command, not its bash one (copilot 1.0.80 bundle:
// hookSelectShellScript(bash, powershell, platform === "win32")), so a hook
// file without it never fires there (live check 2026-10-20: the Windows
// install had no Observer hook and a core.hooksPath bypass commit ran
// unguarded).
func (r *Registry) copilotCLIHooksTargetAt(dir, label, wrapper, errPrefix string, psCommand func(event string) string) jsonHooksTarget {
	t := jsonHooksTarget{
		tool: "copilot-cli", label: label, wrapper: wrapper, dir: dir, file: "superbased-observer.json",
		eventsPath: []string{"hooks"}, events: []string{"preToolUse", "userPromptSubmitted"},
		handler: func(cmd string) map[string]any {
			return map[string]any{"type": "command", "bash": cmd, "timeoutSec": 30}
		},
		commandKey: "bash",
		settings:   []jsonSetting{{path: []string{"version"}, value: 1}},
		dedicated:  true, errPrefix: errPrefix,
	}
	if psCommand != nil {
		t.eventHandler = func(event, cmd string) map[string]any {
			return map[string]any{"type": "command", "bash": cmd, "powershell": psCommand(event), "timeoutSec": 30}
		}
	}
	return t
}

// copilotPowerShellCommand is Observer's PowerShell command for a Copilot CLI
// event: prefix ("& " for a native Windows binary, the wsl.exe bridge
// otherwise), then the binary and its arguments, each PowerShell-quoted,
// then copilotPowerShellExit. Copilot reads the hook's exit code as the
// PowerShell process's: without the explicit exit, Windows PowerShell's own
// view of the native command (a stderr line read as an error record) can
// make that non-zero, which Copilot reports as "Denied by preToolUse hook
// (hook errored)" and drops the deny's reason (WINNODE2 item 10). With it,
// the exit code is exactly observer's.
func (r *Registry) copilotPowerShellCommand(prefix, event string) string {
	cmd := prefix + psQuoteIfNeeded(forwardSlashPath(r.opts.BinaryPath)) + " hook copilot-cli " + event
	if r.opts.ConfigPath != "" {
		cmd += " --config " + psQuoteIfNeeded(forwardSlashPath(r.opts.ConfigPath))
	}
	return cmd + copilotPowerShellExit
}

// copilotPowerShellExit ends every Copilot PowerShell hook command. It
// exits with observer's own exit code, and with 1 when there is none: a
// command that never ran (observer.exe missing after an extension update
// deleted its bundled binary, or an uninstall that left the hooks file)
// leaves $LASTEXITCODE unset, and a bare `exit $LASTEXITCODE` then exits 0,
// which Copilot reads as allow. Exiting 1 keeps the gate fail-closed: a
// non-zero exit denies (WINNODE2 merge, audit H3). Measured with Windows
// PowerShell 5.1: missing binary 1, a binary exiting 0 gives 0, exiting 2
// gives 2.
const copilotPowerShellExit = "; if ($LASTEXITCODE -is [int]) { exit $LASTEXITCODE } else { exit 1 }"

// psQuoteIfNeeded returns s as a PowerShell argument: verbatim when it holds
// no character PowerShell treats specially, else a single-quoted literal
// with embedded single quotes doubled (PowerShell's own escape; the POSIX
// '\” form shellQuote writes is not valid PowerShell).
func psQuoteIfNeeded(s string) string {
	if s == "" {
		return "''"
	}
	if !strings.ContainsAny(s, " \t'\"`$;&|(){}@#<>,") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// registerCopilotCLIWindows installs Observer's Copilot CLI hooks file into
// the Windows-side ~/.copilot/hooks (typically
// /mnt/c/Users/<u>/.copilot/hooks/superbased-observer.json) as the
// copilot-cli-windows bridge. Same ownership-verified Windows home
// detection and sandbox rule as every other "-windows" target.
func (r *Registry) registerCopilotCLIWindows() RegistrationResult {
	res := RegistrationResult{Tool: "copilot-cli-windows", DryRun: r.opts.DryRun}
	dir := r.detectWindowsCopilotHome()
	if dir == "" {
		if r.foreignAutoDetectSuppressed(r.opts.WindowsCopilotHome) {
			r.sandboxSkipResult(&res, ".copilot", "WindowsCopilotHome", r.opts.WindowsCopilotHome)
			return res
		}
		res.Error = errors.New("hook.registerCopilotCLIWindows: no Windows-side .copilot/ detected (set WindowsCopilotHome explicitly or run on a host where crossmount sees /mnt/c/Users/<u>/.copilot/)")
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerCopilotCLIWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.registerJSONHooks(r.copilotCLIWindowsHooksTarget(dir, distro))
}

// unregisterCopilotCLIWindows removes the copilot-cli-windows bridge's hooks
// file. A host with no Windows-side .copilot is a no-op Skip. Ownership is
// read from each entry's command, so the distro does not have to match.
func (r *Registry) unregisterCopilotCLIWindows() UnregistrationResult {
	dir := r.detectWindowsCopilotHome()
	if dir == "" {
		return UnregistrationResult{Tool: "copilot-cli-windows", DryRun: r.opts.DryRun, Skipped: true}
	}
	distro, _ := r.resolveWSLDistro("hook.unregisterCopilotCLIWindows")
	return r.unregisterJSONHooks(r.copilotCLIWindowsHooksTarget(dir, distro))
}

// goosePluginManifest is the plugin.json an Open Plugins directory needs.
var goosePluginManifest = []byte(`{
  "name": "superbased-observer",
  "version": "1.0.0",
  "description": "SuperBased Observer guard: judges each tool call before it runs"
}
`)

// gooseHooksTarget: Goose loads Open Plugins from ~/.agents/plugins/<name>;
// Observer owns one plugin directory (manifest + hooks/hooks.json).
//
// Goose's PreToolUse action fails OPEN by default (an Observer crash, a
// timeout or an unparseable reply lets the call run); "on_failure":"block"
// (read on PreToolUse only, goose 1.53.0 hooks loader) makes it fail
// closed. Observer writes it only while guard enforcement closes the tool
// gate (Options.ToolGateFailsClosed), so a node that does not enforce never
// has a tool call blocked by an Observer failure. The entry differs between
// the two states, so the next registration rewrites it in place.
func (r *Registry) gooseHooksTarget() jsonHooksTarget {
	handler := commandHandler("timeout", 30)
	if r.opts.ToolGateFailsClosed {
		handler = func(cmd string) map[string]any {
			return map[string]any{"type": "command", "command": cmd, "timeout": 30, "on_failure": "block"}
		}
	}
	return jsonHooksTarget{
		tool: "goose", dir: filepath.Join(r.opts.HomeDir, ".agents", "plugins", "superbased-observer"), file: filepath.Join("hooks", "hooks.json"),
		eventsPath: []string{"hooks"}, events: []string{"PreToolUse"},
		grouped: true, matcher: ".*", handler: handler, commandKey: "command",
		dedicated: true, extraFiles: map[string][]byte{"plugin.json": goosePluginManifest},
		errPrefix: "hook.registerGoose",
	}
}

// junieHooksTarget: Junie CLI reads the "hooks" key of ~/.junie/config.json
// (Claude-shaped matcher groups; CLI only, not the IDE / ACP mode). The file
// is the junie/user-config artifact, so JUNIE_HOME moves it (W-4).
func (r *Registry) junieHooksTarget() jsonHooksTarget {
	dir, err := r.artifactDir("junie/user-config")
	return jsonHooksTarget{
		dirErr: err,
		tool:   "junie", dir: dir, file: "config.json",
		eventsPath: []string{"hooks"}, events: []string{"PreToolUse"},
		grouped: true, handler: commandHandler("timeout", junieHookTimeoutSeconds), commandKey: "command",
		errPrefix: "hook.registerJunie",
	}
}

// crushObserverEntryName is the "name" of Observer's Crush hook entry.
const crushObserverEntryName = "superbased-observer"

// crushHooksTarget: Crush reads flat {name, matcher, command, timeout}
// entries under crush.json "hooks" (global ~/.config/crush/crush.json). The
// file is the crush/user-json artifact, the same file the route writer
// edits, so CRUSH_GLOBAL_CONFIG and XDG_CONFIG_HOME move both (FU-17). The
// higher layers Crush also loads (the data-dir crush.json, a crushrc in the
// same directory, project files) are reported by the effective-layer work,
// not written here.
func (r *Registry) crushHooksTarget() jsonHooksTarget {
	dir, err := r.artifactDir("crush/user-json")
	return jsonHooksTarget{
		dirErr: err,
		tool:   "crush", dir: dir, file: "crush.json",
		eventsPath: []string{"hooks"}, events: []string{"PreToolUse"},
		handler: func(cmd string) map[string]any {
			return map[string]any{"name": crushObserverEntryName, "command": cmd, "timeout": 30}
		},
		entryName:  crushObserverEntryName,
		commandKey: "command", errPrefix: "hook.registerCrush",
	}
}

// openInterpreterHooksTarget: Open Interpreter (the Codex CLI rebadge)
// reads the Codex hooks.json shape under its OWN home, ~/.openinterpreter.
// The [features] hooks switch lives in ~/.openinterpreter/config.toml,
// which can hold plaintext provider keys: Observer never reads or rewrites
// it (the developer enables hooks and trusts the entry with /hooks).
//
// hooks.json sits in the Open Interpreter home beside config.toml, so it
// follows INTERPRETER_HOME with the open-interpreter/user-config artifact
// (OI-1; that file is only resolved, never opened).
func (r *Registry) openInterpreterHooksTarget() jsonHooksTarget {
	dir, err := r.artifactDir("open-interpreter/user-config")
	return jsonHooksTarget{
		dirErr: err,
		tool:   "open-interpreter", dir: dir, file: "hooks.json",
		eventsPath: []string{"hooks"}, events: []string{"PreToolUse"},
		grouped: true, matcher: "*", handler: commandHandler("", 0), commandKey: "command",
		errPrefix: "hook.registerOpenInterpreter",
	}
}

// zcodeHooksTarget: zcode reads ~/.zcode/cli/config.json "hooks.events"
// and runs none of them unless "hooks.enabled" is true.
func (r *Registry) zcodeHooksTarget() jsonHooksTarget {
	return jsonHooksTarget{
		tool: "zcode", dir: filepath.Join(r.opts.HomeDir, ".zcode", "cli"), file: "config.json",
		eventsPath: []string{"hooks", "events"}, events: []string{"UserPromptSubmit", "PreToolUse"},
		grouped: true, handler: commandHandler("timeoutMs", 30000), commandKey: "command",
		settings:  []jsonSetting{{path: []string{"hooks", "enabled"}, value: true}},
		errPrefix: "hook.registerZcode",
	}
}

// commandCodeShellTarget: Command Code's SHELL hook layer,
// <home>/settings.json "hooks" (Claude-shaped matcher groups), separate
// from its Mods SDK. home is the .commandcode directory; wrapper / label
// are set for the cross-OS bridge target.
func commandCodeShellTarget(home, wrapper, label string) jsonHooksTarget {
	return jsonHooksTarget{
		tool: "command-code", label: label, wrapper: wrapper, dir: home, file: "settings.json",
		eventsPath: []string{"hooks"}, events: []string{"PreToolUse"},
		grouped: true, handler: commandHandler("", 0), commandKey: "command",
		errPrefix: "hook.registerCommandCodeShell",
	}
}

// commandCodeModGatesTools reports whether the Observer mod under home/mods
// gates tool calls itself (it subscribes to the Mods beforeToolCall hook:
// the in-process plugin shim, hook-parity Lane D). Content-shaped, never a
// version check.
func commandCodeModGatesTools(home string) bool {
	data, err := os.ReadFile(filepath.Join(home, "mods", commandcodemod.ModFileName))
	return err == nil && bytes.Contains(data, []byte("beforeToolCall"))
}

// withCommandCodeShellGate adds the shell-hook PreToolUse gate to a Mods
// registration result, unless the mod gates tool calls itself or the
// registry does not register the shell binding. The two are never both
// gates: when the mod subscribes to beforeToolCall (Lane D) it is the gate
// of record (in-process, one evaluation per call) and any shell entry
// Observer wrote earlier is removed, so a call is never judged twice. Since
// Lane D the registry's shell row is dialect-only, so a mod written WITHOUT
// beforeToolCall (`observer start` while that gate still owes a live test)
// does not fall back to writing the shell gate either (Integration 5).
func (r *Registry) withCommandCodeShellGate(res RegistrationResult, t jsonHooksTarget) RegistrationResult {
	if res.Error != nil || res.Skipped {
		return res
	}
	if commandCodeModGatesTools(t.dir) || !commandcodemod.ShellGateRegistered() {
		if un := r.unregisterJSONHooks(t); un.Error != nil {
			res.Error = un.Error
		}
		return res
	}
	sh := r.registerJSONHooks(t)
	res.HooksAdded = append(res.HooksAdded, sh.HooksAdded...)
	res.AlreadySet = append(res.AlreadySet, sh.AlreadySet...)
	if sh.Error != nil {
		res.Error = sh.Error
	}
	return res
}

// withoutCommandCodeShellGate removes Observer's shell-hook entry beside a
// Mods unregistration.
func (r *Registry) withoutCommandCodeShellGate(res UnregistrationResult, t jsonHooksTarget) UnregistrationResult {
	sh := r.unregisterJSONHooks(t)
	res.HooksRemoved = append(res.HooksRemoved, sh.HooksRemoved...)
	if res.Error == nil && sh.Error != nil {
		res.Error = sh.Error
	}
	return res
}

// registerCommandCodeAll registers the Mods bridge and the shell-hook gate
// in ~/.commandcode.
func (r *Registry) registerCommandCodeAll() RegistrationResult {
	return r.withCommandCodeShellGate(r.registerCommandCode(),
		commandCodeShellTarget(filepath.Join(r.opts.HomeDir, ".commandcode"), "", ""))
}

// unregisterCommandCodeAll removes the mod and Observer's shell-hook entry.
func (r *Registry) unregisterCommandCodeAll() UnregistrationResult {
	return r.withoutCommandCodeShellGate(r.unregisterCommandCode(),
		commandCodeShellTarget(filepath.Join(r.opts.HomeDir, ".commandcode"), "", ""))
}

// registerCommandCodeWindowsAll is registerCommandCodeAll for the cross-OS
// bridge: the Windows-side .commandcode, every command behind
// `wsl.exe -d <distro> --` (the form cmd.exe and PowerShell both run).
func (r *Registry) registerCommandCodeWindowsAll() RegistrationResult {
	res := r.registerCommandCodeWindows()
	winHome := r.detectWindowsCommandCodeHome()
	if res.Error != nil || winHome == "" {
		return res
	}
	distro, err := r.resolveWSLDistro("hook.registerCommandCodeWindows")
	if err != nil {
		res.Error = err
		return res
	}
	return r.withCommandCodeShellGate(res,
		commandCodeShellTarget(winHome, "wsl.exe -d "+shellQuoteIfNeeded(distro)+" -- ", "command-code-windows"))
}

// unregisterCommandCodeWindowsAll removes the Windows-side mod and shell
// entry.
func (r *Registry) unregisterCommandCodeWindowsAll() UnregistrationResult {
	res := r.unregisterCommandCodeWindows()
	winHome := r.detectWindowsCommandCodeHome()
	if winHome == "" {
		return res
	}
	return r.withoutCommandCodeShellGate(res, commandCodeShellTarget(winHome, "", "command-code-windows"))
}

func (r *Registry) registerGrok() RegistrationResult { return r.registerJSONHooks(r.grokHooksTarget()) }

func (r *Registry) unregisterGrok() UnregistrationResult {
	return r.unregisterJSONHooks(r.grokHooksTarget())
}

func (r *Registry) registerCopilotCLI() RegistrationResult {
	return r.registerJSONHooks(r.copilotCLIHooksTarget())
}

func (r *Registry) unregisterCopilotCLI() UnregistrationResult {
	return r.unregisterJSONHooks(r.copilotCLIHooksTarget())
}

func (r *Registry) registerGoose() RegistrationResult {
	return r.registerJSONHooks(r.gooseHooksTarget())
}

func (r *Registry) unregisterGoose() UnregistrationResult {
	return r.unregisterJSONHooks(r.gooseHooksTarget())
}

func (r *Registry) registerJunie() RegistrationResult {
	return r.registerJSONHooks(r.junieHooksTarget())
}

func (r *Registry) unregisterJunie() UnregistrationResult {
	return r.unregisterJSONHooks(r.junieHooksTarget())
}

func (r *Registry) registerCrush() RegistrationResult {
	return r.registerJSONHooks(r.crushHooksTarget())
}

func (r *Registry) unregisterCrush() UnregistrationResult {
	return r.unregisterJSONHooks(r.crushHooksTarget())
}

func (r *Registry) registerOpenInterpreter() RegistrationResult {
	return r.registerJSONHooks(r.openInterpreterHooksTarget())
}

func (r *Registry) unregisterOpenInterpreter() UnregistrationResult {
	return r.unregisterJSONHooks(r.openInterpreterHooksTarget())
}

func (r *Registry) registerZcode() RegistrationResult {
	return r.registerJSONHooks(r.zcodeHooksTarget())
}

func (r *Registry) unregisterZcode() UnregistrationResult {
	return r.unregisterJSONHooks(r.zcodeHooksTarget())
}

// devinCLIEvents are the Devin CLI events Observer registers in the CLI's
// user config (the registry row's Registered Devin CLI bindings; the
// Cascade events are cascadeEvents).
var devinCLIEvents = []string{"PreToolUse"}

// devinCLIConfigDir is the Devin CLI's user config directory, per
// docs.devin.ai/cli/extensibility/hooks/overview (fetched 2026-10-06) and
// docs.devin.ai/desktop/cascade/mcp (surface-gap S-10, 2026-10-25):
//
//   - Windows: %APPDATA%\devin, else <home>\AppData\Roaming\devin (the
//     roaming profile can live off the default drive, so the variable wins
//     over the derived path);
//   - Linux and macOS: $XDG_CONFIG_HOME/devin, else ~/.config/devin.
//
// The same directory is the install signal (register_core.go), so detection
// and the write follow one rule. A relative variable value is ignored, as
// every other env-relocated writer here does (envDir). On Windows the
// directory is also Devin Desktop's Electron user-data dir (%APPDATA%\Devin,
// NTFS is case-insensitive; internal/adapter/devin/surface.go).
//
// Since FU-5 the rule is the devin/user-config artifact (its %APPDATA% token
// and its Linux-only XDG_CONFIG_HOME relocation), not a copy here.
func (r *Registry) devinCLIConfigDir() string {
	fallback := filepath.Join(r.opts.HomeDir, ".config", "devin")
	if r.hostGOOS() == "windows" {
		fallback = filepath.Join(r.opts.HomeDir, "AppData", "Roaming", "devin")
	}
	return r.artifactDirOr("devin/user-config", fallback)
}

// devinCLIHooksTarget: the Devin CLI reads the "hooks" key of its user
// config.json (Claude Code's matcher-group shape; devin 3000.11.3 on demo
// node 1 parses the same ClaudeHookConfig). T-478.
func (r *Registry) devinCLIHooksTarget() jsonHooksTarget {
	return jsonHooksTarget{
		tool: "devin", label: "devin-cli", dir: r.devinCLIConfigDir(), file: "config.json",
		eventsPath: []string{"hooks"}, events: devinCLIEvents,
		grouped: true, handler: commandHandler("timeout", 30), commandKey: "command",
		errPrefix: "hook.registerDevinCLI",
	}
}

// registerDevinAll registers the Windsurf / Devin Desktop Cascade hooks and,
// when the Devin CLI is installed (its config directory exists), the CLI's
// tool gate. The two never judge the same call: Cascade and the CLI are
// different hosts with different event names. A home with only the CLI gets
// no Cascade file; a home with neither keeps the earlier behaviour (Cascade).
func (r *Registry) registerDevinAll() RegistrationResult {
	t := r.devinCLIHooksTarget()
	cli := r.dirExists(t.dir)
	res := RegistrationResult{Tool: "devin", DryRun: r.opts.DryRun}
	if r.dirExists(filepath.Join(r.opts.HomeDir, ".codeium", "windsurf")) || !cli {
		res = r.registerCascade()
	}
	if res.Error != nil || !cli {
		return res
	}
	c := r.registerJSONHooks(t)
	if res.ConfigPath == "" {
		res.ConfigPath = c.ConfigPath
	}
	if res.Skipped {
		// The Cascade file stood down for the system hooks file (IDE-6),
		// but the CLI half still registers: report the stand-down as a note
		// on a result that wrote the CLI file.
		res.Warnings = append(res.Warnings, "Devin Desktop: "+res.SkipReason+"; "+res.SkipAdvice)
		res.Skipped, res.SkipKind, res.SkipReason, res.SkipAdvice = false, "", "", ""
		res.ConfigPath = c.ConfigPath
	}
	res.Warnings = append(res.Warnings, c.Warnings...)
	res.HooksAdded = append(res.HooksAdded, c.HooksAdded...)
	res.AlreadySet = append(res.AlreadySet, c.AlreadySet...)
	if c.Error != nil {
		res.Error = c.Error
	}
	return res
}

// unregisterDevinAll removes Observer's Cascade hooks and its Devin CLI
// entry.
func (r *Registry) unregisterDevinAll() UnregistrationResult {
	res := r.unregisterCascade()
	cli := r.unregisterJSONHooks(r.devinCLIHooksTarget())
	// Report the file that actually changed: a CLI-only home removes
	// nothing from the Cascade file.
	if len(res.HooksRemoved) == 0 && len(cli.HooksRemoved) > 0 {
		res.ConfigPath = cli.ConfigPath
	}
	res.HooksRemoved = append(res.HooksRemoved, cli.HooksRemoved...)
	if res.Error == nil && cli.Error != nil {
		res.Error = cli.Error
	}
	return res
}

// museHooksTarget: Muse Code reads Claude-shaped matcher groups under the
// "hooks" key of its user settings, ~/.config/muse/settings.json, beside
// "schema_version": 1 (dev.meta.ai/docs/muse-code/extending; Muse 1.4.3 on
// demo node 1 ran a hook from it with no trust step, T-479). The file holds
// the model and provider choice; the sign-in lives in auth.json, which is
// never read.
func (r *Registry) museHooksTarget() jsonHooksTarget {
	return jsonHooksTarget{
		tool: "muse", dir: filepath.Join(r.opts.HomeDir, ".config", "muse"), file: "settings.json",
		eventsPath: []string{"hooks"}, events: eventsOr("muse", "PreToolUse"),
		grouped: true, handler: commandHandler("timeout", 30), commandKey: "command",
		settings:  []jsonSetting{{path: []string{"schema_version"}, value: 1}},
		errPrefix: "hook.registerMuse",
	}
}

func (r *Registry) registerMuse() RegistrationResult {
	return r.registerJSONHooks(r.museHooksTarget())
}

func (r *Registry) unregisterMuse() UnregistrationResult {
	return r.unregisterJSONHooks(r.museHooksTarget())
}
