package integration

import (
	"fmt"
	"sort"
	"strings"
)

// HookShellRequirement is HookSpec.WindowsHookShell: the shell executable a
// host's Windows hook runner spawns by bare name, so it has to resolve on the
// Windows PATH of the host process. A capability, not a tool branch: the hook
// registrars and the doctor ask the row whether it carries one.
type HookShellRequirement struct {
	// Shell is the bare executable name the runner spawns ("sh"). Empty means
	// no requirement.
	Shell string
	// ProvidedBy names the environment that normally puts Shell on PATH for
	// the host when it is launched from there ("Git Bash"), so the warning
	// can say when the host still works.
	ProvidedBy string
	// Fix is the operator's remediation, phrased as an instruction.
	Fix string
	// Grounding records where the requirement was read (vendor version and
	// source location).
	Grounding string
}

// Required reports whether the requirement is set.
func (h HookShellRequirement) Required() bool { return h.Shell != "" }

// WindowsHookShellFor returns tool's Windows hook-shell requirement. A
// "-windows" cross-OS target answers for its base row (the bridge is run by
// the same Windows host). ok is false when the row has none.
func WindowsHookShellFor(tool string) (HookShellRequirement, bool) {
	c, found := For(strings.TrimSuffix(tool, "-windows"))
	if !found || !c.Hook.WindowsHookShell.Required() {
		return HookShellRequirement{}, false
	}
	return c.Hook.WindowsHookShell, true
}

// WindowsHookShellTools lists, sorted, every registry row whose Windows hook
// runner needs a shell on PATH.
func WindowsHookShellTools() []string {
	var out []string
	for _, c := range Capabilities() {
		if c.Hook.WindowsHookShell.Required() {
			out = append(out, c.Tool)
		}
	}
	sort.Strings(out)
	return out
}

// WindowsHookShellWarning is the one operator-facing sentence for tool when
// its Windows hook shell does not resolve on the Windows PATH. Registration
// results and `observer doctor` both render it, so the two never disagree.
// Empty when tool carries no requirement.
func WindowsHookShellWarning(tool string) string {
	req, ok := WindowsHookShellFor(tool)
	if !ok {
		return ""
	}
	name := DisplayName(strings.TrimSuffix(tool, "-windows"))
	exe := req.Shell
	if !strings.Contains(exe, ".") {
		exe += ".exe"
	}
	where := ""
	if req.ProvidedBy != "" {
		where = " outside " + req.ProvidedBy
	}
	msg := fmt.Sprintf("%s runs hooks with `%s`; %s is not on the Windows PATH, so %s launched%s will skip every Observer hook",
		name, req.Shell, exe, name, where)
	if req.Fix != "" {
		msg += "; " + req.Fix
	}
	return msg
}

// WindowsHookRunnerKind is the closed set of Windows hook-runner
// preconditions a WindowsHookRunner row declares. Distinct from
// HookSpec.WindowsHookShell, which is a shell the runner spawns BY BARE NAME
// on PATH: the kinds here locate their interpreter themselves, so a PATH
// lookup of a bare name would answer the wrong question.
type WindowsHookRunnerKind string

const (
	// RunnerPowerShellScript: the host runs Observer's Windows hook as a .ps1
	// script file through PowerShell (`-File`), so the PowerShell execution
	// policy decides whether it runs at all.
	RunnerPowerShellScript WindowsHookRunnerKind = "powershell_script"
	// RunnerGitBash: the host runs every hook command in Git for Windows'
	// bash.exe, which it locates itself (an environment override, else its
	// own lookup), and reports an error when Git Bash is absent.
	RunnerGitBash WindowsHookRunnerKind = "git_bash"
)

// RunnerFailure is what the host does with the tool call when its Windows
// hook runner cannot run Observer's hook.
type RunnerFailure string

const (
	// FailureUnverified (zero value): not grounded.
	FailureUnverified RunnerFailure = ""
	// FailureOpen: the host runs the tool call without the hook, so guard
	// enforcement silently stops.
	FailureOpen RunnerFailure = "fails_open"
)

// WindowsHookRunner is HookSpec.WindowsRunner: a precondition of a host's
// Windows hook runner that the doctor checks. Data only; the doctor
// dispatches on Kind, never on Tool.
type WindowsHookRunner struct {
	// Tool is the registry row the precondition belongs to. A row on
	// HookSpec leaves it empty: WindowsHookRunnerFor and WindowsHookRunners
	// fill it from the capability, so the tool is named once, by the row.
	Tool string
	Kind WindowsHookRunnerKind
	// PowerShell lists, for RunnerPowerShellScript, the executables the host
	// tries in its own order; the first that runs is the one whose policy
	// applies (Windows PowerShell 5.1 and PowerShell 7 keep separate policy
	// stores). A `%VAR%` token is expanded from the Windows environment; a
	// bare name is looked up on PATH.
	PowerShell []string
	// BypassArg is true when the host passes `-ExecutionPolicy Bypass`, so
	// only a Group Policy scope (MachinePolicy, UserPolicy) can block.
	BypassArg bool
	// EnvOverride is, for RunnerGitBash, the environment variable that names
	// bash.exe's full path for the host.
	EnvOverride string
	// OnFailure is what the host does with the tool call when the hook
	// cannot run.
	OnFailure RunnerFailure
	// Fix is the operator's remediation, phrased as an instruction.
	Fix string
	// Grounding records where each fact was read (vendor version and source
	// location).
	Grounding string
}

// Declared reports whether the runner precondition is set (a non-zero Kind).
func (r WindowsHookRunner) Declared() bool { return r.Kind != "" }

// windowsRunnerDirac is the dirac row's HookSpec.WindowsRunner (gap review
// W-8, AP-119). One owner per tool: TestWindowsHookRunnerRows pins that no
// row carrying a WindowsRunner also declares HookSpec.WindowsHookShell.
var windowsRunnerDirac = WindowsHookRunner{
	Kind: RunnerPowerShellScript,
	PowerShell: []string{
		`%ProgramFiles%\PowerShell\7\pwsh.exe`,
		`%ProgramFiles%\PowerShell\6\pwsh.exe`,
		"pwsh.exe",
		"powershell.exe",
	},
	BypassArg: true,
	OnFailure: FailureOpen,
	Fix:       "ask the administrator who owns the Group Policy to allow RemoteSigned for this machine or user, or to sign Observer's hook scripts with a code-signing certificate the policy trusts (AllSigned accepts a trusted signature)",
	Grounding: `dirac master src/core/hooks/HookLaunchConfig.ts: args ["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",scriptPath]; src/utils/powershell.ts getWindowsPowerShellCandidates: %ProgramFiles%\PowerShell\7\pwsh.exe, ...\6\pwsh.exe, pwsh.exe, powershell.exe, first that runs wins (read 2026-10-25); exit 1 and a crash fail open (docs/adapter-parity.md Dirac PreToolUse, live 2026-10-21); gap review W-8, AP-119`,
}

// windowsRunnerCodeBuddy is the codebuddy row's HookSpec.WindowsRunner (gap
// review S-19).
var windowsRunnerCodeBuddy = WindowsHookRunner{
	Kind:        RunnerGitBash,
	EnvOverride: "CODEBUDDY_CODE_GIT_BASH_PATH",
	// The vendor documents an error prompting a Git for Windows install;
	// whether the tool call then runs is not grounded.
	OnFailure: FailureUnverified,
	Fix:       `install Git for Windows, or set CODEBUDDY_CODE_GIT_BASH_PATH to the full path of bash.exe (for example C:\Program Files\Git\bin\bash.exe)`,
	Grounding: "https://www.codebuddy.cn/docs/cli/hooks (read 2026-10-25): on Windows hook commands are forced through Git Bash (cmd.exe and PowerShell are not supported), CODEBUDDY_CODE_GIT_BASH_PATH names bash.exe, and a missing Git Bash reports an error asking to install Git for Windows; the automatic lookup is not documented; gap review S-19",
}

// WindowsHookRunnerFor returns tool's Windows hook-runner precondition, read
// from its registry row's HookSpec.WindowsRunner. A "-windows" cross-OS
// target answers for its base row. ok is false when the row declares none.
func WindowsHookRunnerFor(tool string) (WindowsHookRunner, bool) {
	c, found := For(strings.TrimSuffix(tool, "-windows"))
	if !found || !c.Hook.WindowsRunner.Declared() {
		return WindowsHookRunner{}, false
	}
	return runnerOf(c), true
}

// WindowsHookRunners lists every declared Windows hook-runner precondition,
// sorted by tool. The slices are copies, so a caller cannot edit the
// registry.
func WindowsHookRunners() []WindowsHookRunner {
	var out []WindowsHookRunner
	for _, c := range Capabilities() {
		if c.Hook.WindowsRunner.Declared() {
			out = append(out, runnerOf(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}

// runnerOf returns a copy of c's runner row with Tool set to the row.
func runnerOf(c Capability) WindowsHookRunner {
	r := cloneRunner(c.Hook.WindowsRunner)
	r.Tool = c.Tool
	return r
}

func cloneRunner(r WindowsHookRunner) WindowsHookRunner {
	r.PowerShell = append([]string(nil), r.PowerShell...)
	return r
}
