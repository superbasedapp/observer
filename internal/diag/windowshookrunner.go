package diag

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/pspolicy"
	"github.com/marmutapp/superbased-observer/internal/platform/winshell"
)

// windowshookrunner.go - the doctor rows for a host's Windows hook-runner
// preconditions (integration.WindowsHookRunner): a host that runs Observer's
// hook as a PowerShell script needs an execution policy that runs it (gap
// review W-8), and a host that runs hook commands in Git Bash needs Git for
// Windows (S-19). Both dispatch on the row's Kind, never on a tool name, and
// every read is injected through windowsRunnerProbe, so the tests pass fakes
// and nothing shells out there.
//
// Observer never changes an execution policy or any other system setting:
// the policy is read with `Get-ExecutionPolicy -List` and only reported.

// windowsRunnerProbe is every I/O the hook-runner rows need.
type windowsRunnerProbe struct {
	// goos is the observer's own GOOS: "windows" checks the native target,
	// anything else the "-windows" cross-OS bridge.
	goos string
	// getenv reads the WINDOWS environment (nil from WSL, where the Windows
	// environment is not this process's).
	getenv func(string) string
	// windowsPATH is the Windows PATH as this process addresses it
	// (C:\... natively, /mnt/c/... from WSL); ok=false when not visible.
	windowsPATH func() (string, bool)
	// lookPath resolves a bare executable name on this process's PATH.
	lookPath func(string) (string, error)
	// exists reports whether a path names an existing regular file.
	exists func(string) bool
	// readPolicy runs exe with pspolicy.ListScript and returns its output.
	readPolicy func(ctx context.Context, exe string) (string, error)
	// present reports whether Observer's hooks are in target's config, and
	// that config's path.
	present func(target string) (configPath string, ok bool)
}

// checkWindowsHookRunners builds the production probe and renders the rows.
// A sandboxed run (homeOverride non-empty) reads no environment, no foreign
// home and runs no PowerShell, so it reports nothing; so does an observer
// that is neither on Windows nor in WSL (no Windows side to check). getenv
// is the doctor's one lookup (under the pinned-home rule, FU-129): the
// dry-run registry resolves the hook targets' config homes through it.
func checkWindowsHookRunners(ctx context.Context, homeOverride, binaryPath string, getenv func(string) string) []Check {
	if homeOverride != "" {
		return nil
	}
	goos := runtime.GOOS
	if goos != "windows" && os.Getenv("WSL_DISTRO_NAME") == "" {
		return nil
	}
	if binaryPath == "" {
		binaryPath = "observer"
	}
	reg, err := hook.NewRegistry(hook.Options{
		BinaryPath: binaryPath, DryRun: true,
		Getenv: getenv, WindowsPATH: hook.PersistentWindowsPATH, WSLDistro: os.Getenv("WSL_DISTRO_NAME"),
	})
	if err != nil {
		return nil
	}
	p := windowsRunnerProbe{
		goos:       goos,
		lookPath:   exec.LookPath,
		exists:     regularFile,
		readPolicy: readExecutionPolicyList,
		present: func(target string) (string, bool) {
			// A dry-run Unregister lists the events whose entries Observer
			// owns in the file, whatever binary path they name; it writes
			// nothing.
			res := reg.Unregister(target)
			return res.ConfigPath, res.Error == nil && len(res.HooksRemoved) > 0
		},
	}
	p.windowsPATH = hook.PersistentWindowsPATH
	if goos == "windows" {
		p.getenv = os.Getenv
		p.windowsPATH = func() (string, bool) {
			if v, ok := hook.PersistentWindowsPATH(); ok {
				return v, true
			}
			v := os.Getenv("PATH")
			return v, v != ""
		}
	}
	return windowsHookRunnerChecks(ctx, p)
}

// regularFile is the production file probe.
func regularFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// windowsHookRunnerChecks renders one row per declared runner whose Windows
// target carries Observer's hooks. A target without Observer's hooks, or a
// precondition nothing visible can answer, yields no row, so the doctor
// never raises a false alarm.
func windowsHookRunnerChecks(ctx context.Context, p windowsRunnerProbe) []Check {
	var out []Check
	for _, r := range integration.WindowsHookRunners() {
		c, ok := integration.For(r.Tool)
		if !ok {
			continue
		}
		target := r.Tool
		if p.goos != "windows" {
			if !c.Hook.CrossOSBridge {
				continue
			}
			target += "-windows"
		}
		if p.present == nil {
			continue
		}
		cfg, ok := p.present(target)
		if !ok {
			continue
		}
		var row Check
		switch r.Kind {
		case integration.RunnerPowerShellScript:
			row, ok = executionPolicyCheck(ctx, target, cfg, r, p)
		case integration.RunnerGitBash:
			row, ok = gitBashCheck(target, cfg, r, p)
		default:
			ok = false
		}
		if ok {
			out = append(out, row)
		}
	}
	return out
}

// failureClause is what the host does with the tool call when the hook
// cannot run, as the warning says it.
var failureClause = map[integration.RunnerFailure]string{
	integration.FailureOpen:       "runs every tool call without Observer's hook (it fails open), so guard enforcement stops",
	integration.FailureUnverified: "cannot run Observer's hook (what it then does with the tool call is not verified)",
}

// localPolicyFix is the remediation when a scope the developer owns blocks
// (a runner that does not pass -ExecutionPolicy Bypass). Observer never runs
// it.
const localPolicyFix = "run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` yourself in that PowerShell (Observer never changes the execution policy)"

// executionPolicyCheck is the RunnerPowerShellScript row: the effective
// execution policy of the PowerShell the host would pick, from its
// `Get-ExecutionPolicy -List`, evaluated against how the host launches it.
// ok is false when none of the host's PowerShell candidates is visible.
func executionPolicyCheck(ctx context.Context, target, cfg string, r integration.WindowsHookRunner, p windowsRunnerProbe) (Check, bool) {
	name := target + ".hooks.execution_policy"
	display := integration.DisplayName(r.Tool)
	candidates := powerShellCandidates(r.PowerShell, p)
	if len(candidates) == 0 || p.readPolicy == nil {
		return Check{}, false
	}
	details := []string{
		fmt.Sprintf("%s: Observer's hook scripts under %s", target, cfg),
		"Observer only reads the execution policy; it never changes it",
	}
	var (
		list    pspolicy.List
		exe     string
		lastErr error
	)
	for _, cand := range candidates {
		outText, err := p.readPolicy(ctx, cand)
		if err == nil {
			list, err = pspolicy.ParseList(outText)
		}
		if err == nil {
			exe = cand
			break
		}
		lastErr = err
	}
	if exe == "" {
		return Check{
			Name: name, Status: StatusWarn,
			Message: fmt.Sprintf("could not read the PowerShell execution policy (%v); if Group Policy sets AllSigned or Restricted, %s %s",
				lastErr, display, failureClause[r.OnFailure]),
			Details: append(details, "tried: "+strings.Join(candidates, ", ")),
		}, true
	}
	v := pspolicy.Evaluate(list, pspolicy.Launch{BypassArg: r.BypassArg})
	where := "no scope sets a policy"
	if v.Scope != "" {
		where = "set at the " + string(v.Scope) + " scope"
		if v.GroupPolicy {
			where += " (Group Policy)"
		}
	}
	details = append(details,
		"PowerShell the host runs: "+exe,
		"scopes (Get-ExecutionPolicy -List): "+formatPolicyList(list))
	switch v.Outcome {
	case pspolicy.Runs:
		return Check{
			Name: name, Status: StatusOK,
			Message: fmt.Sprintf("execution policy %s (%s) runs Observer's hook scripts: %s", v.Policy, where, v.Reason),
			Details: details,
		}, true
	case pspolicy.Blocks:
		if v.OverridesBypass {
			where += ", which overrides the host's -ExecutionPolicy Bypass"
		}
		msg := fmt.Sprintf("%s runs Observer's hook as a PowerShell script, and the effective execution policy is %s (%s): %s.", display, v.Policy, where, v.Reason)
		if !v.Certain {
			msg += " On a Windows client edition"
		} else {
			msg += " So"
		}
		msg += " PowerShell refuses the script and " + display + " " + failureClause[r.OnFailure]
		fix := localPolicyFix
		if v.GroupPolicy {
			fix = r.Fix
		}
		return Check{Name: name, Status: StatusWarn, Message: msg + "; " + fix, Details: details}, true
	}
	return Check{
		Name: name, Status: StatusWarn,
		Message: fmt.Sprintf("execution policy %s (%s) is not a value Observer classifies, so it cannot say whether %s runs Observer's hook scripts", v.Policy, where, display),
		Details: details,
	}, true
}

// powerShellCandidates resolves the row's PowerShell list, in the host's
// order, to the executables this process can run: a `%VAR%` entry only on a
// Windows observer with its environment, a bare name through lookPath.
func powerShellCandidates(list []string, p windowsRunnerProbe) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range list {
		var path string
		if strings.Contains(c, "%") {
			if p.goos != "windows" || p.getenv == nil || p.exists == nil {
				continue
			}
			expanded, ok := expandWindowsVars(c, p.getenv)
			if !ok || !p.exists(expanded) {
				continue
			}
			path = expanded
		} else {
			if p.lookPath == nil {
				continue
			}
			found, err := p.lookPath(c)
			if err != nil {
				continue
			}
			path = found
		}
		key := strings.ToLower(path)
		if !seen[key] {
			seen[key] = true
			out = append(out, path)
		}
	}
	return out
}

// expandWindowsVars expands every %VAR% in s; ok is false when one is unset.
func expandWindowsVars(s string, getenv func(string) string) (string, bool) {
	var b strings.Builder
	for {
		i := strings.Index(s, "%")
		if i < 0 {
			b.WriteString(s)
			return b.String(), true
		}
		j := strings.Index(s[i+1:], "%")
		if j < 0 {
			return "", false
		}
		v := getenv(s[i+1 : i+1+j])
		if v == "" {
			return "", false
		}
		b.WriteString(s[:i])
		b.WriteString(v)
		s = s[i+2+j:]
	}
}

// formatPolicyList renders the scopes in precedence order.
func formatPolicyList(l pspolicy.List) string {
	parts := make([]string, 0, len(pspolicy.Precedence))
	for _, s := range pspolicy.Precedence {
		v := l[s]
		if v == "" {
			v = pspolicy.Undefined
		}
		parts = append(parts, string(s)+"="+string(v))
	}
	return strings.Join(parts, ", ")
}

// gitBashCheck is the RunnerGitBash row: whether Git for Windows' bash.exe
// is where a host that locates it itself would look. The order: the row's
// environment override (visible only to a Windows observer), then the Git
// for Windows layout beside a git.exe on the Windows PATH, then the default
// install directory. ok is false when nothing visible can answer (no Windows
// PATH and no default directory found).
func gitBashCheck(target, cfg string, r integration.WindowsHookRunner, p windowsRunnerProbe) (Check, bool) {
	name := target + ".hooks.git_bash"
	display := integration.DisplayName(r.Tool)
	details := []string{
		fmt.Sprintf("%s: Observer's hooks in %s", target, cfg),
		fmt.Sprintf("%s's own Git Bash lookup beyond %s is not documented; Observer checks the standard Git for Windows layout, so an install elsewhere can be missed", display, r.EnvOverride),
	}
	if p.exists == nil {
		return Check{}, false
	}
	found := func(path, how string) (Check, bool) {
		return Check{
			Name: name, Status: StatusOK,
			Message: fmt.Sprintf("%s runs hook commands in Git Bash; bash.exe found at %s (%s)", display, path, how),
			Details: details,
		}, true
	}
	if p.goos == "windows" && p.getenv != nil && r.EnvOverride != "" {
		if v := strings.TrimSpace(p.getenv(r.EnvOverride)); v != "" {
			if p.exists(v) {
				return found(v, r.EnvOverride)
			}
			return Check{
				Name: name, Status: StatusWarn,
				Message: fmt.Sprintf("%s runs hook commands in Git Bash, and %s names %s, which does not exist, so %s %s; %s",
					display, r.EnvOverride, v, display, failureClause[r.OnFailure], r.Fix),
				Details: details,
			}, true
		}
	}
	if p.goos != "windows" {
		details = append(details, "an override set in the Windows environment is not visible from WSL")
	}
	pathGOOS := "linux"
	if p.goos == "windows" {
		pathGOOS = "windows"
	}
	pathEnv, pathKnown := "", false
	if p.windowsPATH != nil {
		pathEnv, pathKnown = p.windowsPATH()
	}
	if pathKnown {
		if st, git := winshell.Check("git", pathGOOS, pathEnv, p.exists); st == winshell.Found {
			for _, bash := range gitBashBesideGit(git) {
				if p.exists(bash) {
					return found(bash, "the Git for Windows install of "+git)
				}
			}
		} else if st == winshell.Unknown {
			pathKnown = false
		}
	}
	defaults := []string{"/mnt/c/Program Files/Git/bin/bash.exe"}
	if p.goos == "windows" {
		defaults = nil
		if p.getenv != nil {
			if d, ok := expandWindowsVars(`%ProgramFiles%\Git\bin\bash.exe`, p.getenv); ok {
				defaults = append(defaults, d)
			}
		}
	}
	for _, d := range defaults {
		if p.exists(d) {
			return found(d, "the default Git for Windows directory")
		}
	}
	if !pathKnown {
		return Check{}, false
	}
	return Check{
		Name: name, Status: StatusWarn,
		Message: fmt.Sprintf("%s runs hook commands in Git Bash on Windows and reports an error without it; Observer found no bash.exe (%s unset, none beside git.exe on the Windows PATH or in the default directory), so %s %s; %s",
			display, r.EnvOverride, display, failureClause[r.OnFailure], r.Fix),
		Details: details,
	}, true
}

// gitBashBesideGit is where Git for Windows keeps bash.exe relative to a
// git.exe on PATH: <root>\cmd\git.exe and <root>\mingw64\bin\git.exe (and
// <root>\bin\git.exe) all sit under the install root that holds bin\bash.exe.
func gitBashBesideGit(git string) []string {
	sep := "/"
	if strings.Contains(git, `\`) {
		sep = `\`
	}
	parent := func(p string) string {
		if i := strings.LastIndexAny(p, `\/`); i > 0 {
			return p[:i]
		}
		return ""
	}
	var out []string
	dir := parent(git)
	for i := 0; i < 2 && dir != ""; i++ {
		dir = parent(dir)
		if dir == "" {
			break
		}
		out = append(out, dir+sep+"bin"+sep+"bash.exe")
	}
	return out
}
