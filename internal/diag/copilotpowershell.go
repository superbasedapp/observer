package diag

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/remedy"
)

// checkCopilotCLIPowerShellOnHost is checkCopilotCLIPowerShell for this
// process's own OS.
func checkCopilotCLIPowerShellOnHost(homeOverride, binaryPath string, getenv func(string) string) []Check {
	return checkCopilotCLIPowerShell(runtime.GOOS, homeOverride, binaryPath, getenv)
}

// checkCopilotCLIPowerShell is the doctor row of FU-166: on a Windows-native
// Observer, Observer's own Copilot CLI hooks file must carry a "powershell"
// command, the only field Copilot CLI runs on Windows. A file an older build
// wrote with only "bash" makes every Copilot CLI tool call fail closed (the
// hook exits 127), so the row is a FAIL. On a WSL (or other non-Windows)
// Observer the same row reads the copilot-cli-windows bridge it writes into
// the Windows home, which an older build also wrote bash-only (FU-166 tail).
// The registry walk is the writer's (hook.Registry.CopilotCLIPowerShell and
// CopilotCLIWindowsPowerShell): the same targets and ownership rule, read
// only. goos is the Observer's own OS (runtime.GOOS in production).
// getenv is the doctor's (DoctorOptions.Getenv, the pinned-home rule
// already applied; FU-173), read for COPILOT_HOME like every other probe.
// A sandboxed run (homeOverride non-empty) reads the sandbox home and no
// environment. No row when the check does not apply or Observer has no
// entry in the file.
func checkCopilotCLIPowerShell(goos, homeOverride, binaryPath string, getenv func(string) string) []Check {
	if binaryPath == "" {
		binaryPath = "observer"
	}
	if homeOverride != "" {
		getenv = nil
	}
	reg, err := hook.NewRegistry(hook.Options{
		BinaryPath: binaryPath, HomeDir: homeOverride, Getenv: getenv, GOOS: goos, DryRun: true,
	})
	if err != nil {
		return nil
	}
	return copilotCLIPowerShellRows(reg)
}

// copilotCLIPowerShellRows renders reg's two reports (at most one applies on
// a host: the native file on Windows, the bridge elsewhere).
func copilotCLIPowerShellRows(reg *hook.Registry) []Check {
	var out []Check
	for _, rep := range []hook.CopilotCLIPowerShellReport{reg.CopilotCLIPowerShell(), reg.CopilotCLIWindowsPowerShell()} {
		if c, ok := copilotCLIPowerShellCheck(rep); ok {
			out = append(out, c)
		}
	}
	return out
}

// copilotCLIPowerShellCheckName scopes to `observer doctor copilot-cli` and
// `observer doctor hooks`.
const copilotCLIPowerShellCheckName = "copilot-cli.hooks.powershell"

// copilotCLIPowerShellCheck renders one report. ok is false when there is
// nothing to say (the report does not apply, or no Observer entry).
func copilotCLIPowerShellCheck(rep hook.CopilotCLIPowerShellReport) (Check, bool) {
	if !rep.Applies {
		return Check{}, false
	}
	details := []string{"Copilot CLI on Windows runs a hook's \"powershell\" command and ignores its \"bash\" one"}
	if rep.Unreadable {
		return Check{
			Name: copilotCLIPowerShellCheckName, Status: StatusWarn,
			Message: fmt.Sprintf("could not read Observer's Copilot CLI hooks file %s, so whether Copilot CLI can run Observer's hook on Windows is unknown", rep.ConfigPath),
			Details: details,
		}, true
	}
	if len(rep.Registered) == 0 {
		return Check{}, false
	}
	details = append(details, fmt.Sprintf("Observer's entries in %s: %s", rep.ConfigPath, strings.Join(rep.Registered, ", ")))
	if rep.Target == "copilot-cli-windows" {
		details = append(details, "written by this Observer's copilot-cli-windows bridge (the Windows home seen from WSL)")
	}
	if len(rep.Stale) == 0 {
		return Check{
			Name: copilotCLIPowerShellCheckName, Status: StatusOK,
			Message: "Observer's Copilot CLI hooks carry the powershell command Copilot CLI runs on Windows",
			Details: details,
		}, true
	}
	fixes := []remedy.Remediation{remedy.Of(remedy.RestartDaemon, ""), remedy.Of(remedy.InitTool, "copilot-cli")}
	return Check{
		Name: copilotCLIPowerShellCheckName, Status: StatusFail,
		Message: fmt.Sprintf("Observer's Copilot CLI hook for %s in %s has no powershell command (an older Observer build wrote it with bash only). "+
			"Copilot CLI on Windows runs only that field, so the hook exits 127 and Copilot CLI fails every tool call closed. "+
			"Restart the Observer daemon (`observer start` rewrites Observer's own entry) or run %s; Observer leaves any other hook in the file as it is",
			strings.Join(rep.Stale, ", "), rep.ConfigPath, remedy.Quote(fixes[1])),
		Details:      details,
		Remediations: fixes,
	}, true
}
