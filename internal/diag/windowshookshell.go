package diag

import (
	"fmt"
	"os"

	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/platform/winshell"
)

// checkWindowsHookShells reports, per tool whose Windows hook runner spawns a
// shell by name (integration.HookSpec.WindowsHookShell, today VT Code's
// `sh -c`), whether that shell resolves on the Windows PATH while Observer's
// hooks are registered on the Windows side. A missing shell makes the host
// skip every hook and fail open, so guard enforcement silently stops.
//
// The registry walk (hook.Registry.WindowsHookShellReports) is the same one
// registration warns from: the native target on a Windows observer, the
// "-windows" bridge from WSL. A sandboxed run (homeOverride non-empty) pins
// the registry's home, which suppresses cross-OS detection as every other
// cross-OS check here does.
//
// getenv is the doctor's one lookup (under the pinned-home rule, FU-129).
func checkWindowsHookShells(homeOverride, binaryPath string, getenv func(string) string) []Check {
	if binaryPath == "" {
		binaryPath = "observer"
	}
	// HomeDir is the caller's RAW override: "" lets the registry resolve the
	// real home, non-empty pins it (and switches cross-OS detection off).
	// The probe is a dry run (hook.Registry.Probe): nothing is written.
	// A sandboxed run gets no environment either, so it never reads the real
	// %APPDATA% config or PATH (no row: the PATH answer is Unknown).
	windowsPATH := hook.PersistentWindowsPATH
	if homeOverride != "" {
		getenv, windowsPATH = nil, nil
	}
	reg, err := hook.NewRegistry(hook.Options{
		BinaryPath: binaryPath, HomeDir: homeOverride,
		Getenv: getenv, WindowsPATH: windowsPATH, WSLDistro: os.Getenv("WSL_DISTRO_NAME"),
	})
	if err != nil {
		return nil
	}
	return windowsHookShellChecks(reg.WindowsHookShellReports())
}

// windowsHookShellChecks renders reports: one check per target whose hooks are
// registered and whose PATH answer is known. Status: WARN when the shell is
// not found (the registration warning's own sentence), OK when found. An
// unregistered target or an Unknown answer (no Windows PATH visible) yields
// no row, so the doctor never raises a false alarm.
//
// Named "<target>.hooks.windows_shell" so `observer doctor vtcode` and
// `observer doctor hooks` both scope to it.
func windowsHookShellChecks(reports []hook.WindowsShellReport) []Check {
	var out []Check
	for _, rep := range reports {
		if !rep.Registered {
			continue
		}
		name := rep.Target + ".hooks.windows_shell"
		details := []string{fmt.Sprintf("%s: Observer's hooks in %s", rep.Target, rep.ConfigPath)}
		switch rep.Status {
		case winshell.Found:
			out = append(out, Check{
				Name: name, Status: StatusOK,
				Message: fmt.Sprintf("`%s` resolves on the Windows PATH (%s)", rep.Shell, rep.ShellPath),
				Details: details,
			})
		case winshell.NotFound:
			out = append(out, Check{
				Name: name, Status: StatusWarn,
				Message: rep.Warning,
				Details: append(details,
					"checked against the Windows PATH this process sees; a host started from a shell that adds the directory itself still runs its hooks"),
			})
		}
	}
	return out
}
