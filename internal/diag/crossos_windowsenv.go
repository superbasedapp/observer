package diag

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/mcpregister"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// checkWindowsSideRelocation names the relocation variables set on the
// Windows side while a WSL daemon's cross-OS "-windows" targets are in use
// (surface-gap FU-70, FU-32). Those targets resolve each tool's file under
// the Windows home at the vendor default, because the Windows environment is
// not the daemon's; a Windows tool whose variable moves its config reads
// another file, so its hooks, MCP entry or route are not the ones it runs.
// A sandboxed run, a non-WSL host and an unreadable Windows environment
// report nothing. Names only: a value is never printed.
func checkWindowsSideRelocation(homeOverride, binaryPath string) (Check, bool) {
	if homeOverride != "" {
		return Check{}, false
	}
	if binaryPath == "" {
		binaryPath = "observer"
	}
	var targets []string
	if reg, err := hook.NewRegistry(hook.Options{BinaryPath: binaryPath, WSLDistro: os.Getenv("WSL_DISTRO_NAME")}); err == nil {
		targets = append(targets, windowsTargets(reg.Installed())...)
	}
	if mr, err := mcpregister.NewRegistrar(mcpregister.RegisterOptions{BinaryPath: binaryPath}); err == nil {
		targets = append(targets, windowsTargets(mr.Installed())...)
	}
	if len(targets) == 0 {
		return Check{}, false
	}
	vals, ok := crossmount.WindowsPersistentEnv(agentconfig.RelocationVariables(), probeWindowsEnv)
	return windowsRelocationCheck(targets, vals, ok)
}

// windowsTargets keeps the "-windows" targets of a detection list.
func windowsTargets(installed []string) []string {
	var out []string
	for _, t := range installed {
		if strings.HasSuffix(t, "-windows") {
			out = append(out, t)
		}
	}
	return out
}

// windowsRelocationCheck renders the row: none when the environment could
// not be read or no relocation variable is set there.
func windowsRelocationCheck(targets []string, vals map[string]string, ok bool) (Check, bool) {
	if !ok || len(vals) == 0 || len(targets) == 0 {
		return Check{}, false
	}
	names := make([]string, 0, len(vals))
	for n := range vals {
		names = append(names, n)
	}
	sort.Strings(names)
	sort.Strings(targets)
	return Check{
		Name:    "crossos.windows_env",
		Status:  StatusWarn,
		Message: fmt.Sprintf("set on the Windows side: %s; the cross-OS targets write each tool's default file under the Windows home", strings.Join(names, ", ")),
		Details: []string{
			"cross-OS targets in use: " + strings.Join(targets, ", "),
			"a Windows tool whose variable above moves its config reads another file than the one Observer wrote, so its hooks, MCP entry or route are not the ones it runs; unset the variable, or wire that tool from a Windows-native observer",
		},
	}, true
}

// probeWindowsEnv runs crossmount's environment-read script through the
// Windows powershell.exe over WSL interop, with a timeout; ok is false on
// any failure. The script is built by crossmount from validated variable
// names only.
func probeWindowsEnv(script string) (string, bool) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	//nolint:gosec // G204: powershell.exe with a script built only from validated variable names.
	out, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return "", false
	}
	return string(out), true
}
