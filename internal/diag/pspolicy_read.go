package diag

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/pspolicy"
)

// readExecutionPolicyList is the production windowsRunnerProbe.readPolicy:
// it runs exe (a PowerShell the host would run) with pspolicy.ListScript and
// returns the `Scope=Policy` lines. Read-only: Get-ExecutionPolicy changes
// nothing, -NoProfile loads no profile script, and an inline -Command is not
// subject to the execution policy it reads. Called only for a target that
// carries Observer's hook scripts, on a Windows observer or from WSL through
// interop (the hook.PersistentWindowsPATH precedent).
func readExecutionPolicyList(ctx context.Context, exe string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "-NoProfile", "-NonInteractive", "-Command", pspolicy.ListScript).Output() //nolint:gosec // G204: exe is the PowerShell the host would run, with a fixed read-only argv
	if err != nil {
		return "", fmt.Errorf("diag.readExecutionPolicyList: %s: %w", exe, err)
	}
	return strings.TrimSpace(string(out)), nil
}
