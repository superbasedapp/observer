//go:build !windows

package hook

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/platform/winshell"
)

// persistentPATHScript prints the machine PATH, then the user PATH, as the
// registry holds them (expanded), on one line.
const persistentPATHScript = `[Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')`

// readPersistentWindowsPATH asks Windows for its persistent PATH through WSL
// interop. Outside WSL (no WSL_DISTRO_NAME) or without powershell.exe on the
// interop PATH it reports ok=false, and the caller falls back to the process
// PATH.
func readPersistentWindowsPATH() (string, bool) {
	if os.Getenv("WSL_DISTRO_NAME") == "" {
		return "", false
	}
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", persistentPATHScript).Output()
	if err != nil {
		return "", false
	}
	list := winshell.WSLPathList(strings.TrimSpace(string(out)))
	if list == "" {
		return "", false
	}
	return list, true
}
