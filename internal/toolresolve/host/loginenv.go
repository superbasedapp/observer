package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// CaptureLoginEnv runs the login shell and returns the named variables as it
// sets them (surface-gap CLI-4, the login-env probe): the same attempt
// ladder, guard variables, detached stdin, bounded output and timeout as
// CaptureLoginPath, with toolresolve.LoginEnvScript as the script. A
// variable the shell leaves unset is present with "". An unknown or empty
// shell yields ErrUnsupportedShell.
func CaptureLoginEnv(shell string, names []string, timeout time.Duration) (map[string]string, error) {
	if strings.TrimSpace(shell) == "" {
		return nil, ErrUnsupportedShell
	}
	plan, ok := loginShellTable[filepath.Base(shell)]
	if !ok {
		return nil, ErrUnsupportedShell
	}
	script, err := toolresolve.LoginEnvScript(names)
	if err != nil {
		return nil, err
	}
	if timeout <= 0 {
		timeout = defaultLoginTimeout
	}
	env := append(os.Environ(), captureEnvVars...)
	var lastErr error
	for _, flags := range plan.attempts {
		argv := append(append([]string{shell}, flags...), script)
		out, err := runOneCapture(argv, env, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		got, err := toolresolve.ParseEnvMarkers(out)
		if err != nil {
			lastErr = fmt.Errorf("toolresolve/host: login environment capture (%s): %w", strings.Join(flags, " "), err)
			continue
		}
		return got, nil
	}
	return nil, lastErr
}
