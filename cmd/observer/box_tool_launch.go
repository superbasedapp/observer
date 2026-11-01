package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// box_tool_launch.go names a tool launch that failed inside a sandbox box
// (Windows 11 Pro run 4, 2026-10-23: the inner `observer claude` logged only
// "exited with code 1", so the run could not tell which binary it ran or
// what Windows said). Inside a box that names an inner log, every launcher's
// tool start and tool exit go through noteBoxToolLaunch: the resolved tool
// path, its argv with secret flag values removed, and the Win32 error code
// and message when there is one. Outside a box it does nothing.

// boxWin32Message is the system's text for a Win32 error code
// (FormatMessage, box_tool_launch_windows.go); nil where Windows codes have
// no system text, which leaves the code alone in the line.
var boxWin32Message func(code uint32) string

// boxSecretFlagWords mark a flag whose value is never logged.
var boxSecretFlagWords = []string{"key", "token", "secret", "password", "passwd", "auth", "credential", "cookie"}

// boxSecretFlag reports whether a flag's name marks a secret value.
func boxSecretFlag(name string) bool {
	n := strings.ToLower(strings.TrimLeft(name, "-"))
	if n == "" {
		return false
	}
	for _, w := range boxSecretFlagWords {
		if strings.Contains(n, w) {
			return true
		}
	}
	return false
}

// boxSafeArgv is args with the value of every secret flag replaced, in both
// the `--flag value` and the `--flag=value` spellings.
func boxSafeArgv(args []string) []string {
	out := make([]string, len(args))
	mask := false
	for i, a := range args {
		switch {
		case mask:
			out[i], mask = "[REDACTED]", false
		case strings.HasPrefix(a, "-") && strings.Contains(a, "="):
			name, _, _ := strings.Cut(a, "=")
			out[i] = a
			if boxSecretFlag(name) {
				out[i] = name + "=[REDACTED]"
			}
		case strings.HasPrefix(a, "-") && boxSecretFlag(a):
			out[i], mask = a, true
		default:
			out[i] = a
		}
	}
	return out
}

// boxToolOutcome is how a tool launch ended: it did not start (StartErr),
// or it ran and exited with Exit.
type boxToolOutcome struct {
	StartErr error
	Exit     int
}

// boxToolOutcomeOf reads a launcher's Start or Wait error. ok is false for
// nil (nothing to report).
func boxToolOutcomeOf(err error) (boxToolOutcome, bool) {
	if err == nil {
		return boxToolOutcome{}, false
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return boxToolOutcome{Exit: ee.ExitCode()}, true
	}
	return boxToolOutcome{StartErr: err}, true
}

// boxExitShapes classify a tool's exit code, first match wins: a negative
// code (no exit status: a signal), an HRESULT carrying a Win32 error
// (facility 7, the loader's and the .NET host's way to fail), an NTSTATUS
// error (a process that failed while starting or crashed), or a plain exit
// code, which is the tool's own answer. loud: the line is also printed,
// because the tool cannot have said it itself.
var boxExitShapes = []struct {
	match    func(code int64) bool
	loud     bool
	describe func(code int64, msg func(uint32) string) string
}{
	{func(c int64) bool { return c < 0 }, true, func(int64, func(uint32) string) string {
		return " (no exit status: it was ended by a signal or could not be waited for)"
	}},
	{func(c int64) bool { return uint32(c)&0xFFFF0000 == 0x80070000 }, true, func(c int64, msg func(uint32) string) string {
		w := uint32(c) & 0xFFFF
		return fmt.Sprintf(" (0x%08X: the HRESULT of Win32 error %d%s)", uint32(c), w, boxWin32Text(w, msg))
	}},
	// 0xFFFFFFFF is the code TerminateProcess(-1) leaves, which is what a
	// forced stop (Stop-Process, Task Manager, taskkill /F) gives; it has
	// the NTSTATUS error bits but is no NTSTATUS value (Windows 11 Pro rerun
	// 2026-10-25, D4).
	{func(c int64) bool { return uint32(c) == 0xFFFFFFFF }, true, func(int64, func(uint32) string) string {
		return " (0xFFFFFFFF: the process was stopped from outside, for example by Stop-Process or taskkill /F; not a crash)"
	}},
	// 0xC000013A STATUS_CONTROL_C_EXIT is what a console process gets when
	// its console window is closed (or Ctrl+C or Ctrl+Break ends it): a stop,
	// not a crash (RERUN2: WIN-8b's window closed by the operator).
	{func(c int64) bool { return uint32(c) == 0xC000013A }, true, func(int64, func(uint32) string) string {
		return " (0xC000013A STATUS_CONTROL_C_EXIT: the console window was closed, or Ctrl+C or Ctrl+Break ended it; not a crash)"
	}},
	{func(c int64) bool { return uint32(c)&0xC0000000 == 0xC0000000 }, true, func(c int64, _ func(uint32) string) string {
		return fmt.Sprintf(" (0x%08X: an NTSTATUS error, the process failed while starting or crashed)", uint32(c))
	}},
	{func(int64) bool { return true }, false, func(int64, func(uint32) string) string { return "" }},
}

// boxExitCodeText is code with its shape's description ("7", or "3221225786
// (0xC000013A STATUS_CONTROL_C_EXIT: the console window was closed ...)").
func boxExitCodeText(code int) string {
	for _, s := range boxExitShapes {
		if s.match(int64(code)) {
			return fmt.Sprintf("%d%s", code, s.describe(int64(code), nil))
		}
	}
	return fmt.Sprint(code)
}

// boxWin32Text is ": <message>" for a Win32 code when the system has text
// for it, else "".
func boxWin32Text(code uint32, msg func(uint32) string) string {
	if msg == nil {
		return ""
	}
	if m := strings.TrimSpace(msg(code)); m != "" {
		return ": " + m
	}
	return ""
}

// boxToolLaunchLine is the one line naming a tool launch's failure: the
// resolved tool path, its argv (secret flag values removed) and, when there
// is one, the Win32 error code and message. loud reports a failure the tool
// could not have printed itself (it did not start, or its exit code is an
// error code rather than its own answer).
func boxToolLaunchLine(bin string, args []string, o boxToolOutcome, msg func(uint32) string) (line string, loud bool) {
	what := fmt.Sprintf("the tool %s (argv %q)", bin, boxSafeArgv(args))
	if o.StartErr != nil {
		code := ""
		var en syscall.Errno
		if errors.As(o.StartErr, &en) {
			code = fmt.Sprintf(" (Win32 error %d%s)", uint32(en), boxWin32Text(uint32(en), msg))
		}
		return fmt.Sprintf("%s did not start: %v%s", what, o.StartErr, code), true
	}
	for _, s := range boxExitShapes {
		if s.match(int64(o.Exit)) {
			return fmt.Sprintf("%s exited with code %d%s", what, o.Exit, s.describe(int64(o.Exit), msg)), s.loud
		}
	}
	return fmt.Sprintf("%s exited with code %d", what, o.Exit), false
}

// noteBoxToolLaunch records a launcher's failed tool start or non-zero tool
// exit (err from Start or Wait) when the process runs in a box that names an
// inner log: the line goes to the inner log, which the host helper prints
// when the box exits non-zero, and a loud one to stderr as well. Outside a
// box, or for a nil err, it does nothing.
func noteBoxToolLaunch(stderr io.Writer, tool, bin string, args []string, err error) {
	if os.Getenv(sandboxInnerLogEnv) == "" {
		return
	}
	o, ok := boxToolOutcomeOf(err)
	if !ok {
		return
	}
	line, loud := boxToolLaunchLine(bin, args, o, boxWin32Message)
	line = "observer " + tool + ": " + line
	appendBoxInnerLog(line)
	if loud && stderr != nil {
		_, _ = fmt.Fprintln(stderr, boxOneLine(line))
	}
}
