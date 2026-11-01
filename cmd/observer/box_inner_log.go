package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

// box_inner_log.go makes an observer process's failure inside a sandbox box
// visible (Windows 11 Pro live run 2026-10-22: the inner `observer claude`
// exited 1 with nothing on the terminal, because Cobra hid a plain error).
// A driver that runs observer processes in a box names an inner log in the
// box's environment (a file in the run's private temp directory); every
// observer process there appends one line per failure, and box detection's
// outcome, and the host helper prints the log when the box exits non-zero.
// Outside a box (no inner log named) nothing here does anything.

// sandboxInnerLogEnv names the run's inner log inside a box.
const sandboxInnerLogEnv = "OBSERVER_SANDBOX_INNER_LOG"

// Inner log bounds: an append to a log past boxInnerLogMax bytes is dropped,
// and a runaway line is cut at boxInnerLineMax bytes, far above any
// diagnostic Observer writes (a box detection line with two SIDs is about
// 400 bytes, which the old 400-byte cut split mid-SID: Windows 11 Pro rerun
// 2026-10-22). The helper's tail prints whole lines (mxcWholeLines).
const (
	boxInnerLogMax  = 1 << 20
	boxInnerLineMax = 4 << 10
)

var (
	// boxDetectNote is why a driver's box detection did not recognise the
	// box this process runs in ("" when it did, or when nothing pointed at
	// one). A refused in-box launch check names it.
	boxDetectNote string

	boxSecretsMu sync.Mutex
	// boxSecrets are values the box's own diagnostics never write (the
	// run's token and the URL carrying it).
	boxSecrets []string
)

// registerBoxSecret adds a value the inner log and a failure line never
// carry.
func registerBoxSecret(s string) {
	if len(s) < 8 {
		return
	}
	boxSecretsMu.Lock()
	defer boxSecretsMu.Unlock()
	boxSecrets = append(boxSecrets, s)
}

// redactBoxSecrets replaces every registered secret in s.
func redactBoxSecrets(s string) string {
	boxSecretsMu.Lock()
	defer boxSecretsMu.Unlock()
	for _, v := range boxSecrets {
		s = strings.ReplaceAll(s, v, "[REDACTED]")
	}
	return s
}

// boxOneLine is s on one bounded line, without control characters or the
// box's secrets.
func boxOneLine(s string) string {
	s = strings.Join(strings.Fields(redactBoxSecrets(s)), " ")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > boxInnerLineMax {
		s = strings.ToValidUTF8(s[:boxInnerLineMax], "") + "..."
	}
	return s
}

// appendBoxInnerLog appends one line to the inner log this process's box
// names. Best effort and bounded: a log past boxInnerLogMax, or one that is
// not a regular file, gets nothing.
func appendBoxInnerLog(line string) {
	p := os.Getenv(sandboxInnerLogEnv)
	if p == "" || !filepath.IsAbs(p) {
		return
	}
	if fi, err := os.Lstat(p); err == nil && (!fi.Mode().IsRegular() || fi.Size() > boxInnerLogMax) { //nolint:gosec // G703: the box log path the launcher set, checked absolute above
		return
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gosec // G304: the inner log the run's helper named, in the box's own temp directory
	if err != nil {
		return
	}
	_, _ = fmt.Fprintf(f, "%s pid %d: %s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), boxOneLine(line))
	_ = f.Close()
}

// boxFailureReason is err as one bounded line: a launcher's bounded message
// when it carries one, else the error's own text, the box's secrets removed.
func boxFailureReason(err error) string {
	msg := err.Error()
	var visible launcherMessageError
	if errors.As(err, &visible) {
		if m := strings.TrimSpace(visible.launcherMessage()); m != "" {
			msg = m
		}
	}
	return boxOneLine(msg)
}

// reportBoxInnerFailure records err, the outcome of this process's command,
// when the process runs in a box that names an inner log. A tool's own exit
// code (exitErr) is logged only: the tool spoke for itself. Any other failure
// is logged and, when Cobra hid it and no bounded launcher message was shown
// (shown), printed to stderr as the same one line. Outside a box it does
// nothing, so every other invocation behaves as before.
func reportBoxInnerFailure(stderr io.Writer, executed *cobra.Command, shown bool, err error) {
	if err == nil || os.Getenv(sandboxInnerLogEnv) == "" {
		return
	}
	verb, silenced := "observer", false
	if executed != nil {
		if executed.HasParent() {
			verb = "observer " + executed.Name()
		}
		silenced = executed.SilenceErrors || executed.Root().SilenceErrors
	}
	var ec exitErr
	if errors.As(err, &ec) {
		appendBoxInnerLog(fmt.Sprintf("%s: exited with code %d", verb, int(ec)))
		return
	}
	reason := boxFailureReason(err)
	appendBoxInnerLog(verb + ": " + reason)
	if silenced && !shown && stderr != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %s\n", verb, reason)
	}
}
