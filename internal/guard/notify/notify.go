// Package notify is the guard layer's alert dispatcher (guard spec
// §3.1): one owner for everything that leaves the process to get a
// human's attention. G5 ships the desktop channel (operator decision
// Q3: pure-Go, exec-based, NO notification library and NO CGO —
// PowerShell toast on Windows, osascript on macOS, notify-send on
// Linux, each degrading to a silent no-op when the helper binary is
// absent). The cloud-tier webhook dispatcher (§15.4) joins here in
// G15 so guard network I/O keeps a single owner.
package notify

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// notifyTimeout bounds the helper process: a hung notification
// daemon must never pin the caller (alerts fire off hot paths, but a
// leaked process per verdict would still accumulate).
const notifyTimeout = 5 * time.Second

// maxField bounds title/body lengths — notifications are glanceable
// summaries, and unbounded rule reasons would truncate ugly in every
// OS's UI anyway.
const maxField = 200

// Desktop sends best-effort OS desktop notifications. The zero value
// is NOT usable; construct with NewDesktop.
type Desktop struct {
	// run executes the helper command; injected in tests. The
	// production runner enforces notifyTimeout.
	run func(name string, args ...string) error
}

// AllowRealNotifyInTestEnv is the escape hatch for the one kind of test
// that must show a real desktop notification (a manual probe): set to "1",
// a `go test` binary's NewDesktop runs the real helper again.
const AllowRealNotifyInTestEnv = "OBSERVER_ALLOW_REAL_NOTIFY_IN_TEST"

// NewDesktop returns the production desktop notifier.
//
// Inside a `go test` binary it returns an inert notifier (ledger TESTNOTIFY-1,
// FU-235): hook and guard tests drive real verdicts (an R-101 deny under a
// fixture org bundle, an org-locked rule) through the same composition the
// daemon uses, and before this guard a test run on a Windows or macOS host,
// or a Linux desktop with notify-send, showed the developer real "Observer
// Guard: R-101 deny ... your organization locks this rule" toasts that no
// node of theirs had produced. The same testing.Testing() backstop shape as
// internal/db GuardLiveDB and internal/testwriteguard. Production cost is one
// boolean read.
func NewDesktop() *Desktop {
	return &Desktop{run: desktopRunner(testing.Testing(), os.Getenv(AllowRealNotifyInTestEnv) == "1")}
}

// desktopRunner picks the helper runner: the real one in production (or in a
// test that opted in), a no-op inside a test binary otherwise.
func desktopRunner(inTest, allowInTest bool) func(name string, args ...string) error {
	if inTest && !allowInTest {
		return func(string, ...string) error { return nil }
	}
	return runWithTimeout
}

// runWithTimeout starts the helper and waits at most notifyTimeout.
// All failures (binary absent, non-zero exit, timeout) are returned
// for the caller to swallow — notification is best-effort by
// contract.
func runWithTimeout(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(notifyTimeout):
		_ = cmd.Process.Kill()
		return <-done
	}
}

// Notify sends one desktop notification, best-effort: every failure
// path is a silent no-op (a missing notify-send must never become a
// guard error — the verdict is already persisted and in the
// forensics log; the notification is a convenience surface).
func (d *Desktop) Notify(title, body string) {
	name, args, ok := notifyCommand(runtime.GOOS, title, body)
	if !ok {
		return
	}
	_ = d.run(name, args...)
}

// notifyCommand maps (goos, title, body) onto the helper invocation.
// Pure — table-tested across all three platforms regardless of the
// test host. ok=false means the platform has no known helper.
func notifyCommand(goos, title, body string) (name string, args []string, ok bool) {
	title = bound(title)
	body = bound(body)
	switch goos {
	case "windows":
		// BurntToast-free toast via the WinRT API from inline
		// PowerShell (Q3). Single-quoted PS literals with quote
		// doubling — no string interpolation of payload content.
		script := `$ErrorActionPreference='Stop';` +
			`[Windows.UI.Notifications.ToastNotificationManager,Windows.UI.Notifications,ContentType=WindowsRuntime]|Out-Null;` +
			`$x=[Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02);` +
			`$t=$x.GetElementsByTagName('text');` +
			`$null=$t.Item(0).AppendChild($x.CreateTextNode('` + psQuote(title) + `'));` +
			`$null=$t.Item(1).AppendChild($x.CreateTextNode('` + psQuote(body) + `'));` +
			`$n=[Windows.UI.Notifications.ToastNotification]::new($x);` +
			`[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('superbased Observer').Show($n)`
		return "powershell", []string{"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script}, true
	case "darwin":
		script := `display notification "` + osaQuote(body) + `" with title "` + osaQuote(title) + `"`
		return "osascript", []string{"-e", script}, true
	case "linux":
		return "notify-send", []string{"--app-name=superbased Observer", title, body}, true
	default:
		return "", nil, false
	}
}

// bound truncates a field rune-safely to maxField.
func bound(s string) string {
	if utf8.RuneCountInString(s) <= maxField {
		return s
	}
	return string([]rune(s)[:maxField]) + "…"
}

// psQuote escapes for a single-quoted PowerShell literal (quotes
// double; no other character is special inside PS single quotes).
func psQuote(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// osaQuote escapes for a double-quoted AppleScript literal.
func osaQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	return strings.ReplaceAll(s, `"`, `\"`)
}
