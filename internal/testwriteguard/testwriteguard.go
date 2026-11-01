package testwriteguard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// ErrRefused is wrapped by every refusal Check returns.
var ErrRefused = errors.New("a test binary may not write outside the test temp directory (incident 2026-10-20, incident 2026-10-21)")

// inTestBinary is true inside a `go test` binary. It is captured once at
// package init; production pays one call to testing.Testing.
var inTestBinary = testing.Testing()

// Check returns nil outside a `go test` binary. Inside one it refuses a
// write to path (returns an *fs.PathError wrapping ErrRefused and records the
// violation for Run) when path is empty, under a real foreign-OS mount, or
// not os.TempDir() or a path beneath it. op names the refused operation
// ("write", "remove", "rename", ...) in the error. A writer calls it before
// it touches path or any directory leading to it.
func Check(op, path string) error {
	return check(inTestBinary, os.TempDir(), op, path)
}

// check is Check with the test-binary flag and the temp root injected.
func check(testBinary bool, tempRoot, op, path string) error {
	if !testBinary {
		return nil
	}
	reason := refusal(path, tempRoot)
	if reason == "" {
		return nil
	}
	violations.mu.Lock()
	violations.list = append(violations.list, path+": "+reason)
	violations.mu.Unlock()
	return &fs.PathError{
		Op: op, Path: path,
		Err: fmt.Errorf("testwriteguard: a test binary refused to %s %s: %s (tests write only under t.TempDir()): %w", op, path, reason, ErrRefused),
	}
}

// refusal is Check's pure decision, as an ordered rule table: the first rule
// that matches names the refusal; "" allows the write.
func refusal(path, tempRoot string) string {
	rules := []struct {
		refuse func() bool
		reason string
	}{
		{func() bool { return path == "" }, "the path is empty"},
		{func() bool { return underRealForeignRoot(path) }, "it is under a real foreign-OS mount"},
		{func() bool { return tempRoot == "" || !crossmount.PathUnder(tempRoot, path) }, "it is outside the test temp directory " + tempRoot},
	}
	for _, r := range rules {
		if r.refuse() {
			return r.reason
		}
	}
	return ""
}

// underRealForeignRoot reports whether path is under one of
// crossmount.RealForeignMountRoots, compared case-insensitively on forward
// slashes (DrvFs and the \\wsl.localhost\ share are case-insensitive).
func underRealForeignRoot(path string) bool {
	candidates := []string{path}
	if abs, err := filepath.Abs(path); err == nil && abs != path {
		candidates = append(candidates, abs)
	}
	for _, c := range candidates {
		p := normalizeRoot(c)
		for _, root := range crossmount.RealForeignMountRoots() {
			r := strings.TrimSuffix(normalizeRoot(root), "/")
			if p == r || strings.HasPrefix(p, r+"/") {
				return true
			}
		}
	}
	return false
}

func normalizeRoot(p string) string {
	return strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
}

var violations struct {
	mu   sync.Mutex
	list []string
}

// Violations returns every write Check refused in this process, in order.
func Violations() []string {
	violations.mu.Lock()
	defer violations.mu.Unlock()
	return append([]string(nil), violations.list...)
}

// TakeViolationsForTest returns the refused writes recorded so far and
// clears the record, for a test that provokes a refusal on purpose and
// asserts on it (Run then sees only unexpected ones).
func TakeViolationsForTest() []string {
	violations.mu.Lock()
	defer violations.mu.Unlock()
	out := violations.list
	violations.list = nil
	return out
}

// Run runs m and fails the package run when any config write was refused by
// Check, even if every test passed (a caller that only logs a registration
// error would otherwise hide the attempt). A test package whose code reaches
// a config writer calls it from TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(testwriteguard.Run(m)) }
func Run(m *testing.M) int {
	code := m.Run()
	if v := Violations(); len(v) > 0 {
		fmt.Fprintf(os.Stderr, "FAIL: %d config write(s) outside the test temp dir were refused (testwriteguard.Check):\n  %s\n",
			len(v), strings.Join(v, "\n  "))
		if code == 0 {
			code = 1
		}
	}
	return code
}
