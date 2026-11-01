package hook

import (
	"os"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/testhome"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// TestMain pins the per-call ask host probe for the package's tests to
// what an unattended run sees without reading the environment (no row,
// except a terminal-gated host, which gets no ask), so a test run under a CI
// environment variable or from inside an agent host keeps the binding's
// own ask behaviour. The probe's own tests replace askHostProbeFn or call
// hostCanAsk directly.
//
// It also exports crossmount.EnvDisableForeignHomes for the whole run, as
// cmd/observer's TestMain does (PT-06): this binary is covered by
// crossmount's test-binary guard, and the variable covers any real observer
// binary a test execs, so neither can resolve the operator's real
// /mnt/c/Users/<u> home.
//
// It also fails the package run when any registrar write was refused by
// testwriteguard.Check (a write outside t.TempDir() or under a real
// foreign-OS mount, incident 2026-10-20), even when the test that caused it
// only saw the error in a RegistrationResult and passed.
//
// It also pins the profile roots (HOME, USERPROFILE, APPDATA, LOCALAPPDATA,
// the XDG dirs) to one process temp home (internal/testhome, surface-gap
// FU-102): 49 tests here drive a hook
// handler without pinning a home, and the forensic log they write
// (hook-events.jsonl) falls back to os.UserHomeDir()/.observer, so before
// the pin every run appended synthetic rows to the developer's real log. A
// test that asserts on the log pins its own home on top (withTempHome).
func TestMain(m *testing.M) {
	if err := os.Setenv(crossmount.EnvDisableForeignHomes, "1"); err != nil {
		os.Exit(2)
	}
	_, cleanupHome, err := testhome.PinProcess()
	if err != nil {
		os.Exit(2)
	}
	askHostProbeFn = func(tool string) (bool, bool) {
		// A test process has no agent host and no terminal: a
		// terminal-gated host (Gemini) gets no ask, as in production.
		if h, ok := integration.AskHostFor(tool); ok && h.AskNeedsTerminal {
			return false, true
		}
		return false, false
	}
	code := testwriteguard.Run(m)
	cleanupHome()
	os.Exit(code)
}
