package crossmount

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// EnvDisableForeignHomes is the operator knob that switches foreign-OS home
// discovery OFF for a process: set it to a truthy value ("1", "true", "yes",
// "on", case-insensitive) and ExtraHomes / AllHomes report no cross-mount home
// at all (AllHomes still returns the native one), and WindowsUserName never
// shells out to cmd.exe. Every reader and writer that resolves the "other
// side" of a WSL2/Windows pair through this package therefore behaves as on a
// single-OS host.
//
// Unset (the default) changes nothing: production behaviour is identical to a
// build without this knob. It exists for two callers:
//
//   - A test harness that spawns a REAL observer binary (tests/e2e, a
//     probe-hook subprocess) under a scratch $HOME. That child is not a test
//     binary, so the in-process guard below does not apply to it; the knob
//     is how the harness keeps `observer start` / `observer init` from
//     resolving the developer's real /mnt/c/Users/<u>/.claude.
//   - An operator who wants a WSL daemon to ignore the Windows side entirely.
const EnvDisableForeignHomes = "OBSERVER_CROSSMOUNT_DISABLE"

// AllowLiveForeignHomesInTestEnv names the ONE escape hatch for the
// test-binary guard: a human who genuinely wants a `go test` run to see the
// real foreign mount (grounding an adapter against a live Windows-side store)
// types it on the command line:
//
//	OBSERVER_ALLOW_LIVE_CROSSMOUNT_IN_TEST=1 go test ./internal/adapter/...
//
// It is read ONCE at package-init time, so a t.Setenv / TestMain cannot open
// it: a test binary receives its environment before any test code runs. Same
// discipline as internal/db's AllowRealDBInTestEnv.
const AllowLiveForeignHomesInTestEnv = "OBSERVER_ALLOW_LIVE_CROSSMOUNT_IN_TEST"

// testBinaryGuard is true inside a `go test` binary unless the operator opened
// AllowLiveForeignHomesInTestEnv on the command line. While it is true the
// default detector enumerates NO foreign-OS home and the Windows-user probe
// never execs cmd.exe.
//
// # INCIDENT 2026-10-02 — why this guard exists
//
// cmd/observer's TestAutoRegisterHooks_PromptLaneOnlyGate pointed HOME and
// USERPROFILE at a t.TempDir() and called autoRegisterHooks — the same
// unpinned hook.NewRegistry shape `observer start` uses in production. The
// sandbox gate from the 2026-07-31 incident (AutoDetectSuppressed) keys off a
// caller-PINNED HomeDir, and this caller pins nothing, so the registry's
// "claude-code-windows" target walked AllHomes(), whose WSL scan enumerates
// the hard-coded /mnt/c/Users root regardless of $HOME. Run inside WSL it
// found the operator's real /mnt/c/Users/<u>/.claude, proved ownership via the
// cmd.exe %USERNAME% probe, and rewrote all 22 hook commands to point at the
// (since deleted) test binary — every hook of the operator's Claude Code then
// failed.
//
// Faking $HOME cannot isolate this: the foreign root is a fixed mount point,
// not something derived from the home. Per-caller pinning is a convention a
// future test can forget, so the guard lives at the ONE place every foreign
// home comes from. It applies to every test binary in the tree by
// construction — no TestMain, no per-package opt-in, nothing to forget.
//
// Production cost: testing.Testing() is one string compare at package init;
// a non-test binary sets this false and never consults it again.
var testBinaryGuard = captureTestBinaryGuard()

// captureTestBinaryGuard resolves testBinaryGuard. Production does no env
// read here at all.
func captureTestBinaryGuard() bool {
	if !testing.Testing() {
		return false
	}
	return !envTruthy(os.Getenv(AllowLiveForeignHomesInTestEnv))
}

// stagedForeignLayout is what StageForeignLayoutForTest installs: a fake
// foreign mount root, a pinned Windows user, and whether discovery of THAT
// root is allowed. It is read through one atomic pointer so a detector
// derives root and permission from the same snapshot (two separate loads
// could pair "discovery allowed" with the REAL root mid-restore).
type stagedForeignLayout struct {
	root        string
	windowsUser string
	discover    bool
	// realHome pins the account's real home for the isolation rules
	// (isolation.go). Empty keeps the staged layout deciding alone.
	realHome string
}

var stagedForeign atomic.Pointer[stagedForeignLayout]

// ForeignHomesSuppressed reports whether foreign-OS home discovery is off for
// this process: EnvDisableForeignHomes is set, this is a test binary
// without a staged layout that opts back in, or the process is isolated
// (IsolationReason: an isolated HOME, --no-crossmount, a --config outside
// the real home; LEFT2 audit S5). Code that reaches the foreign side WITHOUT
// going through AllHomes (a fixed /mnt/c path, an interop exec) must
// consult it so the knob, the test guard and the isolation rules cover that
// path too.
func ForeignHomesSuppressed() bool {
	staged := stagedForeign.Load()
	if foreignSuppressedWith(staged, os.Getenv(EnvDisableForeignHomes), testBinaryGuard) {
		return true
	}
	return activeIsolationReason(staged) != ""
}

// foreignSuppressedWith is the pure decision behind ForeignHomesSuppressed,
// as an ordered rule table:
//
//  1. A staged test layout decides alone: discovery is allowed only when it
//     says so, and then only of its own temp-dir root (defaultDetector swaps
//     the root in from the same snapshot).
//  2. EnvDisableForeignHomes truthy → suppressed.
//  3. Otherwise suppressed exactly when the test-binary guard is up.
func foreignSuppressedWith(staged *stagedForeignLayout, disableEnv string, guard bool) bool {
	if staged != nil {
		return !staged.discover
	}
	if envTruthy(disableEnv) {
		return true
	}
	return guard
}

// ForeignLayoutForTest describes a fake foreign-OS mount a test stages with
// StageForeignLayoutForTest.
type ForeignLayoutForTest struct {
	// Root stands in for the foreign mount root the default detector
	// enumerates: /mnt/c/Users on a Linux host (Root/<user>/NTUSER.DAT …),
	// \\wsl.localhost\ on a Windows host (Root/<distro>/home/<user>).
	// Required; must be absolute and live under os.TempDir() (use
	// t.TempDir()), so staging can never point discovery at a real mount.
	Root string
	// WindowsUser pins WindowsUserName() — the ownership primitive the
	// cross-OS writers consult — for the duration. Empty means "ownership
	// unverifiable", exactly as when interop is off.
	WindowsUser string
	// Discover lifts the test-binary guard for the staged Root ONLY. Leave it
	// false to prove the guard holds with a detectable foreign home present;
	// set it to run a non-vacuous control that shows the same layout IS found
	// once discovery is allowed.
	Discover bool
	// RealHome, when set, stands in for the account's real home and turns on
	// the isolation rules of isolation.go for the staged layout: with HOME
	// (USERPROFILE on Windows) outside RealHome no foreign home is detected
	// and no explicit foreign override outside HOME is honoured, exactly as
	// for a real binary. Empty keeps the old meaning (the layout decides
	// alone).
	RealHome string
}

// StageForeignLayoutForTest installs layout for the rest of the calling test
// and restores the previous state (and an empty AllHomes cache) on cleanup.
// It mutates process-wide state, so the calling test must not run in
// parallel with others that resolve homes.
func StageForeignLayoutForTest(tb testing.TB, layout ForeignLayoutForTest) {
	tb.Helper()
	if err := validateStagedRoot(layout.Root, os.TempDir()); err != nil {
		tb.Fatalf("crossmount.StageForeignLayoutForTest: %v", err)
	}
	prev := stagedForeign.Swap(&stagedForeignLayout{
		root:        filepath.Clean(layout.Root),
		windowsUser: layout.WindowsUser,
		discover:    layout.Discover,
		realHome:    layout.RealHome,
	})
	restoreIsolation := resetProcessIsolationForTest()
	resetExtrasCacheForTest()
	tb.Cleanup(func() {
		stagedForeign.Store(prev)
		restoreIsolation()
		resetExtrasCacheForTest()
	})
}

// validateStagedRoot refuses a staged root that is relative or that resolves
// outside tempRoot. That containment is what keeps Discover from ever being an
// escape hatch onto the real /mnt/c/Users or \\wsl.localhost\.
func validateStagedRoot(root, tempRoot string) error {
	if root == "" {
		return errors.New("staged root is required")
	}
	if !filepath.IsAbs(root) {
		return fmt.Errorf("staged root %q must be absolute", root)
	}
	if !PathUnder(tempRoot, root) {
		return fmt.Errorf("staged root %q must live under %q (use t.TempDir()); a staged layout may never name a real mount", root, tempRoot)
	}
	return nil
}

// envTruthy reports whether an environment value spells "on": "1", "true",
// "yes" or "on", case-insensitive and whitespace-trimmed.
func envTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
