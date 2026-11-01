package crossmount

import (
	"fmt"
	"os"
	"os/user"
	"sync/atomic"
)

// # INCIDENT 2026-10-25 (R-013): why an isolated HOME must isolate crossmount
//
// While building a Windows kit, an `observer init` run inside WSL with HOME
// set to a temp dir still rewrote the operator's real Windows Claude Code
// hook settings (C:\Users\<u>\.claude\settings.json) and the browser-host
// launcher .bat. The foreign roots (/mnt/c/Users, \\wsl.localhost\) are fixed
// mount points, so moving HOME never moved them; the test-binary guard
// (testguard.go) only protects `go test` binaries, not a real binary a human
// runs under a scratch home.
//
// The rule now: a process whose home is isolated from the account's real home
// detects no foreign-OS profile and writes none. "Isolated" is one of the rows
// of isolationReasonWith, in order:
//
//  1. EnvDisableForeignHomes is set (what a test harness sets for the real
//     binaries it spawns).
//  2. The process said so: `--no-crossmount`, or `--config` naming a file
//     outside the real user home (DisableForProcess, set by cmd/observer).
//  3. The home the process resolves (os.UserHomeDir: $HOME, %USERPROFILE%) is
//     not exactly the account's real home (the passwd entry / the Windows
//     profile), both resolved through symlinks. A scratch HOME BENEATH the
//     real home counts too (LEFT2 audit S3): `HOME=~/sbo-scratch/x observer
//     init` is the kit pattern the incident came from.
//
// A process that sets none of these is unchanged: detection and writes behave
// exactly as before.

// processIsolation holds the reason DisableForProcess recorded, if any.
var processIsolation atomic.Pointer[string]

// DisableForProcess switches foreign-OS home detection and writes off for the
// rest of this process and records why (the reason the doctor row names). An
// empty reason is ignored. The first recorded reason wins, so a later call
// cannot replace a more specific one.
func DisableForProcess(reason string) {
	if reason == "" {
		return
	}
	r := reason
	if processIsolation.CompareAndSwap(nil, &r) {
		// A scan cached before the switch must not outlive it.
		resetExtrasCache()
	}
}

// resetProcessIsolationForTest clears DisableForProcess and returns a restore
// func. Test-only.
func resetProcessIsolationForTest() func() {
	prev := processIsolation.Swap(nil)
	return func() { processIsolation.Store(prev) }
}

// isolationInputs are the facts isolationReasonWith decides on. Every field
// is plain data so the rule table is testable without touching the host.
type isolationInputs struct {
	disableEnv string // the EnvDisableForeignHomes value
	process    string // the DisableForProcess reason, "" when none
	home       string // the home this process resolves
	realHome   string // the account's real home, "" when unknown
}

// isolationReasonWith is the ordered rule table described at the top of this
// file. It returns "" when the process is not isolated.
func isolationReasonWith(in isolationInputs) string {
	switch {
	case envTruthy(in.disableEnv):
		return EnvDisableForeignHomes + " is set"
	case in.process != "":
		return in.process
	case homeIsolated(in.home, in.realHome):
		return fmt.Sprintf("the home %s is not the real user home %s", in.home, in.realHome)
	}
	return ""
}

// homeIsolated reports whether home is anything but realHome itself, after
// both are resolved through symlinks (PathUnder both ways is equality). A
// directory beneath the real home is isolated too (LEFT2 audit S3). An
// unknown side (either empty) is never isolated: production with no passwd
// entry behaves exactly as before.
func homeIsolated(home, realHome string) bool {
	if home == "" || realHome == "" {
		return false
	}
	return !PathUnder(realHome, home) || !PathUnder(home, realHome)
}

// IsolationReason reports why foreign-OS home detection and writes are off
// for this process because its home is isolated, or "" when they are not.
// The test-binary guard is not an isolation reason; see DetectionOffReason.
func IsolationReason() string {
	return activeIsolationReason(stagedForeign.Load())
}

// activeIsolationReason applies the isolation rules where they belong. A test
// layout staged without a RealHome keeps its old meaning (it decides alone,
// testguard.go), and an unstaged test binary is already covered by the guard;
// in both the rules stay out of the way, so a harness env var set in a
// TestMain cannot change what a test's explicit foreign override does. A real
// binary, or a test that staged a RealHome, gets the full table.
func activeIsolationReason(staged *stagedForeignLayout) string {
	if staged != nil && staged.realHome == "" {
		return ""
	}
	if staged == nil && testBinaryGuard {
		return ""
	}
	in := currentIsolationInputs()
	if staged != nil {
		// A staged layout answers the harness knob itself (testguard.go:
		// staged allow wins over the knob, its root is a temp dir).
		in.disableEnv = ""
	}
	return isolationReasonWith(in)
}

// DetectionOffReason reports why this process detects no foreign-OS home:
// an isolation reason, the test-binary guard, or "" when detection is on.
// It is what `observer doctor` prints on its crossmount row.
func DetectionOffReason() string {
	if r := IsolationReason(); r != "" {
		return r
	}
	if staged := stagedForeign.Load(); staged != nil {
		if !staged.discover {
			return "a test layout is staged without discovery"
		}
		return ""
	}
	if testBinaryGuard {
		return "this is a test binary"
	}
	return ""
}

// ConfigOutsideRealHome returns a DisableForProcess reason when path (a
// --config value) names a file outside the account's real home, or "" when it
// is inside it, empty, or the real home is unknown.
func ConfigOutsideRealHome(path string) string {
	if path == "" {
		return ""
	}
	realHome := realUserHome(stagedForeign.Load())
	if realHome == "" || PathUnder(realHome, path) {
		return ""
	}
	return fmt.Sprintf("--config %s is outside the real user home %s", path, realHome)
}

// currentIsolationInputs reads the live process facts for the rule table.
func currentIsolationInputs() isolationInputs {
	in := isolationInputs{disableEnv: os.Getenv(EnvDisableForeignHomes)}
	if p := processIsolation.Load(); p != nil {
		in.process = *p
	}
	in.home, _ = os.UserHomeDir()
	in.realHome = realUserHome(stagedForeign.Load())
	return in
}

// realUserHome resolves the account's real home: the staged layout's pinned
// value in a test, nothing in an unstaged test binary (the guard already
// protects it, and a test's fake HOME must not read as isolation), and the
// passwd entry / Windows profile otherwise. Lookup failure is "" (unknown).
func realUserHome(staged *stagedForeignLayout) string {
	if staged != nil {
		return staged.realHome
	}
	if testBinaryGuard {
		return ""
	}
	return lookupRealHome()
}

// lookupRealHome is the account lookup seam. os/user caches the current user,
// so repeated calls cost a map read.
var lookupRealHome = func() string {
	u, err := user.Current()
	if err != nil || u == nil {
		return ""
	}
	return u.HomeDir
}
