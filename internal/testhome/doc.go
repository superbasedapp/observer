// Package testhome pins a `go test` binary's per-user home for the whole
// run, so a test that forgets to pin its own home writes into a throwaway
// temp home instead of the developer's real ~/.observer (surface-gap
// FU-102).
//
// INCIDENT 2026-10-27: the operator's WSL node held 3401 synthetic lines in
// the real ~/.observer/hook-events.jsonl (session ids "s1", "s",
// "fixture-cur-1"; events such as ibm-bob:PreToolUse and
// cursor:beforeShellExecution), written by internal/hook tests that drive a
// hook handler without pinning HOME: the hook forensic log falls back to
// os.UserHomeDir()/.observer when no state-dir resolver is installed.
//
// PinProcess is the package-level backstop a TestMain calls before m.Run.
// It moves the profile roots Go and Observer resolve a home from (HOME and
// USERPROFILE for os.UserHomeDir, APPDATA for os.UserConfigDir,
// LOCALAPPDATA for os.UserCacheDir) to one new temp home, clears the XDG
// base dirs and OBSERVER_CONFIG so they fall back under it, and keeps the go
// toolchain's own caches where they are (a test that execs `go build` must
// not rebuild into an empty home). Whatever a forgetful test writes under
// the default ~/.observer lands in that temp home and is removed with it; a
// test that asserts on Observer state pins its own home with t.Setenv on
// top.
//
// Unlike cmd/observer's backstop, the temp home starts empty (its .observer
// is not a blocker file): what a test writes there is harmless and goes
// away with the home, and a writer under test behaves as it would on a
// clean machine.
//
// cmd/observer keeps its own, larger pin table (testhomes_helpers_test.go:
// every tool home variable as well), because its tests drive the per-tool
// config writers. This package covers the profile roots only, which is what
// a package whose writers resolve only ~/.observer needs.
//
// The write-side guard for the same writers is internal/testwriteguard: the
// hook forensic logs call it, so a write outside the test temp directory is
// refused and fails the package run through testwriteguard.Run even in a
// package that has no backstop.
package testhome
