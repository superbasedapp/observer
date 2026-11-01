//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

// ociReadoptAwaitOffer returns a kept helper's wait (LEFT2 audit S4): after
// it left the container through a daemon hangup, true once the next start
// offered the run within the re-adoption bound, false when none did, and
// the helper then stops the container. It is read and set only on Linux
// (sandbox_readopt_hangup_linux.go sets it; terminal_sandbox_oci_run.go
// reads it), so it lives in a Linux file (WINFIX4 lint: unused on Windows).
// nil unless the re-adoption files are compiled; the returned func is nil
// when the run cannot be re-adopted.
var ociReadoptAwaitOffer func(observerDir, runID string) func() bool

// ociReadoptKeepOnHangup returns the helper's hangup check for one run
// (R-033): true keeps the container for re-adoption after a daemon exit
// instead of stopping it. Set (sandbox_readopt_hangup_linux.go) and read
// (terminal_sandbox_oci_run.go) only on Linux (WINFIX4 lint). nil (never
// keep) unless the re-adoption files are compiled; the returned func is nil
// when the run cannot be re-adopted.
var ociReadoptKeepOnHangup func(observerDir, runID string) func() bool
