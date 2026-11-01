//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "errors"

// errOCIDeferredTimeout is the helper's answer when the daemon never
// finished. Used only by the Linux deferred-run helper
// (terminal_sandbox_oci_deferred_linux.go), so it lives in a Linux file
// (WINFIX4 lint: unused on Windows).
var errOCIDeferredTimeout = errors.New("the daemon did not finish preparing the run in time; nothing of the agent ran")
