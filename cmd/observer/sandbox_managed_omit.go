//go:build sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

// sandbox_managed_omit.go is the twin of sandbox_managed.go in a build
// without the Sandboxes and VMs module: no consumer registers for the
// sandbox managed pull, so the kit's poll step makes no request for that rail
// and nothing composes onto a [terminal.sandbox] block this build cannot use.

// sandboxManagedCompiled reports whether this build consumes the sandbox
// managed pull.
const sandboxManagedCompiled = false
