//go:build sbo_omit_terminals_sandbox_vm || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_vm_omit.go stands in for the Cloud Hypervisor microVM
// driver in a build without it (-tags sbo_omit_terminals_sandbox_vm, or a
// build without the sandbox module): no driver registers, so the
// cloud-hypervisor row drops at S1 (not_in_build), and internal/sandboxvm
// and internal/sandboxvmm are not linked.
func init() { components.MarkOmitted("terminals.sandbox.vm") }
