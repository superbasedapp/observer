//go:build sbo_omit_terminals_sandbox_oci || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import (
	"context"

	"github.com/marmutapp/superbased-observer/internal/components"
)

// terminal_sandbox_oci_omit.go stands in for the oci-runc driver in a build
// without it (-tags sbo_omit_terminals_sandbox_oci, or a build without the
// sandbox module): no driver registers, so the oci-runc row drops at S1
// (not_in_build), and internal/sandboxoci and internal/sandboxengine are
// not linked.
func init() { components.MarkOmitted("terminals.sandbox.oci") }

// sandboxInstallVersionsSeam is nil in a build without the container driver
// (the version picker's route answers 501).
func sandboxInstallVersionsSeam(string) func(context.Context, string) ([]string, error) { return nil }
