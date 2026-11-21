//go:build !linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "context"

// orgShellEndRun: off Linux no hosted run exists (the row's host side runs
// on a Linux or WSL2 daemon only), so the shared teardown is never reached
// either.
func orgShellEndRun(context.Context, *hostedRun) bool { return false }
