//go:build sbo_omit_terminals_sandbox_docker || sbo_omit_terminals_sandbox || sbo_omit_isolation || sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/components"

// terminal_sandbox_dockersbx_omit.go is the Docker Sandboxes driver's twin in
// a build without it (-tags sbo_omit_terminals_sandbox_docker, or a build
// without the sandbox module): no row registers, so the docker-sandboxes
// backend reads not_in_build, and the vendor's wire client is not linked.
func init() { components.MarkOmitted("terminals.sandbox.docker") }
