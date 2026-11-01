//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import "github.com/spf13/cobra"

// security_deps_cmd_omit.go stands in for security_deps_cmd.go in a build
// without the security.deps component: `observer security` has no deps verbs.
func securityDepsSubcommands() []*cobra.Command { return nil }
