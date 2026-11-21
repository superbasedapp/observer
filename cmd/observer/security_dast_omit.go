//go:build sbo_omit_security || sbo_omit_security_dast

package main

import "github.com/spf13/cobra"

// security_dast_omit.go stands in for security_dast.go in a build without
// security.dast: no `observer security dast` verb, and neither the pure
// checker nor its loopback lane is linked.

func securityDASTSubcommands() []*cobra.Command { return nil }
