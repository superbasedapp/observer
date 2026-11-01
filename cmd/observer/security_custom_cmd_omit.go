//go:build sbo_omit_security_scan_custom && !sbo_omit_security

package main

import "github.com/spf13/cobra"

// security_custom_cmd_omit.go stands in for security_custom_cmd.go in a
// build without the security.scan.custom component: `observer security`
// has no scanners verbs.
func securityCustomSubcommands() []*cobra.Command { return nil }
