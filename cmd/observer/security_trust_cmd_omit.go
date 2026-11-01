//go:build sbo_omit_security_trust && !sbo_omit_security

package main

import "github.com/spf13/cobra"

// security_trust_cmd_omit.go stands in for security_trust_cmd.go in a build
// without the security.trust component: `observer security` has no trust
// verbs.
func securityTrustSubcommands() []*cobra.Command { return nil }
