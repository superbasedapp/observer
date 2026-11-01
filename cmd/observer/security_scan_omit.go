//go:build !sbo_omit_security && sbo_omit_security_deps

package main

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
)

// security_scan_omit.go stands in for security_scan.go and
// security_scan_cmd.go in a build without security.deps: the dependency
// drivers require it, so no scan loop starts and `observer security` has
// no scan verbs.

func startSecurityScan(context.Context, *gatedGroup, string, componentstate.Snapshot) {}

func securityScanSubcommands() []*cobra.Command { return nil }
