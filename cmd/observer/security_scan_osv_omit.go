//go:build !sbo_omit_security && !sbo_omit_security_deps && sbo_omit_security_scan_osv

package main

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// security_scan_osv_omit.go stands in for security_scan_osv.go in a build
// without security.scan.osv: there is no osv-scanner driver and no install
// offer.

// errOSVNotInBuild is the answer of the osv-scanner verbs in this build.
var errOSVNotInBuild = errors.New("security.scan.osv is not in this build")

func depsOSVDriver(*extrun.Runner, string, map[string]string, string) secscan.Driver { return nil }

func newSecurityScanInstallCmd() *cobra.Command {
	return &cobra.Command{Use: "install-osv-scanner", Hidden: true, RunE: func(*cobra.Command, []string) error {
		return errOSVNotInBuild
	}}
}
