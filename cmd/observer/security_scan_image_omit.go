//go:build !sbo_omit_security && !sbo_omit_security_deps && (sbo_omit_security_scan_scalibr || sbo_omit_security_scan_os)

package main

import (
	"errors"

	"github.com/spf13/cobra"
)

// security_scan_image_omit.go stands in for security_scan_image.go in a
// build without security.scan.os (or without the SCALIBR facade it needs):
// no image is read and nothing is claimed about one.

// errImageScanNotInBuild is the answer of `observer security scan image`
// in this build.
var errImageScanNotInBuild = errors.New("security.scan.os is not in this build: image OS packages are not scanned")

func newSecurityScanImageCmd() *cobra.Command {
	return &cobra.Command{Use: "image <tar|dir>", Short: "Not in this build (security.scan.os)", Hidden: true, RunE: func(*cobra.Command, []string) error {
		return errImageScanNotInBuild
	}}
}
