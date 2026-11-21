//go:build !sbo_omit_security && !sbo_omit_security_deps && (sbo_omit_security_scan_trivy || sbo_omit_security_scan_image_trivy)

package main

import (
	"context"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
)

// security_scan_image_trivy_omit.go stands in for
// security_scan_image_trivy.go in a build without security.scan.image.trivy
// (or without the Trivy binary's row, security.scan.trivy): no Trivy image
// scan runs, nothing is downloaded, and every verb says it is not in this
// build.

func trivyImageCompiled() bool { return false }

func runImageTrivyScan(context.Context, *depsScanEnv, string, string, func()) (imageScanReport, error) {
	return imageScanReport{}, errTrivyImageNotInBuild
}

func newSecurityScanTrivyDBCmd() *cobra.Command {
	return &cobra.Command{Use: "trivy-db", Short: "Not in this build (security.scan.image.trivy)", Hidden: true, RunE: func(*cobra.Command, []string) error {
		return errTrivyImageNotInBuild
	}}
}

func fillTrivyImageStatus(*depsScanEnv, *dashapi.ScannerImageStatus) {}

func writeTrivyImageState(context.Context, io.Writer, *dashapi.ScannerImageStatus) {}

func acceptTrivyDBDash(*depsScanEnv) error { return errTrivyImageNotInBuild }

// maybeRefreshTrivyDB refreshes nothing: Trivy's database is not in this
// build.
func maybeRefreshTrivyDB(context.Context, *depsScanEnv, time.Time) bool { return false }
