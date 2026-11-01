//go:build !sbo_omit_security && !sbo_omit_security_scan_trivy

package main

import (
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secscan/trivy"
	"github.com/marmutapp/superbased-observer/internal/secscan/trivy/trivynet"
)

// security_iac_trivy.go registers the Trivy engine (component
// security.scan.trivy, lane GATES-SEC): its driver and its guided install's
// egress lane (trivynet). A build with sbo_omit_security_scan_trivy drops
// this file, the driver and the lane (security_iac_trivy_omit.go).

// iacTrivyNet returns the release download client; tests swap it.
var iacTrivyNet = func() iacDownloader { return trivynet.New(trivynet.Options{}) }

func init() {
	registerIaCEngine(iacBinding{id: seciac.Trivy, newDriver: trivy.New, downloader: func() iacDownloader { return iacTrivyNet() }})
}
