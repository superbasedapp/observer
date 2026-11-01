//go:build !sbo_omit_security && !sbo_omit_security_scan_kics

package main

import (
	"github.com/marmutapp/superbased-observer/internal/seciac"
	"github.com/marmutapp/superbased-observer/internal/secscan/kics"
)

// security_iac_kics.go registers the KICS engine (component
// security.scan.kics, lane GATES-SEC). KICS publishes no release binaries,
// so it has no guided install and no egress lane. A build with
// sbo_omit_security_scan_kics drops this file and the driver.

func init() {
	registerIaCEngine(iacBinding{id: seciac.KICS, newDriver: kics.New})
}
