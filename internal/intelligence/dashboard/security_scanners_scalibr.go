//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_scalibr

package dashboard

// scalibrDriverCompiled reports that this build links OSV-SCALIBR. A
// constant, so the dashboard never imports the facade (only the scan
// command and the scan child may, security_scan_egress_test.go).
const scalibrDriverCompiled = true
