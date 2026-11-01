//go:build !sbo_omit_security && !sbo_omit_security_deps && sbo_omit_security_scan_osv

package dashboard

// osvDriverCompiled reports that this build leaves security.scan.osv out.
const osvDriverCompiled = false
