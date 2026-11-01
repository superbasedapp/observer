//go:build !sbo_omit_security && sbo_omit_security_scan_trivy

package main

// security_iac_trivy_omit.go stands in for security_iac_trivy.go in a build
// without security.scan.trivy: no Trivy binding is registered, so every
// IaC verb and the doctor say Trivy is not in this build.
