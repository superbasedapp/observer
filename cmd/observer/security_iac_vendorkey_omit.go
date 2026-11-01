//go:build !sbo_omit_security && sbo_omit_org_update

package main

// security_iac_vendorkey_omit.go: a build without the org update module
// has no vendor key, so no IaC engine manifest verifies (the compiled pins
// hold).
