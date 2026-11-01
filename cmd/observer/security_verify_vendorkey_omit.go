//go:build !sbo_omit_security && sbo_omit_org_update

package main

// verifyDefaultVendorKey in a build without org.update: internal/update is
// not linked, so there is no compiled-in key to default to and
// `observer security verify template` refuses until --vendor-key names
// one (security_verify_vendorkey.go is the default-build twin).
func verifyDefaultVendorKey() string { return "" }
