//go:build !sbo_omit_security && !sbo_omit_org_update

package main

import "github.com/marmutapp/superbased-observer/internal/update"

// verifyDefaultVendorKey is the vendor key the CI verify template pins by
// default: the one this binary's own update path trusts
// (internal/update/vendorkey.go). A build without org.update links no
// update package, so its template needs --vendor-key
// (security_verify_vendorkey_omit.go).
func verifyDefaultVendorKey() string { return update.VendorPublicKeyV1 }
