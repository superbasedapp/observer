//go:build !sbo_omit_security && !sbo_omit_org_update

package main

import "github.com/marmutapp/superbased-observer/internal/update"

// security_iac_vendorkey.go hands the IaC engine manifest the compiled
// vendor keys (the code rules' trust root; a build without the update
// module has none, security_iac_vendorkey_omit.go).
func init() { iacVendorKeysFn = update.VendorPublicKeys }
