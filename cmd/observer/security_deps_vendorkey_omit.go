//go:build !sbo_omit_security && !sbo_omit_security_deps && sbo_omit_org_update

package main

import "crypto/ed25519"

// depsVendorKeys without the org.update component: the vendor key set is
// not in this build, so no content verifies and the install gate reads its
// index as unknown (fail closed).
func depsVendorKeys() []ed25519.PublicKey { return nil }
