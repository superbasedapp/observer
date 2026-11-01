//go:build sbo_omit_org_update && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "crypto/ed25519"

// sandboxImageVendorKeys in a build without the update module carries no
// key, so the default sandbox image is never verified (artifact_unverified).
func sandboxImageVendorKeys() []ed25519.PublicKey { return nil }
