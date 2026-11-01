//go:build !sbo_omit_org_update && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"crypto/ed25519"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// sandboxImageVendorKeys is the vendor key set compiled into this agent, the
// one the default sandbox image's signed manifest verifies against (plan
// 12.3). An empty set verifies nothing: artifact_unverified.
func sandboxImageVendorKeys() []ed25519.PublicKey { return update.VendorPublicKeys() }
