//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep && !sbo_omit_org_update

package main

import (
	"crypto/ed25519"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// codeVendorKeys is the vendor key set compiled into this agent, the one
// the signed content channel verifies rule packs and engine manifests with.
func codeVendorKeys() []ed25519.PublicKey { return update.VendorPublicKeys() }
