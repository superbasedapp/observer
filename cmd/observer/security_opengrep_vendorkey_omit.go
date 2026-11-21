//go:build !sbo_omit_security && !sbo_omit_security_scan_opengrep && sbo_omit_org_update

package main

import "crypto/ed25519"

// codeVendorKeys: a build without the update module carries no vendor key,
// so no rule pack or engine manifest verifies (fail closed) and the
// embedded floor and compiled pins are what the driver uses.
func codeVendorKeys() []ed25519.PublicKey { return nil }

// codeFeedKeys: no content-feed key either in this build.
func codeFeedKeys() []ed25519.PublicKey { return nil }
