//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_org_update

package main

import (
	"crypto/ed25519"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// depsVendorKeys is the vendor key set compiled into this agent, the one
// the signed content channel verifies the install index with.
func depsVendorKeys() []ed25519.PublicKey { return update.VendorPublicKeys() }

// depsFeedKeys is the content-feed key set compiled into this agent
// (update.ContentFeedPublicKeys), accepted for the feed-signed advisory
// kinds (the install index, the OSV exports) only.
func depsFeedKeys() []ed25519.PublicKey { return update.ContentFeedPublicKeys() }
