//go:build !sbo_omit_org_update

package main

import (
	"encoding/base64"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// cloudSessionVendorKeys returns the accepted vendor verification keys,
// base64, newest first: the keys the cloud-session setup script verifies the
// pinned release archive against.
func cloudSessionVendorKeys() []string {
	var out []string
	for _, k := range update.VendorPublicKeys() {
		out = append(out, base64.StdEncoding.EncodeToString(k))
	}
	return out
}
