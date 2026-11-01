//go:build !sbo_omit_org_update && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import "github.com/marmutapp/superbased-observer/internal/update"

// The sandbox content kinds verify against the vendor key set compiled into
// this agent (sandbox plan 12.3); a build without the update module carries
// none, so nothing it fetches verifies (artifact_unverified).
func init() { sandboxContentVendorKeys = update.VendorPublicKeys }
