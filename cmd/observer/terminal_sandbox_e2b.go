//go:build !sbo_omit_terminals_sandbox_e2b && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/e2b"
)

// terminal_sandbox_e2b.go registers the E2B hosted driver (sandbox plan v2
// section 13 P7 R2, lane SBX-P7) with the shared hosted core
// (terminal_sandbox_hosted*.go): the one place that names the vendor's wire
// client. terminal_sandbox_e2b_omit.go is its twin in a build without it.
func init() {
	registerHostedVendor(hostedVendorReg{
		vendor: sandboxremote.VendorE2B, component: "terminals.sandbox.e2b",
		newClient: func(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error) {
			// A credential connected for a pinned endpoint pins its server
			// key (SBX-GOV-4, lane SBX-UPD).
			return e2b.New(e2b.Options{Endpoint: endpoint, APIKey: cred.Get("E2B_API_KEY"), SPKISHA256: cred.SPKISHA256})
		},
	})
}
