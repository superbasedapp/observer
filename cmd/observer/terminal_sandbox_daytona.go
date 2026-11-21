//go:build !sbo_omit_terminals_sandbox_daytona && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/daytona"
)

// terminal_sandbox_daytona.go registers the Daytona hosted driver (the fifth
// hosted row, sandbox plan v2's Daytona row) with the shared hosted core
// (terminal_sandbox_hosted*.go): the one place that names the vendor's wire
// client. terminal_sandbox_daytona_omit.go is its twin in a build without
// it.
func init() {
	registerHostedVendor(hostedVendorReg{
		vendor: sandboxremote.VendorDaytona, component: "terminals.sandbox.daytona",
		newClient: func(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error) {
			v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
			return daytona.New(daytona.Options{Endpoint: endpoint, Key: cred.Get(v.EnvCredential[0])})
		},
	})
}
