//go:build !sbo_omit_terminals_sandbox_vercel && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/vercel"
)

// terminal_sandbox_vercel.go registers the Vercel Sandbox hosted driver
// (sandbox plan v2 section 13 P7 R4, lane SBX-P7) with the shared hosted
// core (terminal_sandbox_hosted*.go): the one place that names the vendor's
// wire client. terminal_sandbox_vercel_omit.go is its twin in a build
// without it.
func init() {
	registerHostedVendor(hostedVendorReg{
		vendor: sandboxremote.VendorVercel, component: "terminals.sandbox.vercel",
		newClient: func(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error) {
			return vercel.New(vercel.Options{
				Endpoint: endpoint, Token: cred.Get("VERCEL_TOKEN"),
				TeamID: cred.Get("VERCEL_TEAM_ID"), ProjectID: cred.Get("VERCEL_PROJECT_ID"),
			})
		},
	})
}
