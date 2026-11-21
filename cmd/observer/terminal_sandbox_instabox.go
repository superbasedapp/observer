//go:build !sbo_omit_terminals_sandbox_instabox && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/instabox"
)

// terminal_sandbox_instabox.go registers the InstaBox hosted driver with
// the shared hosted core (terminal_sandbox_hosted*.go): the one place that
// names the vendor's wire client. terminal_sandbox_instabox_omit.go is its
// twin in a build without it.
func init() {
	registerHostedVendor(hostedVendorReg{
		vendor: sandboxremote.VendorInstaBox, component: "terminals.sandbox.instabox",
		newClient: func(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error) {
			return instabox.New(instabox.Options{Endpoint: endpoint, Key: cred.Get("INSTABOX_API_KEY")})
		},
	})
}
