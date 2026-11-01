//go:build !sbo_omit_terminals_sandbox_modal && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/modal"
)

// terminal_sandbox_modal.go registers the Modal hosted driver (sandbox plan
// v2 section 13 P7 R3, lane SBX-P7) with the shared hosted core
// (terminal_sandbox_hosted*.go): the one place that names the vendor's wire
// client, and so the one place that links Modal's Go SDK.
// terminal_sandbox_modal_omit.go is its twin in a build without it.
func init() {
	registerHostedVendor(hostedVendorReg{
		vendor: sandboxremote.VendorModal, component: "terminals.sandbox.modal",
		newClient: func(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error) {
			return modal.New(modal.Options{Endpoint: endpoint, TokenID: cred.Get("MODAL_TOKEN_ID"), TokenSecret: cred.Get("MODAL_TOKEN_SECRET")})
		},
	})
}
