//go:build sbo_omit_cloud_intelligence

package main

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/frontdoor"
)

// connect_identity_omit.go: a build without Cloud Intelligence has no
// SuperBased sign-in (cloud_omit.go), so `observer connect` attaches only.
// The status sentence then says nothing about identity.

func connectIdentityState(string) frontdoor.Identity { return frontdoor.IdentityUnknown }

func runConnectIdentity(*cobra.Command, []string) error {
	return errors.New("observer connect --identity-only: superbased sign-in is not in this build; connecting to a team server by its address still works (observer connect <server>)")
}
