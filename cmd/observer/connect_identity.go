//go:build !sbo_omit_cloud_intelligence

package main

import (
	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/frontdoor"
)

// connect_identity.go is `observer connect`'s identity owner in a build with
// Cloud Intelligence: the sign-in IS `observer cloud login`, run as typed,
// and the state is the dashboard's own local credential read
// (probeCloudSignIn; no network call).

// connectIdentityState reads the local SuperBased sign-in state.
func connectIdentityState(configPath string) frontdoor.Identity {
	st, err := probeCloudSignIn(configPath)
	if err != nil {
		return frontdoor.IdentityUnknown
	}
	if st.APITokenPresent || st.WorkOSSignInPresent {
		return frontdoor.IdentitySignedIn
	}
	return frontdoor.IdentitySignedOut
}

// runConnectIdentity runs `observer cloud login` with args.
func runConnectIdentity(cmd *cobra.Command, args []string) error {
	return runSubcommand(cmd, newCloudLoginCmd(), args, cmd.InOrStdin())
}
