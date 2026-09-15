package main

import (
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
)

// attestTokenSourceFromEnv resolves the managed-identity token source for the
// ContentLogging ARM canary (gap 5.1). SBCI_ARM_TOKEN, when set, wins — a
// fixed StaticTokenSource for dev/test or a manually rotated token, exactly
// the pre-D6 behaviour. Otherwise it returns the real Azure IMDS source
// (internal/cloudserver/attest.ManagedIdentityTokenSource), scoped to a
// user-assigned identity when SBCI_ARM_IDENTITY_CLIENT_ID is set, else the
// host's system-assigned (or sole) identity.
//
// This is additive: chooseAttestor in main.go still builds the
// attest.ARMAttestor and the operator-attested override exactly as before;
// only its Tokens field changes from the inline StaticTokenSource literal to
// this function. See the orchestrator note in this wave's final report for
// the one-line edit.
func attestTokenSourceFromEnv() attest.TokenSource {
	if tok := strings.TrimSpace(os.Getenv("SBCI_ARM_TOKEN")); tok != "" {
		return attest.StaticTokenSource{Value: tok}
	}
	return &attest.ManagedIdentityTokenSource{
		ClientID: strings.TrimSpace(os.Getenv("SBCI_ARM_IDENTITY_CLIENT_ID")),
	}
}
