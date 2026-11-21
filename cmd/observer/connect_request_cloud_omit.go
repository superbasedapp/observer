//go:build sbo_omit_cloud_intelligence

package main

import "github.com/marmutapp/superbased-observer/internal/orgcontract"

// connect_request_cloud_omit.go: a build without Cloud Intelligence links no
// cloud network package, so it has no connect request seams; `observer
// connect` with no address asks for the organization's address instead
// (printConnectNeedsAddress).

func defaultConnectRequestSeams() connectRequestSeams { return connectRequestSeams{} }

// defaultAttachProver: a build without Cloud Intelligence has no device key,
// so `observer enroll --attach-grant-file` refuses and names --idp.
func defaultAttachProver() func(configPath string) func(grant, agentPublicKey string) (orgcontract.AttachProof, error) {
	return nil
}
