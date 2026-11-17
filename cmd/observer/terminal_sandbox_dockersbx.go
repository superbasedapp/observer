//go:build !sbo_omit_terminals_sandbox_docker && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote/dockersbx"
)

// terminal_sandbox_dockersbx.go registers the Docker Sandboxes hosted driver
// (lane SBX-DOCKER) with the shared hosted core (terminal_sandbox_hosted*.go):
// the one place that names the vendor's wire client. The credential's two
// fields are the vendor row's environment names, in order: the account's
// access token, then the Docker ID. terminal_sandbox_dockersbx_omit.go is
// its twin in a build without it.
func init() {
	registerHostedVendor(hostedVendorReg{
		vendor: sandboxremote.VendorDockerSandboxes, component: "terminals.sandbox.docker",
		newClient: func(cred sandboxremote.Credential, endpoint string) (sandboxremote.Client, error) {
			v, _ := sandboxremote.VendorFor(sandboxremote.VendorDockerSandboxes)
			if len(v.EnvCredential) != 2 {
				return nil, errors.New("docker-sandboxes: the vendor row names no credential fields")
			}
			return dockersbx.New(dockersbx.Options{
				Endpoint: endpoint, Access: cred.Get(v.EnvCredential[0]), DockerID: cred.Get(v.EnvCredential[1]),
			})
		},
	})
}
