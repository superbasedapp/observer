//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// sandbox_setup_oci_linux.go reads the docker-group step's passive facts:
// Docker's rootful socket (owner, group, mode) and the engine socket the row
// will use (its owner), with this process's own uid and groups. Every read
// is an lstat; nothing is dialed or executed.

func init() {
	sandboxSetupDockerAccess = sandboxSetupOCIDockerAccess
}

// sandboxDockerRootfulSocket is Docker's rootful socket path (the oci
// driver's rootful candidate; /var/run is a symlink to /run on most
// distributions).
const sandboxDockerRootfulSocket = "/run/docker.sock"

// sandboxSetupOCIDockerAccess gathers sandboxsetup.DockerAccess for cfg.
func sandboxSetupOCIDockerAccess(cfg config.Config) (sandboxsetup.DockerAccess, bool) {
	a := sandboxsetup.DockerAccess{UID: uint32(os.Getuid())} //nolint:gosec // G115: getuid(2)
	if gs, err := os.Getgroups(); err == nil {
		for _, g := range gs {
			a.Groups = append(a.Groups, uint32(g)) //nolint:gosec // G115: a group id from getgroups(2)
		}
	}
	a.Groups = append(a.Groups, uint32(os.Getgid())) //nolint:gosec // G115: getgid(2)
	if f, err := statSocketChain(sandboxDockerRootfulSocket); err == nil && f.Exists && f.IsSocket {
		a.DockerSocket, a.DockerUID, a.DockerGID, a.DockerMode = sandboxDockerRootfulSocket, f.UID, f.GID, f.Mode
	}
	if eng := sandboxSetupOCIEngineSocket(cfg); eng != "" {
		if f, err := statSocketChain(eng); err == nil && f.Exists && f.IsSocket {
			a.EngineSocket, a.EngineUID = eng, f.UID
		}
	}
	return a, true
}
