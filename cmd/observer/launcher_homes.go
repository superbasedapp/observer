package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// Launcher config homes (surface-gap Wave 4, lane w4-homes-b; S-17). A
// launcher that writes a session provider into a tool's own config file
// (pi's and prime-agent's models.json) names the file by its agentconfig
// artifact, so the tool's home variable (PI_CODING_AGENT_DIR,
// PRIME_AGENT_CODING_AGENT_DIR) moves the write: the launched tool inherits
// this process's environment, so the file it reads is the one this
// process's environment names.

// launcherArtifactPath resolves artifact id for a tool this process
// launches: this host's OS, home and environment.
func launcherArtifactPath(id string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return launcherArtifactPathAt(id, home, os.Getenv)
}

// launcherArtifactPathAt is launcherArtifactPath with the home and
// environment injected. A relocation variable whose relative value the tool
// reads against its own working directory is an error, never the default
// file.
func launcherArtifactPathAt(id, home string, getenv func(string) string) (string, error) {
	got, err := agentconfig.ResolveArtifact(id, agentconfig.PathEnv{GOOS: runtime.GOOS, Home: home, Getenv: getenv})
	if err != nil {
		return "", err
	}
	switch got.Status {
	case agentconfig.PathResolved:
		return got.Path, nil
	case agentconfig.PathRelocationUnresolved:
		return "", fmt.Errorf("%s is set to a relative path, which the tool reads against its own working directory; set an absolute path", got.RelocatedBy)
	}
	return "", fmt.Errorf("%s has no path on %s", id, runtime.GOOS)
}
