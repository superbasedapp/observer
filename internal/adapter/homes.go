package adapter

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// RelocatedToolHome returns the directory a tool's home variable moves its
// catalogued artifact id to (the file's directory, then up levels above
// it), or "" when this process's environment moves nothing (surface-gap
// Wave 4, lane w4-homes-b; S-17). An adapter adds the relocated home's
// session subtree to its watch roots beside the per-home defaults, so the
// adapter, the hook writer and the route writer read one relocation rule
// (agentconfig's fileRelocations). Like AbsEnvRoot, the value is this
// process's own environment, so it is not re-resolved per cross-mount home;
// unlike AbsEnvRoot, a relative value names nothing (the tool reads it
// against a working directory the daemon does not share).
func RelocatedToolHome(id string, up int) string {
	home, _ := os.UserHomeDir()
	return relocatedToolHome(id, up, home, os.Getenv, runtime.GOOS)
}

// relocatedToolHome is RelocatedToolHome with its inputs injected.
func relocatedToolHome(id string, up int, home string, getenv func(string) string, goos string) string {
	got, err := agentconfig.ResolveArtifact(id, agentconfig.PathEnv{GOOS: goos, Home: home, Getenv: getenv})
	if err != nil || got.RelocatedBy == "" || got.Path == "" {
		return ""
	}
	if got.Status != agentconfig.PathResolved && got.Status != agentconfig.PathDirectory {
		return ""
	}
	d := filepath.Clean(got.Path)
	if got.Status == agentconfig.PathResolved {
		d = filepath.Dir(d)
	}
	for i := 0; i < up; i++ {
		d = filepath.Dir(d)
	}
	return d
}
