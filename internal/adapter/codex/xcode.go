package codex

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Xcode's Codex (surface-gap FU-150, S-2). Xcode 26.3+ runs its Codex with
// CODEX_HOME set to the catalogued codex/xcode-agent-home directory (macOS
// only) and writes the same rollouts under its sessions/ (MAC-1 read,
// 2026-10-28). Codex proper watches that tree beside ~/.codex/sessions and
// stamps a session read from it ide/xcode: the rollout's place is the
// grounded fact; the originator Xcode's Codex writes is not grounded, so it
// never decides. The Open Interpreter variant has no such home
// (hostHomeArtifact empty).

// xcodeHomeArtifact is the catalogued Xcode Codex home.
const xcodeHomeArtifact = "codex/xcode-agent-home"

// xcodeSurfaceHost is the surface host of a session read from the Xcode
// home (in the reviewed org-wire host set, knownSurfaceHosts).
const xcodeSurfaceHost = "xcode"

// hostSessionsRoot is <artifact directory>/sessions on this machine, ""
// where the catalogue names no such home for goos.
func hostSessionsRoot(artifact, goos, home string) string {
	if artifact == "" || home == "" {
		return ""
	}
	got, err := agentconfig.ResolveArtifact(artifact, agentconfig.PathEnv{GOOS: goos, Home: home})
	if err != nil || got.Status != agentconfig.PathDirectory || got.Path == "" {
		return ""
	}
	return filepath.Join(filepath.Clean(got.Path), "sessions")
}

// xcodeRoot is this instance's Xcode sessions root (a.xcodeRootFn in tests).
func (a *Adapter) xcodeRoot() string {
	if a.xcodeRootFn != nil {
		return a.xcodeRootFn()
	}
	if a.hostHomeArtifact == "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return hostSessionsRoot(a.hostHomeArtifact, runtime.GOOS, home)
}

// hostedSurface is the surface a rollout at path is stamped with because of
// where it lives, ok=false when its place says nothing.
func (a *Adapter) hostedSurface(path string) (kind, host string, ok bool) {
	if r := a.xcodeRoot(); r != "" && adapter.UnderAnyWatchRoot(path, []string{r}) {
		return models.SurfaceIDE, xcodeSurfaceHost, true
	}
	return "", "", false
}
