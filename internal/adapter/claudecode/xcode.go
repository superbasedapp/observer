package claudecode

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Xcode's Claude Agent (surface-gap FU-150, S-2). Xcode 26.3+ runs its
// bundled Claude with CLAUDE_CONFIG_DIR set to the catalogued
// claude-code/xcode-agent-home directory (macOS only) and writes the same
// JSONL transcripts under its projects/ (MAC-1 read, 2026-10-28). The
// adapter watches that tree beside ~/.claude/projects and stamps a session
// read from it ide/xcode: the transcript's place is the grounded fact; the
// entrypoint Xcode's Claude writes is not grounded, so it never decides.

// xcodeHomeArtifact is the catalogued Xcode Claude Agent home.
const xcodeHomeArtifact = "claude-code/xcode-agent-home"

// xcodeSurfaceHost is the surface host of a session read from the Xcode
// home (in the reviewed org-wire host set, knownSurfaceHosts).
const xcodeSurfaceHost = "xcode"

// xcodeProjectsRoot is <Xcode Claude Agent home>/projects on this machine,
// "" where the catalogue names no such home (every OS but macOS) or the
// home cannot be resolved.
func xcodeProjectsRoot(goos, home string) string {
	if home == "" {
		return ""
	}
	got, err := agentconfig.ResolveArtifact(xcodeHomeArtifact, agentconfig.PathEnv{GOOS: goos, Home: home})
	if err != nil || got.Status != agentconfig.PathDirectory || got.Path == "" {
		return ""
	}
	return filepath.Join(filepath.Clean(got.Path), "projects")
}

// xcodeRoot is this adapter's Xcode projects root (a.xcodeRootFn in tests).
func (a *Adapter) xcodeRoot() string {
	if a.xcodeRootFn != nil {
		return a.xcodeRootFn()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return xcodeProjectsRoot(runtime.GOOS, home)
}

// hostedSurface is the surface a transcript at path is stamped with because
// of where it lives, ok=false when its place says nothing.
func (a *Adapter) hostedSurface(path string) (kind, host string, ok bool) {
	if r := a.xcodeRoot(); r != "" && adapter.UnderAnyWatchRoot(path, []string{r}) {
		return models.SurfaceIDE, xcodeSurfaceHost, true
	}
	return "", "", false
}
