package gemini

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// Xcode's Gemini agent (surface-gap FU-160, S-2). Xcode 26.6 bundles a
// Gemini CLI (CodingAssistant/Agents/gemini) whose home is the catalogued
// gemini-cli/xcode-agent-home directory (macOS only), a .gemini folder
// with the CLI's own layout: settings.json, GEMINI.md, projects.json,
// history/ and tmp/ (Mac round 5b, 2026-10-28). The adapter watches its
// tmp/ beside ~/.gemini/tmp, through the same path classifier (only
// tmp/<project>/chats/session-* is a session file), and stamps a session
// read from it ide/xcode: the chat's place is the grounded fact. The
// project resolves from that home's own .project_root sidecars and
// projects.json (resolveProjectRoot walks up from the chat), never from
// ~/.gemini.

// xcodeHomeArtifact is the catalogued Xcode Gemini CLI home.
const xcodeHomeArtifact = "gemini-cli/xcode-agent-home"

// xcodeSurfaceHost is the surface host of a session read from the Xcode
// home (in the reviewed org-wire host set, knownSurfaceHosts).
const xcodeSurfaceHost = "xcode"

// xcodeChatsRoot is <Xcode Gemini home>/tmp on this machine, "" where the
// catalogue names no such home (every OS but macOS) or the home cannot be
// resolved.
func xcodeChatsRoot(goos, home string) string {
	if home == "" {
		return ""
	}
	got, err := agentconfig.ResolveArtifact(xcodeHomeArtifact, agentconfig.PathEnv{GOOS: goos, Home: home})
	if err != nil || got.Status != agentconfig.PathDirectory || got.Path == "" {
		return ""
	}
	return filepath.Join(filepath.Clean(got.Path), "tmp")
}

// xcodeRoot is this adapter's Xcode chats root (a.xcodeRootFn in tests).
func (a *Adapter) xcodeRoot() string {
	if a.xcodeRootFn != nil {
		return a.xcodeRootFn()
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return xcodeChatsRoot(runtime.GOOS, home)
}

// stampHostedSurface adds one ide/xcode SessionSurface per session res
// carries events for when path lives under the Xcode home. A chunk with no
// event stamps nothing; the next one that has events does (the store write
// is first-wins-unless-empty, so a re-stamp is harmless).
func (a *Adapter) stampHostedSurface(path string, res *adapter.ParseResult) {
	r := a.xcodeRoot()
	if r == "" || !adapter.UnderAnyWatchRoot(path, []string{r}) {
		return
	}
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		res.SessionSurfaces = append(res.SessionSurfaces, models.SessionSurface{
			SessionID:   id,
			Surface:     models.SurfaceIDE,
			SurfaceHost: xcodeSurfaceHost,
		})
	}
	for _, e := range res.ToolEvents {
		add(e.SessionID)
	}
	for _, e := range res.TokenEvents {
		add(e.SessionID)
	}
}
