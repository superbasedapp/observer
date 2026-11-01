package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/git"
)

// codeintel_core.go holds the helpers core paths use (the proxy profiles'
// collapse settings, backfill's project-root mapping), split out of
// codeintel.go so they stay in a build without the codeintel component
// (-tags sbo_omit_codeintel, lane MP-L1H, T-715).

// codeCollapseSettings resolves the [codeintel.compression] body-collapse
// settings the proxy's profile pipelines apply. Fail-closed: collapse is on
// only when the module itself is on AND code_aggressive is set, so with
// code intelligence off (the default since D-307) it is a no-op whatever
// the compression keys say. exts is the opt-in extension set.
func codeCollapseSettings(cfg config.Config) (enabled bool, exts map[string]bool, preview bool) {
	if !cfg.CodeIntel.Enabled || !cfg.CodeIntel.Compression.CodeAggressive {
		return false, nil, false
	}
	return true, aggressiveExtsFor(cfg.CodeIntel.Compression.AggressiveLanguages), cfg.CodeIntel.Compression.PreviewOnly
}

// absPath resolves p to an absolute path (cwd-relative when p is
// relative or empty).
func absPath(p string) (string, error) {
	if p == "" {
		p = "."
	}
	return filepath.Abs(p)
}

// resolveProjectRoot maps a directory to the top level of its checkout,
// falling back to the absolute directory for non-git trees. Inside a
// linked worktree that is the worktree itself (git.FindCheckoutRoot,
// F0-14): the index is built from the files the agent sees, and the MCP
// symbol tools are asked about that same directory.
func resolveProjectRoot(dir string) string {
	if root, ok := git.FindCheckoutRoot(dir); ok {
		return root
	}
	if abs, err := absPath(dir); err == nil {
		return abs
	}
	return dir
}
