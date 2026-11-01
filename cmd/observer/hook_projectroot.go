package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// hook_projectroot.go derives the project root of a hook event whose payload
// names none (lane sec-p2a audit finding 1): Claude Code's PreToolUse, Codex
// and most tool gates carry only the working directory, so the guard's org
// project layer and its project_unknown floor never applied there. The
// derived root goes into policy.Event.ProjectLookupRoot, which only the
// guard's project lookup and the floor read; ProjectRoot stays as the host
// sent it (empty on those hooks), so the boundary rules keep their
// documented hook-path behaviour. Built with and without the security
// module: the project layer is guard's, not the pillar's.

// withProjectLookupRoot returns the tool gate's Enrich step: it stamps the
// event's project lookup root (hookProjectRoot: the relayed run's root, the
// host's root, else the identity root of the working directory), then runs
// next (nil runs nothing more). File reads only, no git process.
func withProjectLookupRoot(next func(*policy.Event)) func(*policy.Event) {
	return func(pe *policy.Event) {
		if pe.ProjectLookupRoot == "" {
			pe.ProjectLookupRoot = hookProjectRoot(pe)
		}
		if pe.ProjectRoot == "" && pe.RepoRoot == "" {
			pe.RepoRoot = hookRepoRoot(pe)
		}
		if next != nil {
			next(pe)
		}
	}
}

// hookProjectRoot is the project an event belongs to, spelled the way the
// daemon spells a project root (internal/git.Resolve, as the watcher
// records projects.root_path): the event's own root when the host sent
// one, else the git working tree containing the working directory (or the
// directory itself, absolute and with symlinks resolved, outside any
// tree). A subdirectory of a repository is never hashed as a project of
// its own. It reads no branch and no remote (git.FindRoot, not
// git.Resolve): the hook needs the root only.
func hookProjectRoot(pe *policy.Event) string {
	// A relayed event's project is the run's (the host launch fact the
	// relay channel carries), never a directory the box reported (lane
	// sbx-p2b, plans decision log P-026).
	if root := hookctx.Process().RunProjectRoot(); root != "" {
		return root
	}
	if pe.ProjectRoot != "" {
		return pe.ProjectRoot
	}
	if pe.Cwd == "" {
		return ""
	}
	return hookRootOf(pe.Cwd)
}

// hookRepoRoot is the root R-101's recursive-delete arms judge an event
// with no ProjectRoot against (policy.Event.RepoRoot, D-MU10): the relayed
// run's checkout (RunCheckoutRoot, else its project root), else the git
// checkout containing the working directory. It is the CHECKOUT, not the
// identity root: a linked worktree that lives outside its main repository
// is its own tree for a delete, so `rm -rf build` there is inside the
// project (MACUSER merge H1), while the posture key (hookProjectRoot) stays
// the main repository (F0-14). Outside any working tree it is "": the bare
// cwd is never a project root (R-101's home-folder arm covers that case).
func hookRepoRoot(pe *policy.Event) string {
	if root := hookctx.Process().RunCheckoutRoot(); root != "" {
		return root
	}
	if root := hookctx.Process().RunProjectRoot(); root != "" {
		return root
	}
	if pe.Cwd == "" {
		return ""
	}
	if root, ok := git.FindCheckoutRoot(pe.Cwd); ok {
		return root
	}
	return ""
}

// hookRootOf is the git working tree containing dir, else dir itself made
// absolute with symlinks resolved (git.Resolve's Root, without its branch
// and remote reads). Inside a linked worktree it is the main repository's
// top level (F0-14), so the posture key matches the session's project.
func hookRootOf(dir string) string {
	if root, ok := git.FindRoot(dir); ok {
		return root
	}
	return hookAbs(dir)
}

func hookAbs(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}
