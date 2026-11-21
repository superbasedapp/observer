package main

import (
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// hook_projectroot.go derives the project root of a hook event whose payload
// names none (lane sec-p2a audit finding 1): Claude Code's PreToolUse, Codex
// and most tool gates carry only the working directory, so the guard's org
// project layer and its project_unknown floor never applied there. The
// derived root goes into policy.Event.ProjectLookupRoot, which the guard's
// project lookup, the floor and the approval lookup read (a project-scoped
// grant matches on it, P-232: before that the approval lookup read only
// ProjectRoot and a project grant never applied on these hooks);
// ProjectRoot stays as the host sent it (empty on those hooks), so the
// boundary rules keep their documented hook-path behaviour. The git checkout
// around cwd goes into policy.Event.RepoRoot, which only the destructive
// rules' outside-the-project arms read (R-101, D-MU10; R-102 and R-141's
// chown arm, surface-gap FU-101). Built with and without the security
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
//
// A foreign cwd is translated first, the way the watcher translates it
// before git.ResolveIdentity (crossmount.TranslateForeignPath in the
// claudecode adapter): a Windows Claude Code whose hook runs inside WSL
// through the wsl.exe bridge sends `C:\x\repo`, the watcher records
// projects.root_path as /mnt/c/x/repo, and a project grant hashed from that
// root must match the hook's root byte for byte (P-232). NormalizeForeign
// rewrites only unmistakably foreign spellings, so a native cwd is never
// changed.
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
	return hookRootOf(pathnorm.NormalizeForeign(pe.Cwd))
}

// hookRepoRoot is the root the destructive rules' outside-the-project arms
// judge an event with no ProjectRoot against (policy.Event.RepoRoot: R-101,
// D-MU10; R-102 and R-141's chown arm, FU-101): the relayed run's checkout
// (RunCheckoutRoot, else its project root), else the git checkout
// containing the working directory. It is the CHECKOUT, not the identity
// root: a linked worktree that lives outside its main repository is its own
// tree for a delete, so `rm -rf build` there is inside the project (MACUSER
// merge H1), while the posture key (hookProjectRoot) stays the main
// repository (F0-14). Outside any working tree it is "": the bare cwd is
// never a project root (R-101's home-folder arm covers that case).
//
// A foreign cwd is translated first, as hookProjectRoot does
// (pathnorm.NormalizeForeign, the store's spelling): a Windows host whose
// hook runs on a WSL daemon through the wsl.exe bridge (the IBM Bob IDE)
// sends its own `d:\repo`, which the Linux hook finds at `/mnt/d/repo`
// (surface-gap FU-101). A native spelling is unchanged.
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
	if root, ok := hookFindCheckoutRoot(pathnorm.NormalizeForeign(pe.Cwd)); ok {
		return root
	}
	return ""
}

// hookFindCheckoutRoot is git.FindCheckoutRoot; a test seam so a receiver
// test can stand a checkout at a path the test host does not have (a
// Windows cwd read through drvfs).
var hookFindCheckoutRoot = git.FindCheckoutRoot

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
