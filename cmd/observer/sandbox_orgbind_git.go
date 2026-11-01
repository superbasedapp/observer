//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// sandbox_orgbind_git.go protects the repositories an org-set write bind
// exposes (orchestrator ruling P-054, SBX-P2E audit finding 8). A write bind
// of a project directory stays allowed (the ancestor rule covers the home and
// system locations, not a repository's own .git internals), but the box must
// not plant a hook or a config the next host git command runs: the bind's
// repository's .git/hooks and .git/config are re-bound read-only inside the
// box through the launch's protective overlays (sandboxRuntime.overlays,
// applied after every rw bind, so the rw bind cannot re-open them), the same
// rows the workspace's own repository gets (sandbox.WorkspaceExecState).
// Unlike the workspace rows these do not yield to allow_tool_config_writes:
// that switch is the developer's, and the bind is the org's.
//
// Each repository found also has its folder and its .git pinned (bound onto
// themselves, sandbox.Request.Pins), so the box cannot rename the .git or
// the repository aside and plant a replacement the overlays above would no
// longer cover (SBX-WORKTREE-SOURCE audit finding 4); the live-source
// workspace's .git gets the same pin (sandboxRuntime.protection).

// The walk under one org write bind (P-054 follow-up, lane
// SBX-WORKTREE-SOURCE milestone 5; one shared budget since lane LEFT-SBX,
// ledger SBX-GOV-3): a repository is found at the bind and at any plain
// directory level below it, and directly inside any repository found (as
// before). The bind's walk, the .git/modules walk of every repository it
// finds and their linked-worktree listings share ONE budget of
// sandboxOrgBindScanCap directory reads, where a folder is read in pages of
// sandboxOrgBindPageSize entries and each page counts as one read. A folder
// with more entries than one page is therefore read in pages within the
// budget instead of refusing (the P-082 residual: a large real cache folder
// refused the launch), and depth is bounded by the budget, not by a fixed
// number of levels (a repository five plain levels below the bind was not
// covered). A walk that spends the budget still refuses the launch naming
// the bind, never a silent skip, so an org can narrow the bind or mark it
// skip_repo_scan. The budget is 20000 (orchestrator ruling P-060,
// SBX-WORKTREE-SOURCE audit finding 3): an ordinary cache bind such as
// ~/.cache/go-build (256 two-hex folders) needs 257 reads.
const (
	sandboxOrgBindScanCap  = 20000
	sandboxOrgBindPageSize = 4096
)

// remedyOrgWriteBind names who can lift a refusal on an org-set bind.
const remedyOrgWriteBind = ", or ask your organization's admin to change the sandbox write bind that exposes it"

// orgBindWalk is the one budget of the walk under one org write bind: every
// page of every folder read for the bind, its repositories, their modules
// and their linked worktrees counts against it.
type orgBindWalk struct {
	bind  string
	reads int
}

// readDir reads dir in pages of sandboxOrgBindPageSize entries, charging one
// read per page. ok=false (with no error) is a folder that cannot be opened:
// it holds nothing the box could reach either. err is the budget's refusal.
func (w *orgBindWalk) readDir(dir string) (entries []os.DirEntry, ok bool, err error) {
	f, oerr := os.Open(dir) //nolint:gosec // G304: a folder under an org write bind, read only
	if oerr != nil {
		return nil, false, nil
	}
	defer func() { _ = f.Close() }()
	for {
		if err := w.charge(); err != nil {
			return nil, false, err
		}
		page, rerr := f.ReadDir(sandboxOrgBindPageSize)
		entries = append(entries, page...)
		if rerr != nil || len(page) < sandboxOrgBindPageSize {
			if rerr != nil && !errors.Is(rerr, io.EOF) && len(entries) == 0 {
				return nil, false, nil
			}
			return entries, true, nil
		}
	}
}

// charge spends one read of the budget, refusing past it. The walk keeps
// its full depth and fails closed over the budget (ruling P-141 part 2: a
// fixed four-level stop could miss a nested git dir); the refusal names
// the bind, the count and the remedy.
func (w *orgBindWalk) charge() error {
	w.reads++
	if w.reads > sandboxOrgBindScanCap {
		return sandboxOrgBindBudgetRefusal(w.bind)
	}
	return nil
}

// sandboxOrgBindBudgetRefusal is the refusal of a bind whose walk spent the
// budget: the bind, the count read and the remedy (skip_repo_scan, or a
// narrower bind).
func sandboxOrgBindBudgetRefusal(bind string) error {
	return fmt.Errorf("terminal_sandbox: the organization's sandbox write bind %s holds more than %d directories (pages of %d entries) across the bind, its repositories, their submodules and linked worktrees; the walk read %d, its whole budget, and stopped, so not every repository below the bind could have its git hooks and config made read-only in the box, and the launch is refused; to launch, ask your organization's admin to mark %s skip_repo_scan (\"Write binds that hold no repositories\" on your page in the org dashboard; an assertion that it holds no repository) or to narrow the bind",
		bind, sandboxOrgBindScanCap, sandboxOrgBindPageSize, sandboxOrgBindScanCap, bind)
}

// sandboxOrgBindGitRows is the protected rows for the org-set write binds:
// for each repository the walk finds under a bind (the bind itself, the
// plain directories below it at any depth the budget reaches, and the
// directories directly inside a repository found) that holds a .git
// directory, its git-dir execution paths (sandbox.WorkspaceExecState) read
// only, and the same for each submodule and linked-worktree git dir it
// keeps; for a .git FILE (a worktree or submodule pointer, which a rewrite
// would point at a planted config), the file itself read-only. A symlinked
// .git is a row too, so the launch refuses it naming the path
// (protectPath). A walk that spends its budget refuses the launch. pins are
// the repository folders (other than a bind itself, already a mount point)
// and their .git directories or files, bound onto themselves before the
// overlays so neither can be renamed in the box.
//
// skipScan are binds the organization asserts hold no repositories
// (node.skip_repo_scan, ruling P-060, ledger SBX-GOV-3): for each, only the
// bind itself is checked for a .git (one stat, no walk), so the budget does
// not apply to it; every other bind is walked exactly as above.
func sandboxOrgBindGitRows(binds, skipScan []string) (rows []protectedRow, pins []string, err error) {
	skip := map[string]bool{}
	for _, b := range skipScan {
		skip[filepath.Clean(b)] = true
	}
	for _, b := range binds {
		w := &orgBindWalk{bind: b}
		var repos []string
		if skip[filepath.Clean(b)] {
			if _, lerr := os.Lstat(filepath.Join(b, ".git")); lerr == nil {
				repos = []string{b}
			}
		} else if repos, err = w.repoCandidates(); err != nil {
			return nil, nil, err
		}
		for _, repo := range repos {
			gitPath := filepath.Join(repo, ".git")
			var modPins, wtPins []string
			fi, err := os.Lstat(gitPath)
			if err != nil {
				continue
			}
			switch {
			case fi.Mode()&os.ModeSymlink != 0:
				rows = append(rows, protectedRow{path: gitPath, kind: sandbox.OverlayReadOnly, remedy: remedyOrgWriteBind})
				continue
			case fi.Mode().IsRegular():
				rows = append(rows, protectedRow{path: gitPath, kind: sandbox.OverlayReadOnly, remedy: remedyOrgWriteBind})
			case fi.IsDir():
				rows = append(rows, sandboxGitDirExecRows(gitPath, remedyOrgWriteBind)...)
				var modRows, wtRows []protectedRow
				modRows, modPins, err = w.moduleGitDirs(gitPath)
				if err != nil {
					return nil, nil, err
				}
				rows = append(rows, modRows...)
				wtRows, wtPins, err = sandboxLinkedWorktreeRows(gitPath, remedyOrgWriteBind, w)
				if err != nil {
					return nil, nil, err
				}
				rows = append(rows, wtRows...)
			default:
				continue
			}
			if filepath.Clean(repo) != filepath.Clean(b) {
				pins = append(pins, repo)
			}
			// A parent folder is pinned before the folders inside it.
			pins = append(pins, gitPath)
			if fi.IsDir() {
				pins = append(pins, sandboxGitDirParentPins(gitPath)...)
			}
			pins = append(pins, modPins...)
			pins = append(pins, wtPins...)
		}
	}
	return rows, pins, nil
}

// sandboxOrgBindRepoCandidates is the repository walk of one bind with its
// own budget (repoCandidates).
func sandboxOrgBindRepoCandidates(bind string) ([]string, error) {
	return (&orgBindWalk{bind: bind}).repoCandidates()
}

// repoCandidates walks the bind breadth first (never through a symlink,
// never into .git) and returns the directories that hold a .git entry: the
// bind and the plain directories below it at any depth, plus the
// directories directly inside a repository (the walk does not go deeper
// into a repository's own tree). A folder that cannot be read holds nothing
// the box could reach either.
func (w *orgBindWalk) repoCandidates() ([]string, error) {
	queue := []string{w.bind}
	var out []string
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		entries, ok, err := w.readDir(d)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		repo := false
		var subdirs []string
		for _, e := range entries {
			if e.Name() == ".git" {
				repo = true
				continue
			}
			if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
				subdirs = append(subdirs, filepath.Join(d, e.Name()))
			}
		}
		if repo {
			out = append(out, d)
		}
		for _, sd := range subdirs {
			if repo {
				// Directly inside a repository, as before: a nested
				// repository holds its own .git.
				if _, err := os.Lstat(filepath.Join(sd, ".git")); err == nil {
					out = append(out, sd)
				}
				continue
			}
			queue = append(queue, sd)
		}
	}
	return out, nil
}

// sandboxGitDirExecRows is the read-only rows of one git dir's execution
// paths (sandbox.WorkspaceExecState, the one table, relative to gitDir).
func sandboxGitDirExecRows(gitDir, remedy string) []protectedRow {
	rows := make([]protectedRow, 0, len(sandbox.WorkspaceExecState))
	for _, pp := range sandbox.WorkspaceExecState {
		rel := strings.TrimPrefix(filepath.ToSlash(pp.Rel), ".git/")
		rows = append(rows, protectedRow{path: filepath.Join(gitDir, filepath.FromSlash(rel)), kind: sandbox.OverlayReadOnly, dir: pp.Dir, remedy: remedy})
	}
	return rows
}

// sandboxLinkedWorktreeRows protects the linked-worktree git dirs a
// repository keeps under gitDir/worktrees (git's own registry of its linked
// worktrees, each <name> folder holding the gitdir back pointer to the
// worktree's .git file; ledger SBX-BE-21 residual, lane LEFT-SBX). A host
// git command run in a linked worktree elsewhere on disk reads that folder's
// commondir, config.worktree and the rest, so a box that can write the main
// repository's .git could otherwise redirect it at a planted config or
// hooks. Each <name> folder gets the same execution-path rows as the .git
// itself (sandboxGitDirExecRows; a missing one becomes a read-only
// placeholder under a writable bind, which git ignores there because those
// paths live in the common dir), and the worktrees folder, each <name>
// folder and the folders holding its protected paths are pinned, parents
// first. A symlinked <name> is a row, so the launch refuses it naming the
// path. A worktrees folder that exists but cannot be listed refuses the
// launch (fail closed). w, when not nil, is the org-bind walk whose budget
// the listing spends.
func sandboxLinkedWorktreeRows(gitDir, remedy string, w *orgBindWalk) (rows []protectedRow, pins []string, err error) {
	root := filepath.Join(gitDir, "worktrees")
	fi, lerr := os.Lstat(root)
	switch {
	case errors.Is(lerr, fs.ErrNotExist):
		return nil, nil, nil
	case lerr != nil:
		return nil, nil, fmt.Errorf("terminal_sandbox: cannot inspect the linked worktrees of %s: %w", gitDir, lerr)
	case fi.Mode()&os.ModeSymlink != 0:
		return []protectedRow{{path: root, kind: sandbox.OverlayReadOnly, dir: true, remedy: remedy}}, nil, nil
	case !fi.IsDir():
		return nil, nil, nil
	}
	var entries []os.DirEntry
	if w != nil {
		var ok bool
		if entries, ok, err = w.readDir(root); err != nil {
			return nil, nil, err
		} else if !ok {
			return nil, nil, fmt.Errorf("terminal_sandbox: cannot list the linked worktrees of %s, so their git config and hooks could not be made read-only in the box; the launch is refused%s", gitDir, remedy)
		}
	} else if entries, err = os.ReadDir(root); err != nil {
		return nil, nil, fmt.Errorf("terminal_sandbox: cannot list the linked worktrees of %s, so their git config and hooks could not be made read-only in the box; the launch is refused: %w", gitDir, err)
	}
	pins = append(pins, root)
	for _, e := range entries {
		dir := filepath.Join(root, e.Name())
		if e.Type()&os.ModeSymlink != 0 {
			rows = append(rows, protectedRow{path: dir, kind: sandbox.OverlayReadOnly, dir: true, remedy: remedy})
			continue
		}
		if !e.IsDir() {
			continue
		}
		rows = append(rows, sandboxGitDirExecRows(dir, remedy)...)
		pins = append(pins, dir)
		pins = append(pins, sandboxGitDirParentPins(dir)...)
	}
	return rows, pins, nil
}

// sandboxOrgBindModuleGitDirs is the modules walk of one repository with its
// own budget (moduleGitDirs).
func sandboxOrgBindModuleGitDirs(bind, gitDir string) (rows []protectedRow, pins []string, err error) {
	return (&orgBindWalk{bind: bind}).moduleGitDirs(gitDir)
}

// moduleGitDirs finds the submodule git directories a repository keeps
// under gitDir/modules (git's own layout since 1.7.8: an absorbed
// submodule's .git is a pointer FILE to .git/modules/<name>, and a nested
// submodule's git dir is in its parent git dir's modules folder). They are
// git data exactly like the repository's own .git: each one's execution
// paths are re-bound read-only, and each one, the modules folder and every
// folder between them are pinned, so the box can neither write a hook a
// host `git submodule` command would run nor rename a submodule's git dir
// aside and plant another (SHR-WORKTREE2 milestone 5, done in lane
// SHR-FOLLOWUPS). The walk never follows a symlink and never goes into a
// git dir's objects, refs or logs; a symlinked git dir config or hooks is a
// row, so the launch refuses it naming the path. It spends the bind walk's
// one budget (orgBindWalk), so depth is bounded by that budget.
func (w *orgBindWalk) moduleGitDirs(gitDir string) (rows []protectedRow, pins []string, err error) {
	root := filepath.Join(gitDir, "modules")
	if fi, lerr := os.Lstat(root); lerr != nil || !fi.IsDir() {
		return nil, nil, nil
	}
	// walk returns whether dir holds (at or below it) a submodule git dir,
	// so only the folders on a path to one are pinned.
	var walk func(dir string) (bool, error)
	walk = func(dir string) (bool, error) {
		entries, ok, err := w.readDir(dir)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		isGitDir := sandboxIsGitDir(dir, entries)
		found := isGitDir
		if isGitDir {
			rows = append(rows, sandboxGitDirExecRows(dir, remedyOrgWriteBind)...)
		}
		for _, e := range entries {
			if !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
				continue
			}
			// Inside a git dir only its own modules folder holds more
			// git dirs; everywhere else a folder may be part of a
			// submodule name with slashes.
			if isGitDir && e.Name() != "modules" {
				continue
			}
			sub, err := walk(filepath.Join(dir, e.Name()))
			if err != nil {
				return false, err
			}
			found = found || sub
		}
		if found {
			if isGitDir {
				// The folders holding the git dir's protected paths, in the
				// reverse of the order they are pinned in (the list is
				// reversed below, parents first).
				parents := sandboxGitDirParentPins(dir)
				slices.Reverse(parents)
				pins = append(pins, parents...)
			}
			pins = append(pins, dir)
		}
		return found, nil
	}
	if _, err := walk(root); err != nil {
		return nil, nil, err
	}
	// The walk records a folder after the folders inside it; pin parents
	// first.
	slices.Reverse(pins)
	return rows, pins, nil
}

// sandboxIsGitDir reports whether dir, holding entries, is a git directory
// by git's own test (setup.c is_git_directory): a HEAD file, an objects
// folder and a refs folder.
func sandboxIsGitDir(dir string, entries []os.DirEntry) bool {
	var head, objects, refs bool
	for _, e := range entries {
		switch e.Name() {
		case "HEAD":
			head = e.Type().IsRegular()
		case "objects":
			objects = e.IsDir()
		case "refs":
			refs = e.IsDir()
		}
	}
	return head && objects && refs
}
