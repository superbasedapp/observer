//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_worktree.go runs the `worktree` workspace source end to
// end (sandbox plan v2 section 6, lane SBX-WORKTREE-SOURCE; operator ruling
// P-047 "Offer it, off by default"). The pure planning is internal/workspace
// (worktree.go); this file is the one place it meets the filesystem and git:
//
//   - availability: the New Terminal picker offers the source only while
//     [terminal.sandbox].allow_worktree_source is on, says so when an org pin
//     keeps it off, and refuses it while a driver other than bwrap is
//     enabled. The oci-runc route stays refused (lane LEFT-SBX decision,
//     ledger SBX-BE-10): the agreed design gives the box a run-private
//     object directory instead of the writable shared object store, but
//     then the run's branch and the worktree's own index and HEAD, which
//     host git reads during and after the run (git gc, git status, the
//     end of run's clean check and `git worktree remove`), name objects
//     only that private directory holds until a checked import at return;
//     the import, its scan and the end-of-run ordering need a container
//     engine and a live run this lane cannot do, so the route is not
//     offered rather than offered half built;
//   - before `git worktree add`: the main repository's layout is checked (a
//     symlinked .git, common dir, object store or worktrees dir refuses the
//     launch, as does a reftable repository), its HEAD commit is read as the
//     run's base, and the run's record is written under the observer dir;
//   - at attach: the box gets the main repository's git common dir
//     read-only, then its object store, the worktree's own git dir and the
//     run's ref and reflog directories read-write, then read-only overlays
//     over what git follows or executes (hooks, config, info,
//     config.worktree, alternates, the other worktrees' git dirs, the
//     worktree's commondir/gitdir pointers and its .git file), whatever
//     allow_tool_config_writes says;
//   - at run end (a watcher per run, a sweep at daemon start and a sweep
//     before every worktree launch, which also finish a crashed run):
//     `git worktree remove` only for a clean worktree on the run's branch
//     that holds no other repository (no gitlink in its index, no modules
//     folder in its git dir, no nested .git in its tree), then only this
//     run's own registration is removed (never `git worktree prune` over
//     the whole repository), and the branch is deleted only while it still
//     points at the base; anything kept is listed, with why, by
//     `observer workspaces ls` and named in the daemon log.
//
// Every host git step runs through the existing exec seams (runGitStep for
// the add, runReturnGit for the rest), hardened: the flags of
// workspace.WorktreeHostGitArgs (no fsmonitor, no hooks, no file transport)
// and the extrun git hardening environment (workspace.Step.Hardened,
// hardenedGitEnv); the status runs with --ignore-submodules=all
// (SBX-WORKTREE-SOURCE audit findings 1 and 6).

// sandboxWorktreeDirName is the observer-dir directory holding one record
// per worktree run (<id>.json). The observer dir is a tmpfs inside every
// box (the capture relay), so a box never sees or writes these records.
const sandboxWorktreeDirName = "sandbox-worktrees"

// The record states.
const (
	// sandboxWorktreePreparing: written before `git worktree add`.
	sandboxWorktreePreparing = "preparing"
	// sandboxWorktreeAttached: the box was composed; the run's relay
	// record existed first, so its absence means the run ended.
	sandboxWorktreeAttached = "attached"
	// sandboxWorktreeKept: the run ended and something was kept for the
	// user (the worktree, or a branch holding the run's commits).
	sandboxWorktreeKept = "kept"
)

// sandboxWorktreeRecord is one worktree run as the host prepared it.
type sandboxWorktreeRecord struct {
	V            int    `json:"v"`
	RunID        string `json:"run_id"`
	MainRoot     string `json:"main_root"`
	CommonDir    string `json:"common_dir"`
	WorkspaceDir string `json:"workspace_dir"`
	Branch       string `json:"branch"`
	Base         string `json:"base"`
	// AdminDir is the worktree's own git dir (<common>/worktrees/<name>),
	// recorded at attach; the end of the run removes exactly this
	// registration when git leaves it behind.
	AdminDir string `json:"admin_dir,omitempty"`
	// CommonExecSnapshot is a fingerprint of the common dir's git execution
	// -risk paths (internal/workspace.ScanGitDirExecRisk) taken at attach.
	// The end of the run compares the common dir against it and warns the
	// developer if any such path changed, even though the box mounts the
	// common dir read-only and so should not be able to change one (belt and
	// braces, live Mac D1, ledger SBX-BE-21). Absent on a record written
	// before this field existed; the end then skips the comparison.
	CommonExecSnapshot map[string]string `json:"common_exec_snapshot,omitempty"`
	State              string            `json:"state"`
	Reason             string            `json:"reason,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	EndedAt            time.Time         `json:"ended_at,omitzero"`
}

// sandboxWorktreeRecordVersion is the record's version.
const sandboxWorktreeRecordVersion = 1

// sandboxWorktreeEndPoll is how often a run's watcher checks whether the
// run ended.
var sandboxWorktreeEndPoll = 5 * time.Second

// sandboxWorktreePrepGrace is how old a record still "preparing" must be,
// with no live run, before the sweep finishes it (a launch in another
// process may still be between its add and its attach).
const sandboxWorktreePrepGrace = 15 * time.Minute

// sandboxWorktreeClaimStale is how old a claim must be before the sweep
// takes it over (a process that crashed while ending the run).
const sandboxWorktreeClaimStale = 10 * time.Minute

// sandboxWorktreeMu serializes this process's sweeps; claims serialize
// them across processes.
var sandboxWorktreeMu sync.Mutex

// sandboxWorktreeOrgPinned reports whether an org pin decides
// allow_worktree_source on this node (the restrictive-only pin of
// internal/config/governance.go, safe value false). A seam for tests.
var sandboxWorktreeOrgPinned = func() bool { return sandboxWorktreeOrgPinCheck(daemonConfigPath()) }

// sandboxWorktreeOrgPinCheck is the real pin check over the config at
// configPath and its governance overlay.
func sandboxWorktreeOrgPinCheck(configPath string) bool {
	_, gout, err := config.LoadGovernance(config.LoadOptions{GlobalPath: configPath})
	return err == nil && gout.Governed() && slices.Contains(gout.Applied, sandboxPinPrefix+"allow_worktree_source")
}

// worktreeOrgPinned is sandboxWorktreeOrgPinned read once per runtime. A
// runtime is rebuilt on every config or managed-body change (the picker's
// refresh cycle), so a picker refresh while the setting is off no longer
// loads the governance overlay on every call (SBX-WORKTREE-SOURCE audit
// finding 6).
func (r *sandboxRuntime) worktreeOrgPinned() bool {
	r.worktreePinOnce.Do(func() { r.worktreePinned = sandboxWorktreeOrgPinned() })
	return r.worktreePinned
}

// The availability reasons the New Terminal picker shows.
const (
	worktreeReasonOrg = "Your organization keeps the worktree source off on this node (an org pin on allow_worktree_source)."
	worktreeReasonOff = "Off. Turn on \"Allow git worktree source\" in Terminals > Settings > Sandbox isolation: it mounts the main repository's .git folder writable inside the box."
)

// worktreeSourceAvail is the worktree row of the source list
// (sandboxRuntime.sources).
func (r *sandboxRuntime) worktreeSourceAvail() dashapi.SandboxSourceAvail {
	out := dashapi.SandboxSourceAvail{ID: string(workspace.SourceWorktree)}
	switch {
	case !r.cfg.AllowWorktreeSource && r.worktreeOrgPinned():
		out.Reason = worktreeReasonOrg
	case !r.cfg.AllowWorktreeSource:
		out.Reason = worktreeReasonOff
	case r.worktreeDriverBlock() != "":
		out.Reason = worktreeDriverReason(r.worktreeDriverBlock())
	default:
		out.Available = true
	}
	return out
}

// worktreeDriverBlock names the first enabled backend whose driver is
// active on this node, or "" when every launch takes the bwrap path.
func (r *sandboxRuntime) worktreeDriverBlock() string {
	switch r.forceBackend {
	case "":
	case sandboxbackend.BackendBwrap:
		return "" // the CLI named bwrap: never substituted (I1)
	default:
		return r.forceBackend
	}
	for _, id := range sandboxEnabledBackends(r.cfg) {
		if _, ok := r.drivers[id]; ok {
			return id
		}
	}
	return ""
}

// worktreeDriverReason is the refusal while a driver other than bwrap is
// enabled.
func worktreeDriverReason(id string) string {
	return "The worktree source runs only on the bwrap backend; this node enables " + id +
		", which cannot mount the main repository's .git folder into its box yet."
}

// worktreeBeforeAdd runs before a worktree workspace is planned: it
// refuses a node whose launches may take another driver and a main
// repository whose layout the box cannot be held to, finishes ended
// worktree runs, reads the base commit and writes the run's record. It
// returns the base, which pins `git worktree add`'s start point.
func (r *sandboxRuntime) worktreeBeforeAdd(ctx context.Context, req termsvc.PrepareRequest, id string) (string, error) {
	if !r.cfg.AllowWorktreeSource {
		return "", nil // workspace.Plan refuses it with its own reason
	}
	if d := r.worktreeDriverBlock(); d != "" {
		return "", fmt.Errorf("terminal_sandbox: %s", worktreeDriverReason(d))
	}
	sweepSandboxWorktrees(ctx, r.observerDir, r.managedRoot, r.now(), r.logger)
	branch, err := workspace.WorktreeBranch(id, req.WorkspaceBranch)
	if err != nil {
		return "", err
	}
	root, main, common, err := sandboxWorktreeMainLayout(req.ProjectRoot)
	if err != nil {
		return "", err
	}
	if err := r.worktreeWriteRootRefusal(common, r.cfg.ExtraRWBinds); err != nil {
		return "", err
	}
	out, err := runReturnGit(ctx, sandboxWorktreeGitStep(root, "rev-parse", "--verify", "--quiet", "HEAD^{commit}"))
	if err != nil {
		return "", fmt.Errorf("terminal_sandbox: the worktree source needs a repository with at least one commit: %w", err)
	}
	base := strings.TrimSpace(string(out))
	rec := sandboxWorktreeRecord{
		V: sandboxWorktreeRecordVersion, RunID: id, MainRoot: main, CommonDir: common,
		WorkspaceDir: filepath.Join(r.managedRoot, id, filepath.Base(req.ProjectRoot)),
		Branch:       branch, Base: base, State: sandboxWorktreePreparing, CreatedAt: r.now(),
	}
	if err := writeSandboxWorktreeRecord(r.observerDir, rec); err != nil {
		return "", err
	}
	return base, nil
}

// sandboxWorktreeGitStep is one hardened host git step in dir: the
// worktree source's flags (workspace.WorktreeHostGitArgs) and, through
// Step.Hardened, the extrun git hardening environment.
func sandboxWorktreeGitStep(dir string, args ...string) workspace.Step {
	argv := append(append([]string{"git", "-C", dir}, workspace.WorktreeHostGitArgs()...), args...)
	return workspace.Step{Argv: argv, Hardened: true}
}

// worktreeWriteRootRefusal refuses the worktree source when a write root
// of the launch (a user, org or extra write bind, a tool's state dir)
// covers the main repository's git common dir: equals it, is an ancestor
// of it, or lies inside it. The extra binds are mounted after the common
// dir's read-only bind, so such a bind makes the whole .git folder (refs,
// packed-refs, HEAD, modules) writable in the box again
// (SBX-WORKTREE-SOURCE audit finding 2). The refusal names the bind.
func (r *sandboxRuntime) worktreeWriteRootRefusal(common string, roots []string) error {
	common = filepath.Clean(common)
	for _, root := range roots {
		if strings.TrimSpace(root) == "" {
			continue
		}
		res := filepath.Clean(root)
		if rr, err := filepath.EvalSymlinks(res); err == nil {
			res = rr
		}
		if !isWithinPath(common, res) && !isWithinPath(res, common) {
			continue
		}
		remedy := "; remove the write bind or choose another workspace source"
		if slices.Contains(r.orgRWBinds, root) {
			remedy = remedyOrgWriteBind
		}
		return fmt.Errorf("terminal_sandbox: the write bind %s covers the main repository's git directory %s and would make all of it writable inside the box, so the worktree source is refused%s", root, common, remedy)
	}
	return nil
}

// sandboxWorktreeMainLayout resolves the repository at projectRoot (root,
// symlinks resolved) to its main top level (main, where the end of the run
// runs git) and its git common dir, refusing anything the box
// could not be held to: a project root that is not a repository's top
// level, a symlinked .git, common dir, object store, refs or worktrees
// directory, and a reftable repository (no loose ref directory to bind).
func sandboxWorktreeMainLayout(projectRoot string) (root, main, common string, err error) {
	root, err = filepath.EvalSymlinks(projectRoot)
	if err != nil {
		return "", "", "", fmt.Errorf("terminal_sandbox: resolve the project root: %w", err)
	}
	dotGit := filepath.Join(root, ".git")
	fi, err := os.Lstat(dotGit)
	switch {
	case err != nil:
		return "", "", "", fmt.Errorf("terminal_sandbox: the worktree source needs the project root to be a git repository's top level (%s: %w)", dotGit, err)
	case fi.Mode()&os.ModeSymlink != 0:
		return "", "", "", fmt.Errorf("terminal_sandbox: %s is a symlink; the worktree source refuses a symlinked git directory (the box's binds would follow it)", dotGit)
	case fi.IsDir():
		common = dotGit
	default:
		// The project root is itself a linked worktree: its common dir.
		gd, ok := readSandboxGitFile(dotGit)
		if !ok {
			return "", "", "", fmt.Errorf("terminal_sandbox: %s is not a linked worktree's .git file; the worktree source refuses it", dotGit)
		}
		c, cerr := os.ReadFile(filepath.Join(gd, "commondir")) //nolint:gosec // G304: a path read from the repository's own .git file, inspected before any box runs
		if cerr != nil {
			return "", "", "", fmt.Errorf("terminal_sandbox: read the worktree's commondir: %w", cerr)
		}
		common = strings.TrimSpace(string(c))
		if !filepath.IsAbs(common) {
			common = filepath.Join(gd, common)
		}
		common = filepath.Clean(common)
	}
	for _, p := range []string{common, filepath.Join(common, "objects"), filepath.Join(common, "refs"), filepath.Join(common, "worktrees")} {
		pfi, perr := os.Lstat(p) //nolint:gosec // G703: the repository's own git dirs, inspected before any box runs
		if perr != nil {
			if errors.Is(perr, fs.ErrNotExist) && p == filepath.Join(common, "worktrees") {
				continue // git creates it on the first worktree
			}
			return "", "", "", fmt.Errorf("terminal_sandbox: the worktree source cannot read %s: %w", p, perr)
		}
		if pfi.Mode()&os.ModeSymlink != 0 || !pfi.IsDir() {
			return "", "", "", fmt.Errorf("terminal_sandbox: %s is a symlink or not a directory; the worktree source refuses a symlinked git common dir", p)
		}
	}
	if resolved, rerr := filepath.EvalSymlinks(common); rerr != nil || resolved != common {
		return "", "", "", fmt.Errorf("terminal_sandbox: the git common dir %s resolves through a symlink; the worktree source refuses it", common)
	}
	if _, rerr := os.Lstat(filepath.Join(common, "reftable")); rerr == nil { //nolint:gosec // G703: the repository's own git dir
		return "", "", "", fmt.Errorf("terminal_sandbox: %s keeps its refs in reftable; the worktree source needs loose refs (it binds only the run's own ref directory writable)", root)
	}
	main = root
	if m, ok := git.FindRoot(root); ok {
		main = m
	}
	return root, main, common, nil
}

// readSandboxGitFile reads the gitdir of a .git file: absolute, no "..".
func readSandboxGitFile(path string) (string, bool) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the repository's own .git file, inspected before any box runs
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(b), "\n") {
		v, ok := strings.CutPrefix(line, "gitdir:")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if !filepath.IsAbs(v) || slices.Contains(strings.Split(filepath.ToSlash(v), "/"), "..") {
			return "", false
		}
		return filepath.Clean(v), true
	}
	return "", false
}

// sandboxWorktreeBinds is what a worktree run adds to its box.
type sandboxWorktreeBinds struct {
	ro, rw   []string
	overlays []sandbox.Overlay
}

// worktreeBox composes a worktree run's binds at attach, from its record
// and the filesystem as git left it (the box has not started). rw are the
// launch's other writable roots. A run with no worktree record is not a
// worktree run and gets nothing.
func (r *sandboxRuntime) worktreeBox(runID, workspaceRoot string, rw []string) (sandboxWorktreeBinds, error) {
	rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(r.observerDir, runID))
	if errors.Is(err, fs.ErrNotExist) {
		return sandboxWorktreeBinds{}, nil
	}
	if err != nil {
		return sandboxWorktreeBinds{}, err
	}
	if filepath.Clean(rec.WorkspaceDir) != filepath.Clean(workspaceRoot) {
		return sandboxWorktreeBinds{}, fmt.Errorf("terminal_sandbox: the worktree record names %s, not the run's workspace %s", rec.WorkspaceDir, workspaceRoot)
	}
	layout, err := sandboxWorktreeLayout(rec)
	if err != nil {
		return sandboxWorktreeBinds{}, err
	}
	if err := r.worktreeWriteRootRefusal(layout.CommonDir, rw); err != nil {
		return sandboxWorktreeBinds{}, err
	}
	box, err := workspace.PlanWorktreeBox(layout)
	if err != nil {
		return sandboxWorktreeBinds{}, fmt.Errorf("terminal_sandbox: %w", err)
	}
	// Every write hole is its own path, no symlink anywhere on the way: a
	// link planted at the run's ref or reflog dir (an earlier live-source
	// box could) would move the writable bind elsewhere
	// (SBX-WORKTREE-SOURCE audit finding 5).
	for _, p := range box.ReadWrite {
		if res, err := filepath.EvalSymlinks(p); err != nil || res != p {
			return sandboxWorktreeBinds{}, fmt.Errorf("terminal_sandbox: the worktree's writable path %s is missing or resolves through a symlink; the worktree source refuses it", p)
		}
	}
	out := sandboxWorktreeBinds{ro: box.ReadOnly, rw: box.ReadWrite}
	roots := append(slices.Clip(rw), box.ReadWrite...)
	seen := map[string]bool{}
	for _, p := range box.Protect {
		o, ok, err := protectPath(protectedRow{path: p.Path, kind: sandbox.OverlayReadOnly, dir: p.Dir}, roots)
		if err != nil {
			return sandboxWorktreeBinds{}, err
		}
		if ok && o.Path != "" && !seen[o.Path] {
			seen[o.Path] = true
			out.overlays = append(out.overlays, o)
		}
	}
	rec.State = sandboxWorktreeAttached
	rec.AdminDir = layout.AdminDir
	// A best-effort launch-time fingerprint of the common dir's execution
	// -risk paths; the end of the run warns if any changed (belt and braces).
	// A scan error leaves it nil and the end skips the comparison, never a
	// false warning.
	if snap, serr := workspace.ScanGitDirExecRisk(rec.CommonDir); serr == nil {
		rec.CommonExecSnapshot = snap
	}
	if err := writeSandboxWorktreeRecord(r.observerDir, rec); err != nil {
		return sandboxWorktreeBinds{}, err
	}
	rewriteSandboxWorktreeMeta(filepath.Dir(rec.WorkspaceDir), rec.Branch)
	r.watchWorktreeRun(runID)
	return out, nil
}

// sandboxWorktreeLayout reads a prepared worktree's layout and checks it
// is git's own: the workspace's .git file names a git dir under the
// record's common dir, whose commondir and back pointer agree, with no
// symlink on the way.
func sandboxWorktreeLayout(rec sandboxWorktreeRecord) (workspace.WorktreeLayout, error) {
	ws := filepath.Clean(rec.WorkspaceDir)
	gitFile := filepath.Join(ws, ".git")
	if fi, err := os.Lstat(gitFile); err != nil || !fi.Mode().IsRegular() {
		return workspace.WorktreeLayout{}, fmt.Errorf("terminal_sandbox: %s is not the .git file git worktree add writes", gitFile)
	}
	admin, ok := readSandboxGitFile(gitFile)
	if !ok {
		return workspace.WorktreeLayout{}, fmt.Errorf("terminal_sandbox: %s names no usable git dir", gitFile)
	}
	common := filepath.Clean(rec.CommonDir)
	if filepath.Dir(admin) != filepath.Join(common, "worktrees") {
		return workspace.WorktreeLayout{}, fmt.Errorf("terminal_sandbox: the worktree's git dir %s is not under %s", admin, filepath.Join(common, "worktrees"))
	}
	for _, p := range []string{common, filepath.Join(common, "objects"), filepath.Join(common, "worktrees"), admin} {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
			return workspace.WorktreeLayout{}, fmt.Errorf("terminal_sandbox: %s is missing, a symlink or not a directory; the worktree source refuses it", p)
		}
	}
	back, err := os.ReadFile(filepath.Join(admin, "gitdir")) //nolint:gosec // G304: the worktree's own git dir, read before the box starts
	if err != nil || filepath.Clean(strings.TrimSpace(string(back))) != gitFile {
		return workspace.WorktreeLayout{}, fmt.Errorf("terminal_sandbox: the worktree git dir %s does not point back at %s", admin, gitFile)
	}
	l := workspace.WorktreeLayout{WorkspaceDir: ws, CommonDir: common, AdminDir: admin, Branch: rec.Branch}
	if entries, err := os.ReadDir(filepath.Join(common, "worktrees")); err == nil {
		for _, e := range entries {
			if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
				l.OtherAdmins = append(l.OtherAdmins, filepath.Join(common, "worktrees", e.Name()))
			}
		}
	}
	refDir := filepath.Join(common, workspace.WorktreeRunRefDir(rec.Branch))
	logDir := filepath.Join(common, "logs", workspace.WorktreeRunRefDir(rec.Branch))
	for _, p := range []string{refDir, logDir} {
		if fi, err := os.Lstat(p); err == nil && (fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir()) {
			return workspace.WorktreeLayout{}, fmt.Errorf("terminal_sandbox: %s is a symlink or not a directory; the worktree source refuses it", p)
		}
	}
	l.RefDirExists = isRealDir(refDir)
	l.LogDirExists = isRealDir(logDir)
	return l, nil
}

// isRealDir reports whether p is a directory and not a symlink.
func isRealDir(p string) bool {
	fi, err := os.Lstat(p) //nolint:gosec // G703: a metadata read; the callers pass the run's own workspace paths
	return err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0
}

// rewriteSandboxWorktreeMeta records the run's real branch in the managed
// workspace's meta.json (written with the requested label), so
// `observer workspaces ls` lists the branch a kept run left.
func rewriteSandboxWorktreeMeta(runDir, branch string) {
	updateSandboxWorktreeMeta(runDir, func(m *workspace.Meta) bool {
		if m.Branch == branch {
			return false
		}
		m.Branch = branch
		return true
	})
}

// markSandboxWorktreeMetaKept records in the managed workspace's meta.json
// why the end of the run kept it, so `observer workspaces ls` says why.
func markSandboxWorktreeMetaKept(runDir, reason string) {
	updateSandboxWorktreeMeta(runDir, func(m *workspace.Meta) bool {
		if m.Kept == reason {
			return false
		}
		m.Kept = reason
		return true
	})
}

// updateSandboxWorktreeMeta applies mut to runDir's meta.json and writes it
// back when mut reports a change; a missing or unreadable file is left.
func updateSandboxWorktreeMeta(runDir string, mut func(*workspace.Meta) bool) {
	path := filepath.Join(runDir, "meta.json")
	b, err := os.ReadFile(path) //nolint:gosec // G304: the managed workspace's own meta.json, outside every box
	if err != nil {
		return
	}
	var m workspace.Meta
	if json.Unmarshal(b, &m) != nil || !mut(&m) {
		return
	}
	if data, err := workspace.MarshalMeta(m); err == nil {
		_ = os.WriteFile(path, data, 0o600) //nolint:gosec // G703: the managed workspace's own meta.json
	}
}

// watchWorktreeRun ends a worktree run once its relay record is gone (the
// host helper removes it when the run ends; the relay's sweep removes the
// record of a helper that died). A process that exits first leaves the
// run to the next sweep.
func (r *sandboxRuntime) watchWorktreeRun(runID string) {
	observerDir, managedRoot, logger := r.observerDir, r.managedRoot, r.logger
	go func() {
		t := time.NewTicker(sandboxWorktreeEndPoll)
		defer t.Stop()
		for range t.C {
			_, _ = sandboxrelayd.PruneDeadRuns(observerDir)
			if sandboxWorktreeRunLive(observerDir, runID) {
				continue
			}
			sweepSandboxWorktrees(context.Background(), observerDir, managedRoot, time.Now().UTC(), logger)
			return
		}
	}()
}

// sandboxWorktreeRunLive reports whether runID's relay record is present
// (an unreadable record counts as present: never end a run on doubt).
func sandboxWorktreeRunLive(observerDir, runID string) bool {
	_, err := sandboxrelayd.ReadRun(observerDir, runID)
	return !errors.Is(err, sandboxrelayd.ErrNoRecord)
}

// sweepSandboxWorktrees finishes every worktree run that has ended: an
// attached run whose relay record is gone, a run still preparing past the
// grace, a claim a crashed process left; and forgets a kept run whose
// managed workspace the user removed (pruning its registration, never
// deleting its branch). It never returns an error: each run that cannot
// be finished is logged and retried at the next sweep.
func sweepSandboxWorktrees(ctx context.Context, observerDir, managedRoot string, now time.Time, logger *slog.Logger) {
	sandboxWorktreeMu.Lock()
	defer sandboxWorktreeMu.Unlock()
	dir := filepath.Join(observerDir, sandboxWorktreeDirName)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	_, _ = sandboxrelayd.PruneDeadRuns(observerDir)
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() {
			continue
		}
		var id string
		var claimed bool
		switch {
		case strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".ending"):
			id, claimed = strings.TrimSuffix(strings.TrimPrefix(name, "."), ".ending"), true
		case strings.HasSuffix(name, ".json"):
			id = strings.TrimSuffix(name, ".json")
		default:
			continue
		}
		if !validSandboxWorktreeID(id) {
			continue
		}
		path := filepath.Join(dir, name)
		if claimed {
			fi, err := e.Info()
			if err != nil || now.Sub(fi.ModTime()) < sandboxWorktreeClaimStale {
				continue
			}
		} else {
			rec, err := readSandboxWorktreeRecord(path)
			if err != nil || !sandboxWorktreeEnded(observerDir, managedRoot, rec, now) {
				continue
			}
		}
		claim := filepath.Join(dir, "."+id+".ending")
		if path != claim {
			if err := os.Rename(path, claim); err != nil {
				continue // another process took it
			}
		} else if err := os.Chtimes(claim, now, now); err != nil {
			continue
		}
		rec, err := readSandboxWorktreeRecord(claim)
		if err != nil {
			continue
		}
		rec = endSandboxWorktree(ctx, rec, managedRoot, now)
		if rec.State == "" {
			_ = os.Remove(claim)
			sandboxWorktreeLog(logger).Info("sandbox worktree: run ended and was cleaned up", "run", rec.RunID)
			continue
		}
		if err := writeSandboxWorktreeRecord(observerDir, rec); err == nil {
			_ = os.Remove(claim)
		}
		sandboxWorktreeLog(logger).Warn("sandbox worktree: run ended; kept for you (observer workspaces ls)", "run", rec.RunID, "branch", rec.Branch, "workspace", rec.WorkspaceDir, "reason", rec.Reason)
	}
}

// sandboxWorktreeEnded reports whether rec's run has ended and still needs
// its end: an attached run with no relay record, a preparing run past the
// grace with none, and a kept run whose managed workspace is gone.
func sandboxWorktreeEnded(observerDir, managedRoot string, rec sandboxWorktreeRecord, now time.Time) bool {
	switch rec.State {
	case sandboxWorktreeKept:
		_, err := os.Lstat(filepath.Join(managedRoot, rec.RunID))
		return errors.Is(err, fs.ErrNotExist)
	case sandboxWorktreeAttached:
		return !sandboxWorktreeRunLive(observerDir, rec.RunID)
	case sandboxWorktreePreparing:
		return now.Sub(rec.CreatedAt) >= sandboxWorktreePrepGrace && !sandboxWorktreeRunLive(observerDir, rec.RunID)
	}
	return false
}

// warnWorktreeExecRiskChange warns the developer, at the end of a worktree
// run, if any git-dir execution-risk path in the main repository's common dir
// changed from the launch-time snapshot (sandboxWorktreeRecord.CommonExecSnapshot).
// The box mounts the common dir read-only, so this should never fire; it is
// the belt-and-braces check item 3 of the D1 fix asks for on a live workspace,
// naming the file so the developer reviews it before running git there. No
// snapshot (an older record or a failed launch scan) means no comparison.
func warnWorktreeExecRiskChange(rec sandboxWorktreeRecord) {
	if rec.CommonExecSnapshot == nil {
		return
	}
	after, err := workspace.ScanGitDirExecRisk(rec.CommonDir)
	if err != nil {
		return
	}
	changed := workspace.GitDirExecRiskChanged(rec.CommonExecSnapshot, after)
	if len(changed) == 0 {
		return
	}
	sandboxWorktreeLog(nil).Warn("sandbox worktree: a git-dir execution-risk path changed during the run; review it before running git in this repository",
		"run", rec.RunID, "common_dir", rec.CommonDir, "paths", strings.Join(changed, ", "))
}

// endSandboxWorktree ends one run: it reads the facts from the main
// repository, walks the end-of-run table and runs its steps. The returned
// record has State "" when nothing is left to keep, else State kept with
// the reason.
func endSandboxWorktree(ctx context.Context, rec sandboxWorktreeRecord, managedRoot string, now time.Time) sandboxWorktreeRecord {
	runDir := filepath.Join(managedRoot, rec.RunID)
	warnWorktreeExecRiskChange(rec)
	keep := func(reason string) sandboxWorktreeRecord {
		rec.State, rec.Reason, rec.EndedAt = sandboxWorktreeKept, reason, now
		markSandboxWorktreeMetaKept(runDir, reason)
		return rec
	}
	if rec.State == sandboxWorktreeKept {
		// The user removed the kept workspace: remove this run's own
		// registration and forget it. The branch is never deleted here.
		if err := pruneSandboxWorktreeAdmin(rec); err != nil {
			return keep(rec.Reason)
		}
		rec.State = ""
		return rec
	}
	facts := sandboxWorktreeEndFacts(ctx, rec)
	d := workspace.DecideWorktreeEnd(facts)
	steps, err := workspace.PlanWorktreeEnd(workspace.WorktreeEndRequest{MainRoot: rec.MainRoot, WorkspaceDir: rec.WorkspaceDir, Branch: rec.Branch, Base: rec.Base}, d)
	if err != nil {
		return keep("could not plan the end of the run: " + err.Error())
	}
	for _, s := range steps {
		if _, err := runReturnGit(ctx, s); err != nil {
			return keep("git refused a cleanup step, so everything is kept: " + err.Error())
		}
	}
	if d.Action == workspace.WorktreeEndKeep {
		return keep(d.Reason)
	}
	// The worktree is gone (removed above, or already): this run's own
	// registration goes too when git left it, and never another
	// worktree's (SBX-WORKTREE-SOURCE audit finding 6).
	if err := pruneSandboxWorktreeAdmin(rec); err != nil {
		return keep("the run's worktree registration could not be removed, so it is kept: " + err.Error())
	}
	if facts.BranchTip == "" || d.DeleteBranch {
		// Nothing of the run is left: the managed run dir goes too.
		if workspace.ValidateManagedWorkspace(runDir, managedRoot) == nil {
			_ = os.RemoveAll(runDir) //nolint:gosec // G703: <managedRoot>/<id>, checked strictly under the managed root
		}
		rec.State = ""
		return rec
	}
	// The branch holds the run's commits: the run dir's meta.json stays, so
	// `observer workspaces ls` lists the branch.
	return keep(d.Reason + " (branch " + rec.Branch + ")")
}

// pruneSandboxWorktreeAdmin removes this run's own worktree registration
// (<common>/worktrees/<name>) once the run's worktree directory is gone:
// the one entry `git worktree prune` would remove for this run, and never
// another worktree's (SBX-WORKTREE-SOURCE audit finding 6). The admin dir
// is the one the record names, else the one whose gitdir file points at
// the run's worktree; it must be a real directory directly under the
// common dir's worktrees folder, and a locked one is left (as git would).
// Nothing left to remove is not an error. No git command runs.
func pruneSandboxWorktreeAdmin(rec sandboxWorktreeRecord) error {
	ws := filepath.Clean(rec.WorkspaceDir)
	if _, err := os.Lstat(ws); err == nil {
		return fmt.Errorf("the worktree directory %s still exists", ws)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	worktrees := filepath.Join(filepath.Clean(rec.CommonDir), "worktrees")
	var candidates []string
	if rec.AdminDir != "" {
		candidates = []string{filepath.Clean(rec.AdminDir)}
	} else if entries, err := os.ReadDir(worktrees); err == nil {
		for _, e := range entries {
			candidates = append(candidates, filepath.Join(worktrees, e.Name()))
		}
	}
	want := filepath.Join(ws, ".git")
	for _, admin := range candidates {
		if filepath.Dir(admin) != worktrees || !isRealDir(admin) {
			continue
		}
		back, err := os.ReadFile(filepath.Join(admin, "gitdir")) //nolint:gosec // G304: the run's own worktree registration, read on the host after the run
		if err != nil || filepath.Clean(strings.TrimSpace(string(back))) != want {
			continue
		}
		if _, err := os.Lstat(filepath.Join(admin, "locked")); err == nil {
			return fmt.Errorf("the worktree registration %s is locked", admin)
		}
		if err := os.RemoveAll(admin); err != nil { //nolint:gosec // G703: <common>/worktrees/<name>, checked to point back at this run's worktree
			return fmt.Errorf("remove the worktree registration %s: %w", admin, err)
		}
	}
	return nil
}

// sandboxWorktreeNestedScanCap bounds the walk of a run's worktree for a
// nested .git; a tree past it is kept (unchecked counts as nested).
const sandboxWorktreeNestedScanCap = 500000

// errSandboxWorktreeScanCap stops the nested-repository walk at the cap.
var errSandboxWorktreeScanCap = errors.New("scan cap")

// sandboxWorktreeNestedRepo says why the run's worktree holds another
// repository, or "" when it holds none, before any git command runs in the
// worktree: its git dir has a modules folder, its tree has a .git anywhere
// below the top level, or its index has a gitlink. The first two are read
// from the filesystem (never following a symlink); the index is read by a
// hardened `git ls-files`, which runs no filter and enters no submodule.
// A host git status or worktree remove over such a worktree would run git
// inside a repository whose config the box wrote (a clean filter is a
// command), so it is kept and never cleaned (SBX-WORKTREE-SOURCE audit
// finding 1). Anything that cannot be checked counts as nested.
func sandboxWorktreeNestedRepo(ctx context.Context, rec sandboxWorktreeRecord) string {
	ws := filepath.Clean(rec.WorkspaceDir)
	topGit := filepath.Join(ws, ".git")
	admin := rec.AdminDir
	if admin == "" {
		if gd, ok := readSandboxGitFile(topGit); ok {
			admin = gd
		}
	}
	if admin == "" || filepath.Dir(filepath.Clean(admin)) != filepath.Join(filepath.Clean(rec.CommonDir), "worktrees") {
		return "its git dir could not be found"
	}
	if _, err := os.Lstat(filepath.Join(admin, "modules")); !errors.Is(err, fs.ErrNotExist) {
		return "its git dir " + admin + " holds a modules folder"
	}
	n := 0
	var found string
	walkErr := filepath.WalkDir(ws, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if n++; n > sandboxWorktreeNestedScanCap {
			return errSandboxWorktreeScanCap
		}
		switch {
		case p == topGit:
			if d.IsDir() {
				return fs.SkipDir
			}
		case d.Name() == ".git":
			found = p
			return fs.SkipAll
		}
		return nil
	})
	switch {
	case found != "":
		rel, err := filepath.Rel(ws, found)
		if err != nil {
			rel = found
		}
		return "a nested .git at " + filepath.ToSlash(rel)
	case errors.Is(walkErr, errSandboxWorktreeScanCap):
		return fmt.Sprintf("more than %d entries, too many to check for a nested .git", sandboxWorktreeNestedScanCap)
	case walkErr != nil:
		return "its tree could not be read: " + walkErr.Error()
	}
	out, err := runReturnGit(ctx, sandboxWorktreeGitStep(ws, "ls-files", "--stage", "-z"))
	if err != nil {
		return "its index could not be read"
	}
	for _, e := range bytes.Split(out, []byte{0}) {
		if !bytes.HasPrefix(e, []byte("160000 ")) {
			continue
		}
		path := e
		if i := bytes.IndexByte(e, '\t'); i >= 0 {
			path = e[i+1:]
		}
		return "a gitlink (submodule) in its index at " + string(path)
	}
	return ""
}

// sandboxWorktreeEndFacts reads the end-of-run facts from the main
// repository: whether it lists the worktree, on which branch and whether
// locked, the branch tip and, for a worktree that may be removed, whether
// it holds another repository (sandboxWorktreeNestedRepo, checked before
// any git command runs in it) and whether it is clean. Every git command
// is hardened, and the status ignores submodules. A read that fails counts
// against removal.
func sandboxWorktreeEndFacts(ctx context.Context, rec sandboxWorktreeRecord) workspace.WorktreeEndFacts {
	f := workspace.WorktreeEndFacts{Base: rec.Base, DirExists: isRealDir(rec.WorkspaceDir)}
	git := func(dir string, args ...string) ([]byte, error) {
		return runReturnGit(ctx, sandboxWorktreeGitStep(dir, args...))
	}
	if out, err := git(rec.MainRoot, "rev-parse", "--verify", "--quiet", "refs/heads/"+rec.Branch); err == nil {
		f.BranchTip = strings.TrimSpace(string(out))
	}
	out, err := git(rec.MainRoot, "worktree", "list", "--porcelain")
	if err != nil {
		f.Registered, f.Locked = true, true // unknown: keep
		return f
	}
	if e, ok := findSandboxWorktreeEntry(out, rec.WorkspaceDir); ok {
		f.Registered = true
		f.OnBranch = e.branch == "refs/heads/"+rec.Branch
		f.Locked = e.locked
	}
	if f.DirExists && f.Registered && f.OnBranch && !f.Locked {
		if f.NestedRepo = sandboxWorktreeNestedRepo(ctx, rec); f.NestedRepo != "" {
			return f
		}
		st, err := git(rec.WorkspaceDir, "status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=all")
		f.Dirty = err != nil || len(bytes.TrimSpace(st)) > 0
	}
	return f
}

// sandboxWorktreeEntry is one `git worktree list --porcelain` entry.
type sandboxWorktreeEntry struct {
	path, branch string
	locked       bool
}

// findSandboxWorktreeEntry finds the entry for dir in porcelain output.
func findSandboxWorktreeEntry(out []byte, dir string) (sandboxWorktreeEntry, bool) {
	want := filepath.Clean(dir)
	if r, err := filepath.EvalSymlinks(want); err == nil {
		want = r
	}
	var cur sandboxWorktreeEntry
	var found *sandboxWorktreeEntry
	flush := func() {
		if cur.path == "" || found != nil {
			return
		}
		p := filepath.Clean(cur.path)
		if r, err := filepath.EvalSymlinks(p); err == nil {
			p = r
		}
		if p == want {
			e := cur
			found = &e
		}
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			flush()
			cur = sandboxWorktreeEntry{}
		case strings.HasPrefix(line, "worktree "):
			cur.path = strings.TrimPrefix(line, "worktree ")
		case strings.HasPrefix(line, "branch "):
			cur.branch = strings.TrimPrefix(line, "branch ")
		case line == "locked" || strings.HasPrefix(line, "locked "):
			cur.locked = true
		}
	}
	flush()
	if found == nil {
		return sandboxWorktreeEntry{}, false
	}
	return *found, true
}

// validSandboxWorktreeID reports whether id is a clean managed-workspace id.
func validSandboxWorktreeID(id string) bool {
	_, err := workspace.WorktreeBranch(id, "")
	return err == nil
}

// sandboxWorktreeRecordPath is runID's record.
func sandboxWorktreeRecordPath(observerDir, runID string) string {
	return filepath.Join(observerDir, sandboxWorktreeDirName, runID+".json")
}

// readSandboxWorktreeRecord reads one record; a missing file reports
// fs.ErrNotExist.
func readSandboxWorktreeRecord(path string) (sandboxWorktreeRecord, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the observer dir's own worktree records
	if err != nil {
		return sandboxWorktreeRecord{}, err
	}
	var rec sandboxWorktreeRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return sandboxWorktreeRecord{}, fmt.Errorf("terminal_sandbox: worktree record %s: %w", path, err)
	}
	if rec.V != sandboxWorktreeRecordVersion || !validSandboxWorktreeID(rec.RunID) || !filepath.IsAbs(rec.MainRoot) || !filepath.IsAbs(rec.CommonDir) || !filepath.IsAbs(rec.WorkspaceDir) {
		return sandboxWorktreeRecord{}, fmt.Errorf("terminal_sandbox: worktree record %s is not valid", path)
	}
	return rec, nil
}

// writeSandboxWorktreeRecord replaces rec's record whole (a fresh 0600
// file renamed over it).
func writeSandboxWorktreeRecord(observerDir string, rec sandboxWorktreeRecord) error {
	dir := filepath.Join(observerDir, sandboxWorktreeDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("terminal_sandbox: worktree records: %w", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("terminal_sandbox: worktree record: %w", err)
	}
	tmp := filepath.Join(dir, "."+rec.RunID+".tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("terminal_sandbox: worktree record: %w", err)
	}
	if err := os.Rename(tmp, sandboxWorktreeRecordPath(observerDir, rec.RunID)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("terminal_sandbox: worktree record: %w", err)
	}
	return nil
}

// sandboxWorktreeLog is logger, or the default logger when nil.
func sandboxWorktreeLog(logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return slog.Default()
	}
	return logger
}
