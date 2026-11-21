//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_returns_route.go is the dashboard's "Changes from
// sandboxed runs" panel's routes (lane RETURNS, audit items H6 and L1):
// one owner-local list of the work sandboxed runs brought back (a hosted
// run's saved diff, a local copy run's returned commits, a worktree run's
// kept branch), a read-only preview of a saved diff, and three actions, each
// the person's click: open a saved diff as a branch, remove a saved diff,
// remove a local copy. Every route is Local and answers 404 while the
// sandbox module is off; the actions need the confirm token, and guard rule
// R-165 denies an agent's POST to any of them (rules_selfapproval.go), so an
// agent cannot apply its own diff or remove the copy that holds its work.

func init() {
	gatesSandboxRouteFuncs = append(gatesSandboxRouteFuncs, sandboxReturnsRoutes)
}

// The routes' paths.
const (
	sandboxReturnsPath           = "/api/terminal/sandbox/returns"
	sandboxReturnsDiffPath       = sandboxReturnsPath + "/diff"
	sandboxReturnsBranchPath     = sandboxReturnsPath + "/branch"
	sandboxReturnsRemoveDiffPath = sandboxReturnsPath + "/remove-diff"
	sandboxReturnsRemoveCopyPath = sandboxReturnsPath + "/remove-copy"
	// sandboxReturnsRemoveSafePath is "Remove all copies that are safe to
	// remove" (SBXD-2): every copy through the same removal table.
	sandboxReturnsRemoveSafePath = sandboxReturnsPath + "/remove-safe-copies"
)

// sandboxReturnsPreviewMax caps the diff text a preview sends.
const sandboxReturnsPreviewMax = 512 << 10

// sandboxReturnsEnv is what the routes read: the daemon's observer dir and
// managed root, and whether the sandbox module is on (a variable so tests
// stand it in).
var sandboxReturnsEnv = func(configPath string) (observerDir, managedRoot string, active bool) {
	if configPath == "" {
		configPath = daemonConfigPath()
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return "", "", false
	}
	observerDir = sandboxObserverDirFor(cfg)
	if r, rerr := filepath.EvalSymlinks(observerDir); rerr == nil {
		observerDir = r
	}
	managedRoot = defaultWorkspacesDir(cfg.Terminal.Sandbox, observerDir)
	if r, rerr := filepath.EvalSymlinks(managedRoot); rerr == nil {
		managedRoot = r
	}
	return observerDir, managedRoot, sandboxModuleActive(componentSnapshotForConfig(cfg))
}

// hostedDiffView is one saved diff on the panel.
type hostedDiffView struct {
	Run      string    `json:"run"`
	SavedAt  time.Time `json:"saved_at"`
	Bytes    int64     `json:"bytes"`
	Root     string    `json:"root,omitempty"`
	CloneURL string    `json:"clone_url,omitempty"`
	Path     string    `json:"path"`
	// Exact: the diff opens as a branch; Why says why not.
	Exact      bool   `json:"exact"`
	Why        string `json:"why,omitempty"`
	BaseCommit string `json:"base_commit,omitempty"`
	Excluded   int    `json:"excluded,omitempty"`
	Branch     string `json:"branch,omitempty"`
	// BranchExists: the branch was opened already.
	BranchExists bool   `json:"branch_exists,omitempty"`
	ApplyCommand string `json:"apply_command"`
	// NoRepository: the files were sent from a folder that is not a git
	// repository (SBXD-8); the panel offers the diff file's path, not an
	// apply command.
	NoRepository bool `json:"no_repository,omitempty"`
}

// localReturnView is one local copy, return repository or worktree branch
// on the panel.
type localReturnView struct {
	ID        string    `json:"id"`
	Source    string    `json:"source"`
	Origin    string    `json:"origin"`
	CreatedAt time.Time `json:"created_at"`
	CopyDir   string    `json:"copy_dir,omitempty"`
	SizeBytes int64     `json:"size_bytes"`
	SizeOver  bool      `json:"size_over,omitempty"`
	RunLive   bool      `json:"run_live"`
	// State is a workspace.CopyReturn* state ("" for a worktree run).
	State   string `json:"state,omitempty"`
	Ref     string `json:"ref,omitempty"`
	Commit  string `json:"commit,omitempty"`
	Commits int    `json:"commits"`
	Reason  string `json:"reason,omitempty"`
	// ReturnRepo and FetchCommand name a clone-remote run's return
	// repository and the one command that brings the ref home.
	ReturnRepo   string `json:"return_repo,omitempty"`
	FetchCommand string `json:"fetch_command,omitempty"`
	// Branch and Kept are a worktree run's kept branch and why it was kept.
	Branch string `json:"branch,omitempty"`
	Kept   string `json:"kept,omitempty"`
	// Removable: the panel offers "Remove the copy" (the server decides
	// again on the click).
	Removable bool `json:"removable"`
	// SafeToRemove and KeepReason are the removal table's verdict on the
	// copy now (workspace.DecideCopyRemoval over the facts the click reads,
	// sandboxCopyVerdict): the "Remove all copies that are safe to remove"
	// count is the copies with SafeToRemove, so it never counts a copy the
	// click then keeps (live run 2026-11-19, D4).
	SafeToRemove bool   `json:"safe_to_remove"`
	KeepReason   string `json:"keep_reason,omitempty"`
}

// sandboxReturnsRoutes are the panel's routes (gatesSandboxRouteFuncs).
func sandboxReturnsRoutes(configPath string) []dashapi.ExtraRoute {
	gate := func(h func(w http.ResponseWriter, r *http.Request, observerDir, managedRoot string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			obs, managed, active := sandboxReturnsEnv(configPath)
			if !active || obs == "" {
				http.NotFound(w, r)
				return
			}
			h(w, r, obs, managed)
		}
	}
	action := func(do func(ctx context.Context, observerDir, managedRoot, id string) (any, int, error)) http.HandlerFunc {
		return gate(func(w http.ResponseWriter, r *http.Request, obs, managed string) {
			if !hostedConfirmed(w, r) {
				return
			}
			var body struct {
				Run string `json:"run"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body); err != nil || strings.TrimSpace(body.Run) == "" {
				http.Error(w, "a run id is required", http.StatusBadRequest)
				return
			}
			out, code, err := do(r.Context(), obs, managed, strings.TrimSpace(body.Run))
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error(), "detail": out})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
		})
	}
	return []dashapi.ExtraRoute{
		{Pattern: "GET " + sandboxReturnsPath, Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request, obs, managed string) {
			tok := hostedConfirmToken(w, r)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"hosted": listHostedDiffs(r.Context(), obs), "local": listLocalReturns(r.Context(), obs, managed), "confirm_token": tok,
			})
		})},
		{Pattern: "GET " + sandboxReturnsDiffPath, Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request, obs, _ string) {
			run := strings.TrimSpace(r.URL.Query().Get("run"))
			if !returnsRunIDOK(run) {
				http.Error(w, "a run id is required", http.StatusBadRequest)
				return
			}
			text, cut, err := hostedDiffPreview(obs, run)
			if err != nil {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"run": run, "text": text, "cut": cut, "files": hostedDiffFiles(r.Context(), obs, run)})
		})},
		{Pattern: "POST " + sandboxReturnsBranchPath, Capability: dashapi.CapabilityLocal, Handler: action(openHostedDiffBranch)},
		{Pattern: "POST " + sandboxReturnsRemoveDiffPath, Capability: dashapi.CapabilityLocal, Handler: action(removeHostedDiff)},
		{Pattern: "POST " + sandboxReturnsRemoveCopyPath, Capability: dashapi.CapabilityLocal, Handler: action(func(ctx context.Context, obs, managed, id string) (any, int, error) {
			v, err := removeSandboxCopy(ctx, obs, managed, id)
			switch {
			case err != nil:
				return nil, http.StatusBadRequest, err
			case !v.Remove:
				return map[string]string{"kept": v.Reason}, http.StatusConflict, errors.New("the copy is kept: " + v.Reason)
			}
			return map[string]any{"removed": id}, http.StatusOK, nil
		})},
		// SBXD-2: one click, every copy, each walked through the removal
		// table with its facts read again; it names no run, so it has no
		// body (the confirm token still gates it, and R-165 covers it).
		{Pattern: "POST " + sandboxReturnsRemoveSafePath, Capability: dashapi.CapabilityLocal, Handler: gate(func(w http.ResponseWriter, r *http.Request, obs, managed string) {
			if !hostedConfirmed(w, r) {
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(removeSafeSandboxCopies(r.Context(), obs, managed))
		})},
	}
}

// listHostedDiffs lists the saved diffs, newest first.
func listHostedDiffs(ctx context.Context, observerDir string) []hostedDiffView {
	entries, err := os.ReadDir(hostedReturnsDir(observerDir))
	if err != nil {
		return []hostedDiffView{}
	}
	out := []hostedDiffView{}
	for _, e := range entries {
		run, ok := strings.CutSuffix(e.Name(), ".diff")
		if !ok || !e.Type().IsRegular() || !returnsRunIDOK(run) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		diffPath, _ := hostedDiffPaths(observerDir, run)
		v := hostedDiffView{Run: run, SavedAt: info.ModTime().UTC(), Bytes: info.Size(), Path: diffPath, ApplyCommand: workspace.DiffApplyCommand(diffPath)}
		rec, ok := readHostedDiffRecord(observerDir, run)
		if !ok {
			v.Why = "this diff was saved without the facts that say which commit it starts from"
			out = append(out, v)
			continue
		}
		v.SavedAt, v.Root, v.CloneURL, v.BaseCommit, v.Excluded = rec.SavedAt, rec.Root, rec.CloneURL, rec.Base.Commit, rec.Base.Excluded
		v.NoRepository = rec.Base.NoRepository
		verdict := workspace.DecideDiffBase(rec.Base.facts())
		v.Exact, v.Why = verdict.Exact, verdict.Reason
		if ref, err := workspace.DiffBranchRef(run); err == nil {
			v.Branch = workspace.DiffBranchName(ref)
			if v.Root != "" {
				if _, err := copyGit(ctx, v.Root, "rev-parse", "--verify", "--quiet", ref); err == nil {
					v.BranchExists = true
				}
			}
		}
		if v.Exact && (v.Root == "" || !filepath.IsAbs(v.Root)) {
			v.Exact, v.Why = false, "the folder the files were sent from is not recorded"
		}
		// A diff against the box's start is not cut at the guest's cap, so
		// it can be larger than "Open as a branch" reads (lane COPIES):
		// said here, before the click would refuse it.
		if v.Exact && v.Bytes > int64(sandbox.MaxStagedDiff) {
			v.Exact, v.Why = false, fmt.Sprintf("it is larger than the %d MiB Observer opens as a branch", sandbox.MaxStagedDiff>>20)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SavedAt.After(out[j].SavedAt) })
	return out
}

// hostedDiffPreview reads the start of a saved diff (never applied) and
// whether the preview was cut.
func hostedDiffPreview(observerDir, run string) (string, bool, error) {
	p, _ := hostedDiffPaths(observerDir, run)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return "", false, errors.New("there is no saved diff for that run")
	}
	f, err := os.Open(p) //nolint:gosec // G304: <observer>/sandbox-hosted/returns/<run>.diff, the run id one clean token
	if err != nil {
		return "", false, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, sandboxReturnsPreviewMax+1))
	if err != nil {
		return "", false, err
	}
	cut := len(b) > sandboxReturnsPreviewMax
	if cut {
		b = b[:sandboxReturnsPreviewMax]
	}
	return strings.ToValidUTF8(string(b), "�"), cut, nil
}

// hostedDiffFile is one file a saved diff touches.
type hostedDiffFile struct {
	Path    string `json:"path"`
	Added   int    `json:"added"`
	Deleted int    `json:"deleted"`
	Binary  bool   `json:"binary,omitempty"`
}

// hostedDiffFiles is git's reading of the files a saved diff touches (in
// the run's folder, nothing applied); empty when it cannot be read.
func hostedDiffFiles(ctx context.Context, observerDir, run string) []hostedDiffFile {
	out := []hostedDiffFile{}
	rec, ok := readHostedDiffRecord(observerDir, run)
	if !ok || !filepath.IsAbs(rec.Root) {
		return out
	}
	p, _ := hostedDiffPaths(observerDir, run)
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	b, err := copyGit(cctx, rec.Root, "apply", "--numstat", "-z", "--", p)
	if err != nil {
		return out
	}
	recs := strings.Split(string(b), "\x00")
	for i := 0; i < len(recs) && len(out) < 2000; i++ {
		parts := strings.SplitN(recs[i], "\t", 3)
		if len(parts) != 3 {
			continue
		}
		name := parts[2]
		if name == "" && i+2 < len(recs) {
			name = recs[i+1] + " -> " + recs[i+2]
			i += 2
		}
		f := hostedDiffFile{Path: name}
		if parts[0] == "-" {
			f.Binary = true
		} else {
			f.Added, _ = strconv.Atoi(parts[0])
			f.Deleted, _ = strconv.Atoi(parts[1])
		}
		out = append(out, f)
	}
	return out
}

// openHostedDiffBranch is the "Open as a branch" action.
func openHostedDiffBranch(ctx context.Context, observerDir, _, run string) (any, int, error) {
	if !returnsRunIDOK(run) {
		return nil, http.StatusBadRequest, errors.New("a run id is required")
	}
	diffPath, _ := hostedDiffPaths(observerDir, run)
	offer := map[string]string{"apply_command": workspace.DiffApplyCommand(diffPath), "path": diffPath}
	rec, ok := readHostedDiffRecord(observerDir, run)
	if !ok {
		return offer, http.StatusConflict, errors.New("this diff was saved without the facts that say which commit it starts from, so it is offered as a file only")
	}
	if v := workspace.DecideDiffBase(rec.Base.facts()); !v.Exact {
		return offer, http.StatusConflict, errors.New("it cannot be opened as a branch: " + v.Reason)
	}
	if !filepath.IsAbs(rec.Root) {
		return offer, http.StatusConflict, errors.New("the folder the files were sent from is not recorded")
	}
	res, err := sandboxOpenDiffBranch(ctx, rec.Root, diffPath, run, rec.Base.Commit)
	if err != nil {
		return offer, http.StatusConflict, err
	}
	return res, http.StatusOK, nil
}

// removeHostedDiff is the "Remove" action of a saved diff: the diff and its
// record. A branch opened from it stays.
func removeHostedDiff(_ context.Context, observerDir, _, run string) (any, int, error) {
	if !returnsRunIDOK(run) {
		return nil, http.StatusBadRequest, errors.New("a run id is required")
	}
	diffPath, recPath := hostedDiffPaths(observerDir, run)
	fi, err := os.Lstat(diffPath)
	if err != nil || !fi.Mode().IsRegular() {
		return nil, http.StatusNotFound, errors.New("there is no saved diff for that run")
	}
	if err := os.Remove(diffPath); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	if err := os.Remove(recPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, http.StatusInternalServerError, err
	}
	return map[string]string{"removed": run}, http.StatusOK, nil
}

// sandboxReturnsMaxSize caps the bytes, and sandboxReturnsMaxEntries the
// entries, counted for one copy's size (past either the panel says "over").
const (
	sandboxReturnsMaxSize    = 64 << 30
	sandboxReturnsMaxEntries = 300000
)

// listLocalReturns lists the managed workspaces of copy and worktree runs
// with their return, newest first. A removable clone copy also carries the
// removal table's verdict (sandboxCopyVerdictCached: the click's own facts,
// which run git, read again only when the copy or its return changed).
func listLocalReturns(ctx context.Context, observerDir, managedRoot string) []localReturnView {
	out := []localReturnView{}
	entries, err := os.ReadDir(managedRoot)
	if err != nil {
		return out
	}
	for _, e := range entries {
		id := e.Name()
		if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 || !validSandboxWorktreeID(id) {
			continue
		}
		runDir := filepath.Join(managedRoot, id)
		meta, ok := readWorkspaceMeta(runDir)
		if !ok || meta.Source == workspace.SourceLive {
			continue
		}
		v := localReturnView{ID: id, Source: string(meta.Source), Origin: meta.Origin, CreatedAt: meta.CreatedAt, Commits: -1, RunLive: sandboxWorktreeRunLive(observerDir, id)}
		if dir, ok := sandboxCopyDir(runDir); ok {
			v.CopyDir = dir
		}
		var newest time.Time
		v.SizeBytes, v.SizeOver, newest = dirSizeNewest(runDir, sandboxReturnsMaxSize)
		switch meta.Source {
		case workspace.SourceWorktree:
			v.Kept = meta.Kept
			if rec, err := readSandboxWorktreeRecord(sandboxWorktreeRecordPath(observerDir, id)); err == nil {
				v.Branch, v.Kept = rec.Branch, rec.Reason
			}
		default:
			v.State = workspace.CopyReturnUnknown
			if rec, err := readSandboxLocalReturn(sandboxLocalReturnPath(observerDir, id)); err == nil {
				v.State, v.Ref, v.Commit, v.Commits, v.Reason = rec.State, rec.Ref, rec.Commit, rec.Commits, rec.Reason
			} else if v.RunLive {
				v.State = workspace.CopyReturnPending
			}
			if meta.Source == workspace.SourceCloneRemote {
				if repo, err := workspace.ReturnRepoPath(managedRoot, id); err == nil {
					if fi, err := os.Lstat(repo); err == nil && fi.IsDir() {
						v.ReturnRepo = repo
						v.FetchCommand = workspace.ReturnFetchCommand(repo, workspace.ReturnRefPrefix+id)
					}
				}
			}
			v.Removable = !v.RunLive && v.CopyDir != ""
			if v.Removable {
				key := fmt.Sprintf("%d|%t|%d|%s|%s|%s", v.SizeBytes, v.SizeOver, newest.UnixNano(), v.State, v.Ref, v.Commit)
				verdict := sandboxCopyVerdictCached(ctx, observerDir, managedRoot, id, key)
				v.SafeToRemove, v.KeepReason = verdict.Remove, verdict.Reason
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

// dirSizeCapped sums the regular files under root without following any
// link, stopping at limit (over reports the stop).
func dirSizeCapped(root string, limit int64) (int64, bool) {
	total, over, _ := dirSizeNewest(root, limit)
	return total, over
}

// dirSizeNewest is dirSizeCapped that also says the newest modification
// time it saw (a change under the copy changes it).
func dirSizeNewest(root string, limit int64) (int64, bool, time.Time) {
	var newest time.Time
	var total int64
	n := 0
	stop := errors.New("over")
	err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if n++; n > sandboxReturnsMaxEntries {
			return stop
		}
		if info, ierr := d.Info(); ierr == nil {
			if info.ModTime().After(newest) {
				newest = info.ModTime()
			}
			if d.Type().IsRegular() {
				total += info.Size()
			}
		}
		if total > limit {
			return stop
		}
		return nil
	})
	return total, errors.Is(err, stop), newest
}
