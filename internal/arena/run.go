package arena

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// DefaultTimeout is the per-candidate wall cap when a RunSpec leaves
// Timeout unset.
const DefaultTimeout = 15 * time.Minute

// MaxTimeout is the largest per-candidate wall cap accepted from an Arena
// request. The UI tops out at the same two hours; the engine also enforces it
// so a hand-written request cannot create an effectively unbounded drive.
const MaxTimeout = 2 * time.Hour

const (
	maxRunIDBytes      = 64
	maxCandidates      = 16
	maxPromptBytes     = 1 << 20
	maxContextFiles    = 256
	maxModelValueBytes = 512
)

var safeRunID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

// MaxParallelFloor bounds [arena].max_parallel: driving more candidates at
// once than this hammers both the host and the proxy.
const MaxParallelFloor = 1

// Options configures a Runner.
type Options struct {
	// Store persists run/candidate rows (migration 088).
	Store *store.Store
	// WorkspaceDir is the root under which run worktrees are created
	// (typically ~/.observer/arena). Required.
	WorkspaceDir string
	// ProxyURL is the observer proxy base used for token capture lanes;
	// empty disables routing (cost columns then stay honestly zero).
	ProxyURL string
	// MaxParallel caps concurrent candidate drives (default 3, floor 1).
	MaxParallel int
	// Admission runs immediately before each candidate or judge process starts.
	// Nil leaves Arena admission unchanged. The callback receives the tool name
	// and configured Arena proxy URL so cmd can apply launch policy without
	// coupling this package to guard or configuration internals.
	Admission func(context.Context, string, string) error
}

// CandidateSpec names one harness slot in a run.
type CandidateSpec struct {
	Tool  string // registry tool name ("claude-code", "codex")
	Model string // model value passed through the registry ModelSpec; may be ""
}

// RunSpec describes one arena run.
type RunSpec struct {
	ID          string
	ProjectRoot string
	Prompt      string
	// ContextFiles are project-relative regular files explicitly supplied to
	// headless harnesses whose registry contract requires argv context (aider).
	ContextFiles []string
	Candidates   []CandidateSpec
	JudgeTool    string
	JudgeModel   string
	// Timeout caps each candidate drive; DefaultTimeout when zero.
	Timeout time.Duration
}

// PreparedRun is the on-disk + in-store state after StartRun: worktrees
// created, candidate rows pending.
type PreparedRun struct {
	Spec       RunSpec
	BaseSHA    string
	BaseBranch string
	RunDir     string
}

// Runner executes arena runs against a project repository.
type Runner struct {
	opts Options
}

// NewRunner validates options and returns a Runner.
func NewRunner(opts Options) (*Runner, error) {
	if opts.Store == nil {
		return nil, errors.New("arena.NewRunner: store required")
	}
	if opts.WorkspaceDir == "" {
		return nil, errors.New("arena.NewRunner: workspace dir required")
	}
	if opts.MaxParallel < MaxParallelFloor {
		opts.MaxParallel = 3
	}
	return &Runner{opts: opts}, nil
}

// ErrDirtyTree is returned by StartRun when the project has uncommitted
// changes. The CALLER owns the interactive triage ruling (cancel /
// stash / proceed-anyway): proceeding past it means calling StartRunWith
// AllowDirty.
var ErrDirtyTree = errors.New("arena.StartRun: project has uncommitted changes")

// StartRun validates the project, snapshots the base commit, creates one
// worktree + branch + store row per candidate. It never drives agents —
// DriveCandidates does that as a separate, cancellable step so the API
// layer can persist a runnable record before any spend.
func (r *Runner) StartRun(ctx context.Context, spec RunSpec) (*PreparedRun, error) {
	return r.startRun(ctx, spec, false)
}

// StartRunWithForce is StartRun with the dirty-tree guard waived (the
// operator chose "proceed anyway"; diffs stay well-defined because they
// are captured against the recorded BaseSHA).
func (r *Runner) StartRunWithForce(ctx context.Context, spec RunSpec) (*PreparedRun, error) {
	return r.startRun(ctx, spec, true)
}

// startRun runs the sequential validate -> base-resolve -> per-candidate
// worktree/branch provisioning pipeline described on StartRun. Each phase is
// its own helper so the rollback pairing in provisionCandidates (the part
// that actually needs care) isn't buried under unrelated validation noise.
func (r *Runner) startRun(ctx context.Context, spec RunSpec, allowDirty bool) (*PreparedRun, error) {
	if err := validateRunSpec(spec); err != nil {
		return nil, err
	}
	projectRoot, err := resolveProjectRoot(spec.ProjectRoot)
	if err != nil {
		return nil, err
	}
	spec.ProjectRoot = projectRoot

	if err := validateCandidates(spec.Candidates); err != nil {
		return nil, err
	}
	if err := validateJudge(spec.JudgeTool, spec.JudgeModel); err != nil {
		return nil, err
	}
	contextFiles, err := normalizeContextFiles(spec.ProjectRoot, spec.ContextFiles)
	if err != nil {
		return nil, fmt.Errorf("arena.StartRun: context files: %w", err)
	}
	spec.ContextFiles = contextFiles

	baseSHA, baseBranch, err := resolveGitBase(ctx, spec.ProjectRoot, allowDirty)
	if err != nil {
		return nil, err
	}

	prep, err := r.createRunWorkspace(ctx, spec, baseSHA, baseBranch)
	if err != nil {
		return nil, err
	}
	if err := r.provisionCandidates(ctx, prep, baseSHA); err != nil {
		return nil, err
	}
	return prep, nil
}

// validateRunSpec checks the run-level fields a candidate loop doesn't
// touch: required strings, the run ID's path-safe shape, and the size/count
// ceilings that keep a hand-written request from creating an effectively
// unbounded run.
func validateRunSpec(spec RunSpec) error {
	if spec.ID == "" || strings.TrimSpace(spec.ProjectRoot) == "" || strings.TrimSpace(spec.Prompt) == "" {
		return errors.New("arena.StartRun: id, project_root and prompt required")
	}
	if len(spec.ID) > maxRunIDBytes || !safeRunID.MatchString(spec.ID) {
		return fmt.Errorf("arena.StartRun: id must be 1-%d ASCII letters, digits, underscores or hyphens", maxRunIDBytes)
	}
	if len(spec.Prompt) > maxPromptBytes {
		return fmt.Errorf("arena.StartRun: prompt exceeds %d bytes", maxPromptBytes)
	}
	if len(spec.Candidates) == 0 {
		return errors.New("arena.StartRun: at least one candidate required")
	}
	if len(spec.Candidates) > maxCandidates {
		return fmt.Errorf("arena.StartRun: at most %d candidates are allowed", maxCandidates)
	}
	if len(spec.ContextFiles) > maxContextFiles {
		return fmt.Errorf("arena.StartRun: at most %d context files are allowed", maxContextFiles)
	}
	if spec.Timeout < 0 || spec.Timeout > MaxTimeout {
		return fmt.Errorf("arena.StartRun: timeout must be between 0 and %s", MaxTimeout)
	}
	return nil
}

// resolveProjectRoot returns the absolute, symlink-resolved, cleaned form of
// a run's project root so every later path comparison (worktree dirs, git
// invocations) works off one canonical path.
func resolveProjectRoot(projectRoot string) (string, error) {
	abs, err := filepath.Abs(projectRoot)
	if err != nil {
		return "", fmt.Errorf("arena.StartRun: project root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("arena.StartRun: project root: %w", err)
	}
	return filepath.Clean(resolved), nil
}

// validateCandidates checks each candidate's tool is present, unique, and
// grounded (a live headless contract plus a resolvable binary) before any
// worktree is created for it.
func validateCandidates(candidates []CandidateSpec) error {
	seenTools := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		if c.Tool == "" || seenTools[c.Tool] {
			if c.Tool == "" {
				return errors.New("arena.StartRun: candidate tool required")
			}
			return fmt.Errorf("arena.StartRun: duplicate candidate tool %q is not supported", c.Tool)
		}
		seenTools[c.Tool] = true
		if len(c.Model) > maxModelValueBytes {
			return fmt.Errorf("arena.StartRun: model for %q exceeds %d bytes", c.Tool, maxModelValueBytes)
		}
		ic, ok := integration.For(c.Tool)
		if !ok || ic.Headless == nil {
			return fmt.Errorf("arena.StartRun: tool %q has no grounded headless contract", c.Tool)
		}
		if _, err := driveBinaryFor(c.Tool); err != nil {
			return fmt.Errorf("arena.StartRun: candidate %q: %w", c.Tool, err)
		}
	}
	return nil
}

// validateJudge checks the judge tool the same way a candidate is checked
// (a live headless contract plus a resolvable binary) before any worktree
// work starts.
func validateJudge(tool, model string) error {
	judge, ok := integration.For(tool)
	if !ok || judge.Headless == nil {
		return fmt.Errorf("arena.StartRun: judge tool %q has no grounded headless contract", tool)
	}
	if len(model) > maxModelValueBytes {
		return fmt.Errorf("arena.StartRun: judge model exceeds %d bytes", maxModelValueBytes)
	}
	if _, err := driveBinaryFor(tool); err != nil {
		return fmt.Errorf("arena.StartRun: judge %q: %w", tool, err)
	}
	return nil
}

// resolveGitBase checks the working tree is clean (unless the caller waived
// it) and snapshots the commit + branch a run's candidates fork from.
// Detached HEAD is rejected: Keep needs a branch to land a candidate's
// squashed commit onto.
func resolveGitBase(ctx context.Context, projectRoot string, allowDirty bool) (baseSHA, baseBranch string, err error) {
	dirty, err := git.IsDirty(ctx, projectRoot)
	if err != nil {
		return "", "", fmt.Errorf("arena.StartRun: %w", err)
	}
	if dirty && !allowDirty {
		return "", "", ErrDirtyTree
	}
	baseSHA, err = git.HeadSHA(ctx, projectRoot)
	if err != nil {
		return "", "", fmt.Errorf("arena.StartRun: %w", err)
	}
	baseBranch, err = git.CurrentBranch(ctx, projectRoot)
	if err != nil {
		return "", "", fmt.Errorf("arena.StartRun: %w", err)
	}
	if baseBranch == "" {
		return "", "", errors.New("arena.StartRun: detached HEAD is not supported; check out the branch that should receive a kept candidate")
	}
	return baseSHA, baseBranch, nil
}

// createRunWorkspace makes the run's workspace directory and inserts its
// store row. On a row-insert failure the just-created directory is removed
// so a failed StartRun leaves no debris — the same rollback discipline
// provisionCandidates applies one level down, per candidate.
func (r *Runner) createRunWorkspace(ctx context.Context, spec RunSpec, baseSHA, baseBranch string) (*PreparedRun, error) {
	runDir := filepath.Join(r.opts.WorkspaceDir, spec.ID)
	prep := &PreparedRun{Spec: spec, BaseSHA: baseSHA, BaseBranch: baseBranch, RunDir: runDir}
	if err := os.MkdirAll(r.opts.WorkspaceDir, 0o700); err != nil {
		return nil, fmt.Errorf("arena.StartRun: workspace root: %w", err)
	}
	if err := os.Mkdir(runDir, 0o700); err != nil {
		return nil, fmt.Errorf("arena.StartRun: run workspace must be new: %w", err)
	}

	run := &models.ArenaRun{
		ID:          spec.ID,
		ProjectRoot: spec.ProjectRoot,
		BaseBranch:  baseBranch,
		BaseSHA:     baseSHA,
		Prompt:      spec.Prompt,
		JudgeTool:   spec.JudgeTool,
		JudgeModel:  spec.JudgeModel,
		Status:      models.ArenaRunStatusPending,
	}
	if err := r.opts.Store.InsertArenaRun(ctx, run); err != nil {
		_ = os.Remove(runDir)
		return nil, fmt.Errorf("arena.StartRun: %w", err)
	}
	return prep, nil
}

// provisionCandidates creates one worktree + branch + store row per
// candidate, tearing down everything created so far the moment any step
// fails via teardownPartial. The rollback count differs by exactly one
// between the two failure sites (the worktree-add failure hasn't created
// candidate i yet; the row-insert failure has) — that distinction is the
// reason this loop stays one function instead of being split further.
func (r *Runner) provisionCandidates(ctx context.Context, prep *PreparedRun, baseSHA string) error {
	for i, c := range prep.Spec.Candidates {
		wtPath := filepath.Join(prep.RunDir, c.Tool)
		branchName := fmt.Sprintf("arena/%s/%s", prep.Spec.ID, c.Tool)
		if err := git.WorktreeAdd(ctx, prep.Spec.ProjectRoot, wtPath, branchName, baseSHA); err != nil {
			r.teardownPartial(ctx, prep, i, err)
			return fmt.Errorf("arena.StartRun: worktree %s: %w", c.Tool, err)
		}
		row := &models.ArenaCandidate{
			ID:           fmt.Sprintf("%s-%s", prep.Spec.ID, c.Tool),
			RunID:        prep.Spec.ID,
			Tool:         c.Tool,
			Model:        c.Model,
			Seq:          i,
			Status:       models.ArenaCandidateStatusPending,
			BranchName:   branchName,
			WorktreePath: wtPath,
			SessionIDs:   []string{},
		}
		if err := r.opts.Store.InsertArenaCandidate(ctx, row); err != nil {
			r.teardownPartial(ctx, prep, i+1, err)
			return fmt.Errorf("arena.StartRun: candidate row: %w", err)
		}
	}
	return nil
}

// teardownPartial removes worktrees already created when a later step
// fails, so a failed StartRun leaves no debris.
func (r *Runner) teardownPartial(ctx context.Context, prep *PreparedRun, created int, cause error) {
	cleanupCtx := context.WithoutCancel(ctx)
	for i := 0; i < created; i++ {
		wt := filepath.Join(prep.RunDir, prep.Spec.Candidates[i].Tool)
		_ = git.WorktreeRemove(cleanupCtx, prep.Spec.ProjectRoot, wt)
		_ = git.DeleteBranch(cleanupCtx, prep.Spec.ProjectRoot,
			fmt.Sprintf("arena/%s/%s", prep.Spec.ID, prep.Spec.Candidates[i].Tool))
	}
	if rows, err := r.opts.Store.ArenaCandidates(cleanupCtx, prep.Spec.ID); err == nil {
		for i := range rows {
			rows[i].Status = models.ArenaCandidateStatusFailed
			rows[i].Error = truncateStr("start cleanup: "+cause.Error(), 500)
			_ = r.opts.Store.UpdateArenaCandidate(cleanupCtx, &rows[i])
		}
	}
	_ = r.opts.Store.UpdateArenaRunStatus(cleanupCtx, prep.Spec.ID, models.ArenaRunStatusFailed)
	_ = os.Remove(prep.RunDir) // succeeds only when cleanup left an empty run dir
}

// DriveCandidates runs every still-pending candidate of a prepared run
// (bounded parallelism), capturing outcome metrics, the patch, and judge
// scores. Individual failures mark that candidate failed/timeout and do
// not abort siblings; only store errors abort the pass.
func (r *Runner) DriveCandidates(ctx context.Context, prep *PreparedRun) error {
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusRunning); err != nil {
		return fmt.Errorf("arena.DriveCandidates: %w", err)
	}

	rows, err := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	if err != nil {
		return fmt.Errorf("arena.DriveCandidates: %w", err)
	}
	sem := make(chan struct{}, max(1, r.opts.MaxParallel))
	var wg sync.WaitGroup
	errCh := make(chan error, len(rows))
	for _, row := range rows {
		if row.Status != models.ArenaCandidateStatusPending {
			continue
		}
		wg.Add(1)
		go func(row models.ArenaCandidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := r.driveOne(ctx, prep, row); err != nil {
				errCh <- err
			}
		}(row)
	}
	wg.Wait()
	close(errCh)

	// A pipeline error must never leave candidates zombie-"running": the
	// API layer discards this error and moves on to judging, so any row
	// still marked running here (its final update failed under contention)
	// gets an honest failed state with the cause attached.
	var firstErr error
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		if rows, ferr := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID); ferr == nil {
			for i := range rows {
				if rows[i].Status != models.ArenaCandidateStatusRunning {
					continue
				}
				rows[i].Status = models.ArenaCandidateStatusFailed
				rows[i].Error = truncateStr("drive pipeline error: "+firstErr.Error(), 500)
				_ = r.opts.Store.UpdateArenaCandidate(ctx, &rows[i])
			}
		}
		return fmt.Errorf("arena.DriveCandidates: %w", firstErr)
	}

	if err := r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusJudging); err != nil {
		return fmt.Errorf("arena.DriveCandidates: %w", err)
	}
	return nil
}

// driveOne runs one candidate end-to-end: drive → seed attribution →
// commit → diff → patch file → judged → persisted.
func (r *Runner) driveOne(ctx context.Context, prep *PreparedRun, row models.ArenaCandidate) error {
	row.Status = models.ArenaCandidateStatusRunning
	if err := r.opts.Store.UpdateArenaCandidate(ctx, &row); err != nil {
		return fmt.Errorf("arena.driveOne: %w", err)
	}

	timeout := prep.Spec.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	cfgDir, cerr := prepareClaudeSandbox(prep.RunDir, row.Tool, r.opts.WorkspaceDir)
	if cerr != nil {
		row.Status = models.ArenaCandidateStatusFailed
		row.Error = truncateStr(cerr.Error(), 500)
		if uerr := r.opts.Store.UpdateArenaCandidate(ctx, &row); uerr != nil {
			return fmt.Errorf("arena.driveOne: %w", uerr)
		}
		return nil // candidate-level failure is an outcome, not an engine error
	}
	arenaSessionID := ""
	var onStart func(int) error
	var onExit func(int)
	if r.opts.ProxyURL != "" {
		arenaSessionID = models.ArenaSessionIDPrefix + row.ID
		onStart = func(pid int) error {
			return r.opts.Store.BindArenaProcess(ctx, pid, arenaSessionID, row.Tool, row.WorktreePath)
		}
		onExit = func(pid int) {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = r.opts.Store.UnbindArenaProcess(cleanupCtx, pid, arenaSessionID)
		}
	}
	res, err := driveHarness(ctx, driveRequest{
		Tool:         row.Tool,
		Model:        row.Model,
		WorktreePath: row.WorktreePath,
		Prompt:       prep.Spec.Prompt,
		ContextFiles: prep.Spec.ContextFiles,
		ProxyURL:     r.opts.ProxyURL,
		Timeout:      timeout,
		ConfigDir:    cfgDir,
		OnStart:      onStart,
		OnExit:       onExit,
		Admission:    r.opts.Admission,
	})
	if err != nil {
		row.Status = models.ArenaCandidateStatusFailed
		row.Error = truncateStr(err.Error(), 500)
		if uerr := r.opts.Store.UpdateArenaCandidate(ctx, &row); uerr != nil {
			return fmt.Errorf("arena.driveOne: %w", uerr)
		}
		return nil // candidate-level failure is an outcome, not an engine error
	}
	row.ExitCode = res.ExitCode
	row.WallMS = res.WallMS
	row.TimedOut = res.TimedOut
	row.SessionIDs = appendDistinct(res.SessionIDs, arenaSessionID)
	row.FinalAnswerExcerpt = truncateStr(stripANSI(res.FinalAnswer), 2000)
	switch {
	case res.TimedOut:
		row.Status = models.ArenaCandidateStatusTimeout
	case res.ExitCode != 0:
		row.Status = models.ArenaCandidateStatusFailed
		row.Error = "harness exit code " + itoa(res.ExitCode)
	default:
		row.Status = models.ArenaCandidateStatusDone
	}

	// Commit whatever state the harness left and capture the canonical
	// diff vs the run's base SHA — even for failed/timeouted candidates,
	// partial work is exactly what the judge and the operator want to see.
	// Arena/harness artifacts are removed first: they are not candidate
	// work and must not ride the patch (smoke-20260822-01's stray output
	// file, smoke-20260822-02's committed __pycache__ bytecode).
	_ = removeDriveArtifacts(row.WorktreePath)
	patchPath := filepath.Join(prep.RunDir, row.Tool+".patch")
	if sha, cerr := git.CommitAll(ctx, row.WorktreePath,
		fmt.Sprintf("arena %s candidate (%s)", prep.Spec.ID, row.Tool)); cerr == nil && sha != "" {
		files, added, removed, derr := git.DiffStat(ctx, row.WorktreePath, prep.BaseSHA)
		if derr == nil {
			row.DiffFiles, row.DiffAdded, row.DiffRemoved = files, added, removed
		}
		if patch, perr := git.PatchText(ctx, row.WorktreePath, prep.BaseSHA); perr == nil {
			if werr := writePatchFile(patchPath, []byte(patch)); werr == nil {
				row.PatchPath = patchPath
			}
		}
	} else if row.Status == models.ArenaCandidateStatusDone {
		row.Status = models.ArenaCandidateStatusFailed
		row.Error = "commit-all failed: " + truncateStr(cerr.Error(), 300)
	}

	if err := r.opts.Store.UpdateArenaCandidate(ctx, &row); err != nil {
		return fmt.Errorf("arena.driveOne: %w", err)
	}

	// Launch-seed attribution: the child pid was seeded by nothing (we
	// drove the binary directly), so record the seed ourselves post-Start
	// via the driver-reported pid when present.
	if res.PID > 0 {
		_ = r.opts.Store.InsertLaunchSeed(ctx, processobs.LaunchSeed{
			PID: res.PID, Tool: row.Tool, CWD: row.WorktreePath,
			StartedAt: time.Now().UTC().Add(-time.Duration(res.WallMS) * time.Millisecond),
		})
	}
	return nil
}

func appendDistinct(ids []string, extra string) []string {
	out := make([]string, 0, len(ids)+1)
	seen := make(map[string]bool, len(ids)+1)
	for _, id := range append(append([]string(nil), ids...), extra) {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// writePatchFile replaces any pre-planted path (including a symlink) and then
// creates the control artifact exclusively. A candidate must never trick the
// engine's ordinary WriteFile call into following ../<tool>.patch onto an
// unrelated operator file.
func writePatchFile(path string, body []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// normalizeContextFiles validates and deduplicates operator-selected context
// paths before worktrees or database rows are created. Only existing regular
// files inside the project are accepted; harnesses receive project-relative
// paths so the same argv resolves inside every candidate worktree.
func normalizeContextFiles(projectRoot string, paths []string) ([]string, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	root, err := filepath.Abs(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("project root: %w", err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, fmt.Errorf("project root: %w", err)
	}
	root = filepath.Clean(root)
	seen := make(map[string]bool, len(paths))
	out := make([]string, 0, len(paths))
	for _, raw := range paths {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if filepath.IsAbs(raw) || filepath.VolumeName(raw) != "" {
			return nil, fmt.Errorf("%q must be project-relative", raw)
		}
		clean := filepath.Clean(raw)
		if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("%q escapes the project", raw)
		}
		abs := filepath.Join(root, clean)
		rel, err := filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, fmt.Errorf("%q escapes the project", raw)
		}
		// Reject every symlink component, even one whose target currently lands
		// inside the project. Candidate worktrees live elsewhere, so an absolute
		// or escaping link could make aider read or edit the operator's original
		// tree rather than the isolated candidate.
		current := root
		var info os.FileInfo
		for _, part := range strings.Split(clean, string(filepath.Separator)) {
			current = filepath.Join(current, part)
			info, err = os.Lstat(current)
			if err != nil {
				return nil, fmt.Errorf("%q: %w", clean, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("%q must not traverse symlinks", clean)
			}
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%q is not a regular file", clean)
		}
		if !seen[clean] {
			seen[clean] = true
			out = append(out, clean)
		}
	}
	return out, nil
}

// JudgeRun grades every done/done-adjacent candidate with the run's judge
// harness and stores the rubric scores. Candidates whose status is not
// gradeable are skipped silently — their scorecard stays empty and honest.
func (r *Runner) JudgeRun(ctx context.Context, prep *PreparedRun) error {
	jcap, ok := integration.For(prep.Spec.JudgeTool)
	if !ok || jcap.Headless == nil {
		return fmt.Errorf("arena.JudgeRun: judge tool %q has no grounded headless contract", prep.Spec.JudgeTool)
	}
	// Proxy turns stream into api_turns while drives run; bind their
	// rollups onto the candidate rows before grading, and once more at
	// completion to catch turns that landed during judging.
	if err := r.rollupUsage(ctx, prep); err != nil {
		return fmt.Errorf("arena.JudgeRun: %w", err)
	}
	judgeCfg, err := prepareClaudeSandbox(prep.RunDir, "judge", r.opts.WorkspaceDir)
	if err != nil {
		return fmt.Errorf("arena.JudgeRun: %w", err)
	}
	rows, err := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	if err != nil {
		return fmt.Errorf("arena.JudgeRun: %w", err)
	}
	for _, row := range rows {
		switch row.Status {
		case models.ArenaCandidateStatusDone, models.ArenaCandidateStatusTimeout:
		default:
			continue
		}
		patch, err := os.ReadFile(row.PatchPath)
		if err != nil || len(patch) == 0 {
			continue // nothing to judge (inert candidate)
		}
		scores, verdict, jerr := judgeCandidate(ctx, driveRequest{
			Tool:      prep.Spec.JudgeTool,
			Model:     prep.Spec.JudgeModel,
			Prompt:    renderJudgePrompt(prep.Spec.Prompt, string(patch)),
			ProxyURL:  r.opts.ProxyURL,
			Timeout:   DefaultTimeout,
			ConfigDir: judgeCfg,
			Admission: r.opts.Admission,
		}, jcap.Headless)
		if jerr != nil {
			row.Verdict = "judge error: " + truncateStr(jerr.Error(), 300)
		} else {
			row.Scores = scores
			row.Verdict = truncateStr(verdict, 2000)
		}
		row.Status = models.ArenaCandidateStatusJudged
		if err := r.opts.Store.UpdateArenaCandidate(ctx, &row); err != nil {
			return fmt.Errorf("arena.JudgeRun: %w", err)
		}
	}
	if err := r.rollupUsage(ctx, prep); err != nil {
		return fmt.Errorf("arena.JudgeRun: %w", err)
	}
	return r.opts.Store.UpdateArenaRunStatus(ctx, prep.Spec.ID, models.ArenaRunStatusComplete)
}

// MarkRunFailed records an asynchronous pipeline failure without destroying
// completed candidate output. Only non-terminal rows are swept to failed; done
// or judged candidates remain available for inspection and discard.
func (r *Runner) MarkRunFailed(ctx context.Context, runID string, cause error) error {
	if runID == "" {
		return errors.New("arena.MarkRunFailed: run id required")
	}
	if cause == nil {
		cause = errors.New("arena pipeline failed")
	}
	rows, err := r.opts.Store.ArenaCandidates(ctx, runID)
	if err != nil {
		return fmt.Errorf("arena.MarkRunFailed: %w", err)
	}
	for i := range rows {
		switch rows[i].Status {
		case models.ArenaCandidateStatusPending, models.ArenaCandidateStatusRunning:
			rows[i].Status = models.ArenaCandidateStatusFailed
			rows[i].Error = truncateStr("pipeline failed: "+cause.Error(), 500)
			if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[i]); err != nil {
				return fmt.Errorf("arena.MarkRunFailed: %w", err)
			}
		}
	}
	if err := r.opts.Store.UpdateArenaRunStatus(ctx, runID, models.ArenaRunStatusFailed); err != nil {
		return fmt.Errorf("arena.MarkRunFailed: %w", err)
	}
	return nil
}

// removeDriveArtifacts deletes harness/arena byproducts from a worktree
// before the candidate commit: the codex output file plus regenerable
// Python bytecode (__pycache__ dirs, *.pyc/*.pyo) that `git add -A` would
// otherwise sweep into the patch and any subsequent keep.
func removeDriveArtifacts(worktree string) error {
	if worktree == "" {
		return nil
	}
	_ = os.Remove(filepath.Join(worktree, ".arena-last-message.txt"))
	return filepath.WalkDir(worktree, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are not worth failing a drive over
		}
		if d.IsDir() && d.Name() == "__pycache__" {
			return os.RemoveAll(path)
		}
		if !d.IsDir() {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".pyc", ".pyo":
				_ = os.Remove(path)
			}
		}
		return nil
	})
}

// rollupUsage binds per-candidate api_turns sums (input/output tokens,// cost) onto the candidate rows by their driver-parsed session ids. It is
// idempotent — each pass rewrites the columns from full SUMs over
// api_turns, so late-landing turns converge without double counting.
// Candidates with no session ids (or no turns yet) stay honestly zero.
func (r *Runner) rollupUsage(ctx context.Context, prep *PreparedRun) error {
	rows, err := r.opts.Store.ArenaCandidates(ctx, prep.Spec.ID)
	if err != nil {
		return fmt.Errorf("arena.rollupUsage: %w", err)
	}
	for i := range rows {
		if len(rows[i].SessionIDs) == 0 {
			continue
		}
		inTok, outTok, cost, err := r.opts.Store.ArenaUsageBySessions(ctx, rows[i].SessionIDs)
		if err != nil {
			return fmt.Errorf("arena.rollupUsage: %w", err)
		}
		rows[i].InputTokens, rows[i].OutputTokens, rows[i].CostUSD = inTok, outTok, cost
		if err := r.opts.Store.UpdateArenaCandidate(ctx, &rows[i]); err != nil {
			return fmt.Errorf("arena.rollupUsage: %w", err)
		}
	}
	return nil
}

// DiscardCandidate prunes a terminal undecided candidate's worktree and branch
// and then marks the row discarded.
func (r *Runner) DiscardCandidate(ctx context.Context, row models.ArenaCandidate, projectRoot string) error {
	canonical, run, err := r.candidateForMutation(ctx, row.ID, projectRoot)
	if err != nil {
		return fmt.Errorf("arena.DiscardCandidate: %w", err)
	}
	row = *canonical
	if !arenaRunIsTerminal(run.Status) {
		return fmt.Errorf("arena.DiscardCandidate: run status %q is still active", run.Status)
	}
	switch row.Status {
	case models.ArenaCandidateStatusDone, models.ArenaCandidateStatusFailed,
		models.ArenaCandidateStatusTimeout, models.ArenaCandidateStatusJudged:
	default:
		return fmt.Errorf("arena.DiscardCandidate: candidate status %q is not terminal and discardable", row.Status)
	}
	if row.WorktreePath != "" {
		if _, statErr := os.Lstat(row.WorktreePath); statErr == nil {
			if err := git.WorktreeRemove(ctx, projectRoot, row.WorktreePath); err != nil {
				return fmt.Errorf("arena.DiscardCandidate: %w", err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("arena.DiscardCandidate: inspect worktree: %w", statErr)
		}
	}
	if row.BranchName != "" {
		if err := git.DeleteBranch(ctx, projectRoot, row.BranchName); err != nil {
			return fmt.Errorf("arena.DiscardCandidate: %w", err)
		}
	}
	return r.opts.Store.SetCandidateDiscarded(ctx, row.ID)
}

func arenaRunIsTerminal(status string) bool {
	return status == models.ArenaRunStatusComplete || status == models.ArenaRunStatusFailed
}

// candidateForMutation reloads the canonical candidate/run pair and verifies
// every filesystem and branch target before Keep or Discard mutates git. The
// caller-supplied row contributes only its id; stale or forged fields never
// select a branch, worktree, project, or lifecycle state.
func (r *Runner) candidateForMutation(ctx context.Context, candidateID, projectRoot string) (*models.ArenaCandidate, *models.ArenaRun, error) {
	if candidateID == "" {
		return nil, nil, errors.New("candidate id required")
	}
	row, err := r.opts.Store.ArenaCandidate(ctx, candidateID)
	if err != nil {
		return nil, nil, fmt.Errorf("load candidate: %w", err)
	}
	if row == nil {
		return nil, nil, errors.New("candidate not found")
	}
	run, err := r.opts.Store.ArenaRun(ctx, row.RunID)
	if err != nil {
		return nil, nil, fmt.Errorf("load run: %w", err)
	}
	if run == nil {
		return nil, nil, errors.New("candidate run not found")
	}
	if len(run.ID) > maxRunIDBytes || !safeRunID.MatchString(run.ID) {
		return nil, nil, errors.New("candidate run id is not a valid Arena id")
	}
	if _, ok := integration.For(row.Tool); !ok {
		return nil, nil, fmt.Errorf("candidate tool %q is not registered", row.Tool)
	}
	if row.ID != fmt.Sprintf("%s-%s", run.ID, row.Tool) {
		return nil, nil, errors.New("candidate id does not match its run and tool")
	}
	expectedBranch := fmt.Sprintf("arena/%s/%s", run.ID, row.Tool)
	if row.BranchName != expectedBranch {
		return nil, nil, errors.New("candidate branch does not match its run and tool")
	}
	expectedWorktree := filepath.Clean(filepath.Join(r.opts.WorkspaceDir, run.ID, row.Tool))
	if row.WorktreePath != expectedWorktree {
		return nil, nil, errors.New("candidate worktree does not match its Arena workspace")
	}
	wantRoot, err := filepath.EvalSymlinks(run.ProjectRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("run project root: %w", err)
	}
	gotRoot, err := filepath.EvalSymlinks(projectRoot)
	if err != nil {
		return nil, nil, fmt.Errorf("project root: %w", err)
	}
	if filepath.Clean(wantRoot) != filepath.Clean(gotRoot) {
		return nil, nil, errors.New("project root does not match the candidate run")
	}
	return row, run, nil
}

// mintSessionID mints an RFC-4122-v4-shaped UUID for claude-code's
// --session-id (crypto/rand; timestamp fallback mirrors the benchmark
// driver so an attempt is never lost on a rand failure).
func mintSessionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("sbo-arena-%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.TrimSpace(s[:n])
}

func itoa(n int) string {
	return strings.TrimSpace(fmt.Sprint(n))
}

// killProcGroup is defined per-platform in procgroup_unix.go /
// procgroup_other.go (SIGKILL the whole process group on unix; best-effort
// single-process kill elsewhere).
