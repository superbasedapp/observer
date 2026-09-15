package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/arena"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// arena.go — Agent Arena API surface (plan:
// docs/plans/agent-arena-terminal-multi-harness-2026-08-22.md §2f). Read
// routes are View; every mutation POST auto-escalates to Execute via the
// standard V-route rule AND re-checks the double-submit confirm token
// in-handler (spend + code-mutation surface, same posture as terminal
// launch). Run drives execute asynchronously; the UI polls run detail.

// arenaMu guards arenaInFlight: a run id may only be driven once per
// process lifetime (a daemon restart resets it — rows carry the state).
var (
	arenaMu       sync.Mutex
	arenaInFlight = map[string]bool{}
	// arenaActionInFlight serializes main-repository mutations by canonical
	// project root. Separate candidates or runs must never race git state in
	// the same checkout.
	arenaActionInFlight = map[string]bool{}
)

// reconcileStaleArena closes stranded in-flight Arena rows (a candidate stuck
// "running" under a finished run; a crash-orphaned run) to a terminal status on
// read, so the run history stops showing dead work as live. Runs currently
// being driven by this process (arenaInFlight) are passed through as known-live
// and never reconciled. Best-effort: a reconcile error is swallowed so a
// transient DB hiccup never blanks the history view.
func reconcileStaleArena(ctx context.Context, st *store.Store) {
	if st == nil {
		return
	}
	arenaMu.Lock()
	live := make(map[string]bool, len(arenaInFlight))
	for id, v := range arenaInFlight {
		if v {
			live[id] = true
		}
	}
	arenaMu.Unlock()
	_, _ = st.ReconcileStaleArena(ctx, time.Now().UTC(), live)
}

// arenaWorkspaceDir resolves the worktree root, defaulting to
// ~/.observer/arena.
func arenaWorkspaceDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".observer", "arena")
	}
	return filepath.Join(os.TempDir(), "observer-arena")
}

func (s *Server) newArenaRunner() (*arena.Runner, error) {
	st := s.remoteManageStore()
	if st == nil {
		return nil, errors.New("store unavailable")
	}
	return arena.NewRunner(arena.Options{
		Store:        st,
		WorkspaceDir: arenaWorkspaceDir(),
		ProxyURL:     fmt.Sprintf("http://127.0.0.1:%d", s.opts.ProxyPort),
		MaxParallel:  3,
		Admission:    s.opts.ArenaAdmission,
	})
}

func writeArenaErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, arena.ErrDirtyTree), errors.Is(err, arena.ErrMergeConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		writeErr(w, err)
	}
}

func candidateJSON(c models.ArenaCandidate) map[string]any {
	out := map[string]any{
		"id":            c.ID,
		"run_id":        c.RunID,
		"tool":          c.Tool,
		"model":         c.Model,
		"seq":           c.Seq,
		"status":        c.Status,
		"branch_name":   c.BranchName,
		"worktree_path": c.WorktreePath,
		"exit_code":     c.ExitCode,
		"wall_ms":       c.WallMS,
		"timed_out":     c.TimedOut,
		"diff_files":    c.DiffFiles,
		"diff_added":    c.DiffAdded,
		"diff_removed":  c.DiffRemoved,
		"input_tokens":  c.InputTokens,
		"output_tokens": c.OutputTokens,
		"cost_usd":      c.CostUSD,
		"session_ids":   c.SessionIDs,
		"verdict":       c.Verdict,
	}
	if c.FinalAnswerExcerpt != "" {
		out["final_answer"] = c.FinalAnswerExcerpt
	}
	if c.PatchPath != "" {
		out["has_patch"] = true
	}
	if c.Scores != nil {
		out["scores"] = c.Scores
	}
	return out
}

func runJSON(rn models.ArenaRun, candidates []models.ArenaCandidate) map[string]any {
	out := map[string]any{
		"id":           rn.ID,
		"project_root": rn.ProjectRoot,
		"base_branch":  rn.BaseBranch,
		"base_sha":     rn.BaseSHA,
		"prompt":       rn.Prompt,
		"judge_tool":   rn.JudgeTool,
		"judge_model":  rn.JudgeModel,
		"status":       rn.Status,
		"created_at":   rn.CreatedAt,
		"updated_at":   rn.UpdatedAt,
		"candidates":   []map[string]any{},
	}
	for _, c := range candidates {
		out["candidates"] = append(out["candidates"].([]map[string]any), candidateJSON(c))
	}
	return out
}

// handleArenaRuns serves GET /api/arena/runs (list) and POST /api/arena/runs
// (create + start driving asynchronously).
func (s *Server) handleArenaRuns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleArenaRunsList(w, r)
	case http.MethodPost:
		s.handleArenaRunsCreate(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleArenaRunsList(w http.ResponseWriter, r *http.Request) {
	st := s.remoteManageStore()
	if st == nil {
		writeJSON(w, map[string]any{"runs": []any{}})
		return
	}
	reconcileStaleArena(r.Context(), st)
	limit := intArg(r, "limit", 20, 1, 100)
	runs, err := st.RecentArenaRuns(r.Context(), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	out := make([]map[string]any, 0, len(runs))
	for _, rn := range runs {
		cands, err := st.ArenaCandidates(r.Context(), rn.ID)
		if err != nil {
			writeErr(w, err)
			return
		}
		out = append(out, runJSON(rn, cands))
	}
	writeJSON(w, map[string]any{"runs": out})
}

func (s *Server) handleArenaRunsCreate(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		ProjectRoot  string   `json:"project_root"`
		Prompt       string   `json:"prompt"`
		ContextFiles []string `json:"context_files"`
		Candidates   []struct {
			Tool  string `json:"tool"`
			Model string `json:"model"`
		} `json:"candidates"`
		JudgeTool  string `json:"judge_tool"`
		JudgeModel string `json:"judge_model"`
		TimeoutSec int    `json:"timeout_sec"`
		AllowDirty bool   `json:"allow_dirty"`
		RunID      string `json:"run_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	runner, err := s.newArenaRunner()
	if err != nil {
		writeErr(w, err)
		return
	}
	spec := arena.RunSpec{
		ID:           req.RunID,
		ProjectRoot:  req.ProjectRoot,
		Prompt:       req.Prompt,
		ContextFiles: req.ContextFiles,
		JudgeTool:    req.JudgeTool,
		JudgeModel:   req.JudgeModel,
	}
	maxTimeoutSec := int(arena.MaxTimeout / time.Second)
	if req.TimeoutSec < 0 || req.TimeoutSec > maxTimeoutSec {
		http.Error(w, fmt.Sprintf("timeout_sec must be between 0 and %d", maxTimeoutSec), http.StatusBadRequest)
		return
	}
	spec.Timeout = time.Duration(req.TimeoutSec) * time.Second
	for _, c := range req.Candidates {
		spec.Candidates = append(spec.Candidates, arena.CandidateSpec{Tool: c.Tool, Model: c.Model})
	}

	arenaMu.Lock()
	if arenaInFlight[spec.ID] {
		arenaMu.Unlock()
		http.Error(w, "run already in flight", http.StatusConflict)
		return
	}
	arenaMu.Unlock()

	prep, err := runner.StartRun(r.Context(), spec)
	if errors.Is(err, arena.ErrDirtyTree) && req.AllowDirty {
		prep, err = runner.StartRunWithForce(r.Context(), spec)
	}
	if err != nil {
		writeArenaErr(w, err)
		return
	}
	arenaMu.Lock()
	arenaInFlight[prep.Spec.ID] = true
	arenaMu.Unlock()

	go func() {
		ctx := context.WithoutCancel(r.Context())
		if err := runner.DriveCandidates(ctx, prep); err != nil {
			if markErr := runner.MarkRunFailed(ctx, prep.Spec.ID, err); markErr != nil {
				s.opts.Logger.Error("arena drive failed and status finalization failed", "run_id", prep.Spec.ID, "err", err, "mark_err", markErr)
			} else {
				s.opts.Logger.Error("arena drive failed", "run_id", prep.Spec.ID, "err", err)
			}
			arenaMu.Lock()
			delete(arenaInFlight, prep.Spec.ID)
			arenaMu.Unlock()
			return
		}
		if err := runner.JudgeRun(ctx, prep); err != nil {
			if markErr := runner.MarkRunFailed(ctx, prep.Spec.ID, err); markErr != nil {
				s.opts.Logger.Error("arena judge failed and status finalization failed", "run_id", prep.Spec.ID, "err", err, "mark_err", markErr)
			} else {
				s.opts.Logger.Error("arena judge failed", "run_id", prep.Spec.ID, "err", err)
			}
		}
		arenaMu.Lock()
		delete(arenaInFlight, prep.Spec.ID)
		arenaMu.Unlock()
	}()

	writeJSON(w, map[string]any{"run_id": prep.Spec.ID, "status": "started"})
}

func (s *Server) handleArenaRunDetail(w http.ResponseWriter, r *http.Request, runID string) {
	st := s.remoteManageStore()
	reconcileStaleArena(r.Context(), st)
	rn, err := st.ArenaRun(r.Context(), runID)
	if err != nil {
		writeErr(w, err)
		return
	}
	if rn == nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	cands, err := st.ArenaCandidates(r.Context(), runID)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, runJSON(*rn, cands))
}

// handleArenaRunDiff serves the stored patch text for one candidate — read
// from disk under the run directory, never from the DB.
func (s *Server) handleArenaRunDiff(w http.ResponseWriter, r *http.Request, runID, candID string) {
	st := s.remoteManageStore()
	cands, err := st.ArenaCandidates(r.Context(), runID)
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, c := range cands {
		if c.ID != candID {
			continue
		}
		if c.PatchPath == "" {
			writeJSON(w, map[string]any{"patch": ""})
			return
		}
		expected := filepath.Join(arenaWorkspaceDir(), c.RunID, c.Tool+".patch")
		patch, err := readArenaPatch(c.PatchPath, expected)
		if err != nil {
			http.Error(w, "candidate patch is unavailable", http.StatusConflict)
			return
		}
		writeJSON(w, map[string]any{"patch": string(patch)})
		return
	}
	http.Error(w, "candidate not found", http.StatusNotFound)
}

func readArenaPatch(recorded, expected string) ([]byte, error) {
	recorded = filepath.Clean(recorded)
	expected = filepath.Clean(expected)
	if recorded == "." || recorded != expected {
		return nil, errors.New("arena patch path does not match its run artifact")
	}
	pathInfo, err := os.Lstat(expected)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("arena patch is not a regular file")
	}
	f, err := os.Open(expected)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return nil, errors.New("arena patch changed while opening")
	}
	return io.ReadAll(f)
}

// handleArenaCandidateAction performs keep/discard on one candidate. Keep
// requires the judged state and merges onto the project branch (squash by
// default); discard prunes worktree + branch.
func (s *Server) handleArenaCandidateAction(w http.ResponseWriter, r *http.Request, runID, candID string) {
	if !requireConfirmToken(w, r) {
		return
	}
	var req struct {
		Action   string `json:"action"` // keep | discard
		Strategy string `json:"strategy,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request body: "+err.Error(), http.StatusBadRequest)
		return
	}
	runner, err := s.newArenaRunner()
	if err != nil {
		writeErr(w, err)
		return
	}
	st := s.remoteManageStore()
	rn, err := st.ArenaRun(r.Context(), runID)
	if err != nil || rn == nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	if rn.Status != models.ArenaRunStatusComplete && rn.Status != models.ArenaRunStatusFailed {
		http.Error(w, "arena run is still active; wait for judging to finish before keep or discard", http.StatusConflict)
		return
	}
	arenaMu.Lock()
	if arenaActionInFlight[rn.ProjectRoot] {
		arenaMu.Unlock()
		http.Error(w, "another arena action is already mutating this project", http.StatusConflict)
		return
	}
	arenaActionInFlight[rn.ProjectRoot] = true
	arenaMu.Unlock()
	defer func() {
		arenaMu.Lock()
		delete(arenaActionInFlight, rn.ProjectRoot)
		arenaMu.Unlock()
	}()
	cands, err := st.ArenaCandidates(r.Context(), runID)
	if err != nil {
		writeErr(w, err)
		return
	}
	for i := range cands {
		if cands[i].ID != candID {
			continue
		}
		row := cands[i]
		switch strings.ToLower(req.Action) {
		case "keep":
			var strategy arena.KeepStrategy
			switch strings.ToLower(strings.TrimSpace(req.Strategy)) {
			case "", string(arena.KeepSquash):
				strategy = arena.KeepSquash
			case string(arena.KeepJudgeMerge):
				strategy = arena.KeepJudgeMerge
			default:
				http.Error(w, "strategy must be squash or judge_merge", http.StatusBadRequest)
				return
			}
			var judge []arena.JudgeSpec
			if strategy == arena.KeepJudgeMerge {
				judge = []arena.JudgeSpec{{Tool: rn.JudgeTool, Model: rn.JudgeModel}}
			}
			sha, err := runner.Keep(r.Context(), &row, rn.ProjectRoot, strategy, judge...)
			if err != nil {
				writeArenaErr(w, err)
				return
			}
			writeJSON(w, map[string]any{"kept_commit_sha": sha})
		case "discard":
			if err := runner.DiscardCandidate(r.Context(), row, rn.ProjectRoot); err != nil {
				writeArenaErr(w, err)
				return
			}
			writeJSON(w, map[string]any{"discarded": row.ID})
		default:
			http.Error(w, "action must be keep or discard", http.StatusBadRequest)
		}
		return
	}
	http.Error(w, "candidate not found", http.StatusNotFound)
}
