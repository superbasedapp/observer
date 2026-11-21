//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrules"
	"github.com/marmutapp/superbased-observer/internal/secsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_scan_now.go serves the Code security page's "Scan now": GET
// /api/security/scan (the scanners this node can run, the current or last
// job, and the confirm token) and POST {project: <root hash>} | {projects:
// [<root hash>...]} | {all: true}, each with an optional steps: [<scanner
// id>...] and an optional online: true, or {cancel: true}. A job runs the
// chosen scanners (every ready one when steps is empty or absent) on each
// target project in turn, in
// the background, one job at a time; each scanner run is its CLI verb's
// own manual run (Options.SecurityScanNow), plus the bounded
// secrets-in-history scan this package already serves
// (/api/security/scan-history). An unknown scanner id, or a named scanner
// that is not ready, refuses the whole request (400), so a job never
// silently skips what the person chose. Owner-local with the confirm
// token: it runs scanners on this machine and writes findings.
//
// online (decision P-1 of docs/plans/dashboard-cli-parity-plan-2026-11-06.md)
// asks the dependency step to also match online, as `observer security
// scan --online` does: the GET's online block is that check's state (the
// gate the CLI walks: online checks on and their disclosure accepted, and
// the linked driver), and a request asking for it while the gate is closed,
// or without the step it applies to, is refused (400). It reads the
// consent the person already gave on Scanners > Package checks and gives
// none, so it carries no agent self-approval pin of its own (the CLI's
// --online has none either); a project whose own section forbids online
// checks runs local, and its step result says so.

// securityScanHistoryStep is the dashboard's own step: the bounded history
// scan of secsvc.ScanHistory.
const securityScanHistoryStep = "history"

// securityScanStepsTTL is how long the scanners list is reused: each ready
// check opens its scanner's env.
const securityScanStepsTTL = 30 * time.Second

// securityScanJobLimit bounds one job; a cancel stops it sooner.
const securityScanJobLimit = 2 * time.Hour

// securityScanHistoryDeadline is the history step's per-project deadline
// (the same 30 seconds the Findings tab's own history button uses).
const securityScanHistoryDeadline = 30 * time.Second

// securityScanView is GET /api/security/scan. Online is the online
// dependency check's state (absent where this build offers none).
type securityScanView struct {
	ConfirmToken string                      `json:"confirm_token"`
	Steps        []dashapi.SecurityScanStep  `json:"steps"`
	Online       *dashapi.SecurityScanOnline `json:"online,omitempty"`
	Job          *securityScanJobJS          `json:"job"`
}

// The POST body's bounds: the body itself, the projects one request may
// name and the scanners it may choose.
const (
	securityScanBodyMax     = 128 << 10
	securityScanMaxProjects = 1024
	securityScanMaxSteps    = 64
)

// securityScanRequest is the POST body: exactly one of Project, Projects
// and All; Steps empty is every ready scanner; Online asks the dependency
// step to also match online (default false).
type securityScanRequest struct {
	Project  string   `json:"project"`
	Projects []string `json:"projects"`
	All      bool     `json:"all"`
	Steps    []string `json:"steps"`
	Online   bool     `json:"online"`
	Cancel   bool     `json:"cancel"`
}

// securityScanTargetCount is how many of the request's target forms are
// set (exactly one is valid).
func securityScanTargetCount(req securityScanRequest) int {
	n := 0
	for _, set := range []bool{req.Project != "", len(req.Projects) > 0, req.All} {
		if set {
			n++
		}
	}
	return n
}

// securityScanTarget is one project a job scans.
type securityScanTarget struct {
	hash string
	root string
	id   int64
	name string
}

// errSecurityScanRunning refuses a second job.
var errSecurityScanRunning = errors.New("a scan is already running: wait for it, or cancel it")

func (s *Server) handleSecurityScan(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		view := securityScanView{ConfirmToken: setConfirmCookie(w, r), Steps: s.securityScanSteps(r.Context()), Online: s.securityScanOnline(r.Context(), false)}
		s.secScan.mu.Lock()
		if s.secScan.job != nil {
			// Copied under the lock: the job's goroutine writes it.
			b, _ := json.Marshal(s.secScan.job)
			var j securityScanJobJS
			_ = json.Unmarshal(b, &j)
			view.Job = &j
		}
		s.secScan.mu.Unlock()
		writeJSON(w, view)
	case http.MethodPost:
		if !requireJSONConfirm(w, r) {
			return
		}
		var req securityScanRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityScanBodyMax)).Decode(&req); err != nil {
			http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Cancel {
			s.secScan.mu.Lock()
			if s.secScan.cancel != nil {
				s.secScan.cancel()
			}
			s.secScan.mu.Unlock()
			writeJSON(w, map[string]bool{"ok": true})
			return
		}
		if securityScanTargetCount(req) != 1 {
			http.Error(w, "name one project, a list of projects, or all", http.StatusBadRequest)
			return
		}
		if len(req.Projects) > securityScanMaxProjects {
			http.Error(w, fmt.Sprintf("too many projects: at most %d", securityScanMaxProjects), http.StatusBadRequest)
			return
		}
		if len(req.Steps) > securityScanMaxSteps {
			http.Error(w, fmt.Sprintf("too many scanners: at most %d", securityScanMaxSteps), http.StatusBadRequest)
			return
		}
		all := s.securityScanSteps(r.Context())
		steps, err := securityScanChosenSteps(all, req.Steps)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Online {
			// Read fresh: the person may have just accepted the disclosure.
			if err := securityScanOnlineAllowed(s.securityScanOnline(r.Context(), true), all, steps); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		targets, err := s.securityScanTargets(r.Context(), req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		job, err := s.startSecurityScan(targets, req.All, steps, dashapi.SecurityScanOptions{Online: req.Online})
		if errors.Is(err, errSecurityScanRunning) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		writeJSON(w, job)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// securityScanSteps is the scanners list: the seam's rows (cached) and the
// history step.
func (s *Server) securityScanSteps(ctx context.Context) []dashapi.SecurityScanStep {
	s.secScan.mu.Lock()
	cached, at := s.secScan.steps, s.secScan.stepsAt
	s.secScan.mu.Unlock()
	if cached == nil || time.Since(at) > securityScanStepsTTL {
		cached = []dashapi.SecurityScanStep{{ID: securityScanHistoryStep, Label: "Secrets in recent commits", Ready: true}}
		if sn := s.opts.SecurityScanNow; sn != nil && sn.Steps != nil {
			cached = append(cached, sn.Steps(ctx)...)
		}
		s.secScan.mu.Lock()
		s.secScan.steps, s.secScan.stepsAt = cached, time.Now()
		s.secScan.mu.Unlock()
	}
	return append([]dashapi.SecurityScanStep(nil), cached...)
}

// securityScanOnlineTTL is how long the GET reuses the online check's
// state (each read loads the config and the disclosure record); a POST
// asking for online checks always reads it fresh.
const securityScanOnlineTTL = 5 * time.Second

// securityScanOnline is the online dependency check's state from the seam,
// nil where this build offers none. fresh skips the GET's short cache.
func (s *Server) securityScanOnline(ctx context.Context, fresh bool) *dashapi.SecurityScanOnline {
	sn := s.opts.SecurityScanNow
	if sn == nil || sn.Online == nil {
		return nil
	}
	s.secScan.mu.Lock()
	cached, at := s.secScan.online, s.secScan.onlineAt
	s.secScan.mu.Unlock()
	if !fresh && cached != nil && time.Since(at) <= securityScanOnlineTTL {
		c := *cached
		return &c
	}
	st := sn.Online(ctx)
	s.secScan.mu.Lock()
	s.secScan.online, s.secScan.onlineAt = &st, time.Now()
	s.secScan.mu.Unlock()
	out := st
	return &out
}

// securityScanOnlineAllowed refuses a request for online checks the node
// cannot honour, walked top-down: no online check in this build, its gate
// closed (the reason the dialog shows), or the step it applies to not
// among the steps the job runs. It never lets a job claim online checks
// it will not run.
func securityScanOnlineAllowed(online *dashapi.SecurityScanOnline, all, chosen []dashapi.SecurityScanStep) error {
	if online == nil {
		return errors.New("online checks are not available in this build")
	}
	if !online.Open {
		reason := online.Reason
		if reason == "" {
			reason = "closed"
		}
		return fmt.Errorf("online checks are not allowed on this node: %s (turn them on in Code security > Scanners > Package checks)", reason)
	}
	for _, st := range chosen {
		if st.ID == online.Step {
			return nil
		}
	}
	label := online.Step
	for _, st := range all {
		if st.ID == online.Step && st.Label != "" {
			label = st.Label
		}
	}
	return fmt.Errorf("online checks run with the %s scanner: choose it too", label)
}

// securityScanChosenSteps resolves the request's scanner ids against the
// scanners list: none chosen is every ready scanner (the behaviour before
// the choice existed); otherwise each id must name a listed scanner that
// is ready, and the job runs them in the list's order (the cheap checks
// first), each once.
func securityScanChosenSteps(all []dashapi.SecurityScanStep, chosen []string) ([]dashapi.SecurityScanStep, error) {
	if len(chosen) == 0 {
		var ready []dashapi.SecurityScanStep
		for _, st := range all {
			if st.Ready {
				ready = append(ready, st)
			}
		}
		return ready, nil
	}
	byID := map[string]dashapi.SecurityScanStep{}
	for _, st := range all {
		byID[st.ID] = st
	}
	want := map[string]bool{}
	for _, id := range chosen {
		st, ok := byID[id]
		if !ok {
			return nil, fmt.Errorf("unknown scanner: %s", id)
		}
		if !st.Ready {
			reason := st.Reason
			if reason == "" {
				reason = "not ready"
			}
			return nil, fmt.Errorf("%s is not ready: %s", st.Label, reason)
		}
		want[id] = true
	}
	var out []dashapi.SecurityScanStep
	for _, st := range all {
		if want[st.ID] {
			out = append(out, st)
		}
	}
	return out, nil
}

// securityScanTargets resolves the request to the projects to scan: the
// one named project, each named project (in the order named, each once),
// or every active project whose root is a folder here. A hash no stored
// project names refuses the request.
func (s *Server) securityScanTargets(ctx context.Context, req securityScanRequest) ([]securityScanTarget, error) {
	st := store.New(s.db())
	index, err := securityProjectIndex(ctx, st)
	if err != nil {
		return nil, err
	}
	if !req.All {
		hashes := req.Projects
		if req.Project != "" {
			hashes = []string{req.Project}
		}
		var out []securityScanTarget
		seen := map[string]bool{}
		for _, hash := range hashes {
			if seen[hash] {
				continue
			}
			seen[hash] = true
			ref, ok := index[hash]
			if !ok {
				return nil, errors.New("unknown project")
			}
			out = append(out, securityScanTarget{hash: hash, root: ref.Root, id: ref.ID, name: securityProjectName(ref)})
		}
		return out, nil
	}
	roots, err := st.SecActiveProjectRoots(ctx, time.Now().Add(-secsvc.DefaultActiveWithin))
	if err != nil {
		return nil, err
	}
	var out []securityScanTarget
	for _, root := range roots {
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			continue
		}
		hash := secposture.ProjectRootHash(root)
		t := securityScanTarget{hash: hash, root: root, name: root}
		if ref, ok := index[hash]; ok {
			t.id, t.name = ref.ID, securityProjectName(ref)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, errors.New("no active project is a folder on this machine")
	}
	return out, nil
}

// startSecurityScan starts a job running steps over targets under opts,
// refusing while one runs. Its scope is "all" for every active project or
// for a picked set of more than one, "project" for one project.
func (s *Server) startSecurityScan(targets []securityScanTarget, all bool, steps []dashapi.SecurityScanStep, opts dashapi.SecurityScanOptions) (*securityScanJobJS, error) {
	id, err := newJobID()
	if err != nil {
		return nil, fmt.Errorf("generate job id: %w", err)
	}
	s.secScan.mu.Lock()
	defer s.secScan.mu.Unlock()
	if s.secScan.job != nil && s.secScan.job.State == securityScanRunning {
		return nil, errSecurityScanRunning
	}
	scope := "project"
	if all || len(targets) > 1 {
		scope = "all"
	}
	ids := make([]string, 0, len(steps))
	for _, st := range steps {
		ids = append(ids, st.ID)
	}
	job := &securityScanJobJS{
		ID: id, State: securityScanRunning, Scope: scope, StartedAt: time.Now().UTC().Format(time.RFC3339),
		Total: len(targets), Steps: ids, Online: opts.Online, Projects: []securityScanProjectJS{},
	}
	ctx, cancel := context.WithTimeout(context.Background(), securityScanJobLimit)
	s.secScan.job, s.secScan.cancel = job, cancel
	go s.runSecurityScan(ctx, cancel, job, targets, steps, opts)
	snapshot := *job
	return &snapshot, nil
}

// runSecurityScan is the job: each target, each chosen step, in order,
// each step's start and duration recorded on its result.
func (s *Server) runSecurityScan(ctx context.Context, cancel context.CancelFunc, job *securityScanJobJS, targets []securityScanTarget, steps []dashapi.SecurityScanStep, opts dashapi.SecurityScanOptions) {
	defer cancel()
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		s.secScan.mu.Lock()
		job.Projects = append(job.Projects, securityScanProjectJS{ProjectRootHash: t.hash, ProjectID: t.id, Name: t.name, Steps: []dashapi.SecurityScanResult{}})
		at := len(job.Projects) - 1
		s.secScan.mu.Unlock()
		for _, step := range steps {
			if !step.Ready {
				continue
			}
			if ctx.Err() != nil {
				break
			}
			started := time.Now()
			s.secScan.mu.Lock()
			job.Current = &securityScanCurrentJS{
				ProjectRootHash: t.hash, Name: t.name, Step: step.Label, StepID: step.ID,
				StartedAt: started.UTC().Format(time.RFC3339),
			}
			s.secScan.mu.Unlock()
			res := s.runSecurityScanStep(ctx, t.root, step, opts)
			res.StartedAt, res.DurationMS = started.UTC().Format(time.RFC3339), time.Since(started).Milliseconds()
			s.secScan.mu.Lock()
			job.Projects[at].Steps = append(job.Projects[at].Steps, res)
			s.secScan.mu.Unlock()
		}
		s.secScan.mu.Lock()
		job.Done++
		s.secScan.mu.Unlock()
	}
	s.secScan.mu.Lock()
	job.Current = nil
	job.State = securityScanDone
	if ctx.Err() != nil {
		// Cancelled (or past securityScanJobLimit): the step it was on
		// reported its own outcome, the rest never ran.
		job.State = securityScanCancelled
	}
	job.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	s.secScan.cancel = nil
	s.secScan.mu.Unlock()
}

// runSecurityScanStep runs one step on one project under the job's options.
func (s *Server) runSecurityScanStep(ctx context.Context, root string, step dashapi.SecurityScanStep, opts dashapi.SecurityScanOptions) dashapi.SecurityScanResult {
	if step.ID != securityScanHistoryStep {
		sn := s.opts.SecurityScanNow
		if sn == nil || sn.Scan == nil {
			return dashapi.SecurityScanResult{ID: step.ID, Label: step.Label, Outcome: dashapi.SecurityScanSkipped, Reason: "not in this process"}
		}
		res := sn.Scan(ctx, root, step.ID, opts)
		res.ID, res.Label = step.ID, step.Label
		return res
	}
	out := dashapi.SecurityScanResult{ID: step.ID, Label: step.Label}
	if _, ok := git.FindCheckoutRoot(root); !ok {
		out.Outcome, out.Reason = dashapi.SecurityScanSkipped, "not a git repository"
		return out
	}
	resolved, err := config.ResolveGlobalPath(s.opts.ConfigPath)
	if err != nil {
		out.Outcome, out.Reason = "failed", err.Error()
		return out
	}
	res, err := secsvc.ScanHistory(ctx, secsvc.LocalHistoryDeps(resolved, secrules.PackVersion, store.New(s.db())), root,
		secsvc.HistoryOptions{Deadline: securityScanHistoryDeadline})
	if err != nil {
		out.Outcome, out.Reason = "failed", err.Error()
		return out
	}
	out.Findings, out.New = res.Hits, res.NewFindings
	switch {
	case !res.Complete():
		out.Outcome = "unknown"
		out.Reason = fmt.Sprintf("%d commit(s) read; %d could not be judged, %d not reached", res.Commits, res.Unknown, res.Remaining)
	case res.Hits > 0:
		out.Outcome = "findings"
	default:
		out.Outcome = "clean"
	}
	return out
}
