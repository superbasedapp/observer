package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/guardrecipesvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// GUARD SIMULATION RUNS (demo bug #14, 2026-11-10).
//
// GET /api/guard/simulate replays captured history against the policy. A
// week on a busy node is ~40,000 actions, evaluated once for the plain replay
// and three times for a recipe comparison (as-is, before, after). Measured on
// the demo node it took 582 s, the browser showed only a disabled button, and
// two identical replays (the same click from two tabs, or a click and a
// retry) each ran in full, one after the other.
//
// Three changes, each in its own place:
//
//   - the evaluation is fast: the guards share one filesystem memo
//     (guard.ReplayFS), the policy engine's path normalizer has a no-allocation
//     fast path, and the evaluations run side by side;
//   - identical requests share ONE run: a run is keyed by the canonical
//     query plus the config file's identity, and every request with that key
//     waits on (or reads) the same run. A finished run's answer is kept for
//     simulateResultKeep, so a repeat click answers at once;
//   - progress is visible: `progress=1` answers 202 with the run's
//     evaluated/total counts while it runs (starting it if needed) and the
//     result once it is done, so the page can poll and draw a bar.
//
// A run belongs to nobody: it stops when nothing is waiting on it and nobody
// has polled it for simulateAbandonAfter (a closed tab), and a run whose only
// caller was a plain request that went away stops at once - the guarantee the
// route had when every request ran its own replay (sweep finding UI-3).

// simulateResultKeep is how long a finished run answers identical requests.
const simulateResultKeep = 2 * time.Minute

// simulateAbandonAfter is how long a run with no waiting request survives
// without a progress poll.
const simulateAbandonAfter = 20 * time.Second

// simulateReplayCap is the most captured actions one run replays.
const simulateReplayCap = 50000

// simulateParams is one parsed simulate query.
type simulateParams struct {
	hours   int
	enforce bool
	recipe  *guardRecipeQuery
}

// key is the run key: every field that changes the answer, in a fixed order,
// plus the config file's identity (a saved policy edit is a different run).
func (p simulateParams) key(owner any, configPath string) string {
	// owner (the dashboard server) and the path keep two dashboards in one
	// process (tests) from reading each other's runs.
	parts := []string{fmt.Sprintf("owner=%p", owner), "config=" + configPath, "hours=" + strconv.Itoa(p.hours), "enforce=" + strconv.FormatBool(p.enforce)}
	if p.recipe != nil {
		packs := append([]string(nil), p.recipe.req.Packs...)
		sort.Strings(packs)
		parts = append(parts, "recipe=1",
			"remove="+strconv.FormatBool(p.recipe.remove),
			"level="+p.recipe.req.Level,
			"packs="+strings.Join(packs, ","),
			"scope="+string(p.recipe.req.Scope),
			"root="+p.recipe.req.ProjectRoot)
	}
	if configPath != "" {
		if fi, err := os.Stat(configPath); err == nil {
			parts = append(parts, fmt.Sprintf("stat=%d.%d", fi.ModTime().UnixNano(), fi.Size()))
		}
	}
	return strings.Join(parts, "&")
}

// simulateRun is one replay shared by every request with its key.
type simulateRun struct {
	key     string
	started time.Time
	cancel  context.CancelFunc
	done    chan struct{}

	// Progress, read lock-free by polls.
	queued    atomic.Bool
	actions   atomic.Int64
	evaluated atomic.Int64
	total     atomic.Int64

	// Guarded by simulateRuns.mu.
	waiters  int
	lastPoll time.Time

	// Written once before done is closed.
	status      int
	body        []byte
	contentType string
	finishedAt  time.Time
}

// simulateRunRegistry holds the runs in progress and the recently finished.
type simulateRunRegistry struct {
	mu   sync.Mutex
	runs map[string]*simulateRun
}

var simulateRuns = &simulateRunRegistry{runs: map[string]*simulateRun{}}

// simulateRunsStarted counts runs ever started in this process (tests read
// it to prove identical requests share one run).
var simulateRunsStarted atomic.Int64

// finished reports whether the run has an answer.
func (run *simulateRun) finished() bool {
	select {
	case <-run.done:
		return true
	default:
		return false
	}
}

// acquire returns the live or still-fresh run for key, or starts one with
// start. joined reports an existing run (the dedupe the route lacked). A
// waiting request (wait=true) is counted until it calls leave; a poll
// refreshes the run's lastPoll instead.
func (reg *simulateRunRegistry) acquire(key string, wait bool, now time.Time, start func(ctx context.Context, run *simulateRun)) (run *simulateRun, joined bool) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	for k, r := range reg.runs {
		if r.finished() && now.Sub(r.finishedAt) > simulateResultKeep {
			delete(reg.runs, k)
		}
	}
	run, joined = reg.runs[key]
	if !joined {
		ctx, cancel := context.WithCancel(context.Background())
		run = &simulateRun{key: key, started: now, cancel: cancel, done: make(chan struct{})}
		reg.runs[key] = run
		simulateRunsStarted.Add(1)
		go start(ctx, run)
	}
	if wait {
		run.waiters++
	} else {
		run.lastPoll = now
	}
	return run, joined
}

// leave drops one waiting request and stops the run when nothing else wants
// it: no other waiter and no poll within simulateAbandonAfter.
func (reg *simulateRunRegistry) leave(run *simulateRun, now time.Time) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	run.waiters--
	reg.abandonLocked(run, now)
}

// sweep stops every unfinished run nobody wants any more. The run's own
// watchdog calls it.
func (reg *simulateRunRegistry) sweep(run *simulateRun, now time.Time) {
	reg.mu.Lock()
	defer reg.mu.Unlock()
	reg.abandonLocked(run, now)
}

func (reg *simulateRunRegistry) abandonLocked(run *simulateRun, now time.Time) {
	if run.finished() || run.waiters > 0 {
		return
	}
	if !run.lastPoll.IsZero() && now.Sub(run.lastPoll) <= simulateAbandonAfter {
		return
	}
	run.cancel()
	// Gone from the registry at once, so the next identical request starts
	// a fresh run rather than joining a stopped one.
	if reg.runs[run.key] == run {
		delete(reg.runs, run.key)
	}
}

// finish records the run's answer and wakes every waiter.
func (run *simulateRun) finish(status int, contentType string, body []byte) {
	run.status, run.contentType, run.body = status, contentType, body
	run.finishedAt = time.Now()
	close(run.done)
}

// finishJSON records a JSON answer.
func (run *simulateRun) finishJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		run.finishError(http.StatusInternalServerError, err.Error())
		return
	}
	run.finish(http.StatusOK, "application/json", b)
}

// finishError records an http.Error-shaped answer.
func (run *simulateRun) finishError(status int, msg string) {
	run.finish(status, "text/plain; charset=utf-8", []byte(msg+"\n"))
}

// write serves the run's answer.
func (run *simulateRun) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", run.contentType)
	// nosniff on every answer, the JSON one too: a browser must never
	// render the body as anything but its declared type.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(run.status)
	_, _ = w.Write(run.body) //nolint:gosec // G705: the body is the run's own JSON encoding or plain-text error, served with its declared Content-Type and nosniff to the local dashboard; never HTML.
}

// simulateProgress is the 202 body of a progress poll while a run works.
type simulateProgress struct {
	Running bool `json:"running"`
	// Queued is true while the run waits for another (different) replay to
	// finish: one replay evaluates at a time per daemon.
	Queued bool `json:"queued"`
	// Actions is how many captured actions the run replays (0 until they
	// are loaded).
	Actions int64 `json:"actions"`
	// Evaluated and Total count action evaluations: every action once per
	// policy the run compares (one for a plain replay, three for a recipe
	// comparison).
	Evaluated int64 `json:"evaluated"`
	Total     int64 `json:"total"`
	ElapsedMS int64 `json:"elapsed_ms"`
}

func (run *simulateRun) progress(now time.Time) simulateProgress {
	return simulateProgress{
		Running: true, Queued: run.queued.Load(),
		Actions: run.actions.Load(), Evaluated: run.evaluated.Load(), Total: run.total.Load(),
		ElapsedMS: now.Sub(run.started).Milliseconds(),
	}
}

// parseSimulateParams reads one simulate query. A recipe selection is parsed
// here, on the request, so a bad level or an unknown project root answers
// before any run starts.
func (s *Server) parseSimulateParams(r *http.Request) (simulateParams, int, error) {
	q := r.URL.Query()
	p := simulateParams{hours: 168}
	if v, err := strconv.Atoi(q.Get("hours")); err == nil && v >= 1 && v <= 2160 {
		p.hours = v
	}
	p.enforce = q.Get("enforce") == "1" || strings.EqualFold(q.Get("enforce"), "true")
	if q.Get("recipe") == "1" {
		sel, status, err := s.parseGuardRecipeQuery(r)
		if err != nil {
			return p, status, err
		}
		p.recipe = &sel
	}
	return p, 0, nil
}

// handleGuardSimulate serves GET /api/guard/simulate?hours=&enforce=
// [&recipe=1&level=&packs=&scope=&project_root=&remove=][&progress=1] - the
// dashboard face of `observer guard simulate` (G1.2): replay captured history
// against the CURRENT on-disk policy with fresh engines. Nothing persists; the
// live guard state is untouched. The mode-control consent dialog calls it with
// enforce=1 to show "what would last week have BLOCKED" before the operator
// promotes.
//
// Policy source: the config FILE (loadConfigForDashboard), not the running
// daemon's bound config, so a saved-but-not-yet-restarted policy edit is what
// gets simulated.
//
// Runs are shared and observable (see the file comment): a plain request waits
// for its run's answer; progress=1 answers 202 with the run's progress until
// the answer exists. A browser request another site started (Sec-Fetch-Site:
// cross-site, which an <img> carries with no Origin and no Referer) is refused.
func (s *Server) handleGuardSimulate(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		http.Error(w, "a guard simulation is not started from another site", http.StatusForbidden)
		return
	}
	ctx := r.Context()
	if simulateGone(ctx, w) {
		return
	}
	params, status, err := s.parseSimulateParams(r)
	if err != nil {
		http.Error(w, err.Error(), status)
		return
	}
	poll := r.URL.Query().Get("progress") == "1"
	run, _ := simulateRuns.acquire(params.key(s, s.opts.ConfigPath), !poll, time.Now(), func(runCtx context.Context, run *simulateRun) {
		s.runGuardSimulate(runCtx, run, params)
	})
	if poll {
		if run.finished() {
			run.write(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(run.progress(time.Now()))
		return
	}
	select {
	case <-run.done:
		simulateRuns.leave(run, time.Now())
		run.write(w)
	case <-ctx.Done():
		simulateRuns.leave(run, time.Now())
		simulateGone(ctx, w)
	}
}

// runGuardSimulate is one run: wait for the evaluation slot, load the window,
// evaluate it under every policy the query compares, and record the answer.
func (s *Server) runGuardSimulate(ctx context.Context, run *simulateRun, p simulateParams) {
	defer run.cancel()
	// The watchdog stops the run once nothing wants it (a closed tab that
	// was polling); leave() covers waiting requests directly.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-run.done:
				return
			case <-ctx.Done():
				return
			case now := <-t.C:
				simulateRuns.sweep(run, now)
			}
		}
	}()
	stopped := func() bool {
		if ctx.Err() != nil {
			run.finishError(http.StatusServiceUnavailable, "the guard simulation stopped: nothing was waiting for it")
			return true
		}
		return false
	}
	run.queued.Store(true)
	release, err := acquireGuardSimulateSlot(ctx)
	run.queued.Store(false)
	if err != nil {
		run.finishError(http.StatusServiceUnavailable, "another guard simulation is running; try again when it finishes")
		return
	}
	defer release()

	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		run.finishError(http.StatusInternalServerError, fmt.Sprintf("load config: %v", err))
		return
	}
	mode := cfg.Guard.Mode
	if p.enforce {
		mode = "enforce"
		cfg.Guard.Mode = "enforce"
	}
	st := store.New(s.opts.DB)
	home, _ := os.UserHomeDir()
	roots, _ := st.ProjectRoots(ctx)
	// One filesystem memo for every guard this run builds: they judge the
	// same actions against the same filesystem.
	rfs := guard.NewReplayFS()
	g, err := guard.New(guard.Options{Config: cfg.Guard, Home: home, KnownProjectRoots: roots, ReplayFS: rfs})
	if err != nil {
		run.finishError(http.StatusInternalServerError, fmt.Sprintf("construct guard: %v", err))
		return
	}
	inputs, err := st.LoadGuardReplayInputs(ctx, s.now().Add(-time.Duration(p.hours)*time.Hour), simulateReplayCap)
	if err != nil {
		if stopped() {
			return
		}
		run.finishError(http.StatusInternalServerError, err.Error())
		return
	}
	if stopped() {
		return
	}
	evaluations := int64(1)
	if p.recipe != nil {
		evaluations = 3
	}
	run.actions.Store(int64(len(inputs)))
	run.total.Store(int64(len(inputs)) * evaluations)

	// Every evaluation counts its chunks into the run's progress and stops
	// between chunks once the run is stopped.
	eval := func(gg *guard.Guard, in []guard.ActionInput) []guard.ActionVerdict {
		out, _ := evaluateWithProgress(ctx, in, guardSimulateChunk, gg.EvaluateActions, func(n int) {
			run.evaluated.Add(int64(n))
		})
		return out
	}

	// The as-is replay and the recipe comparison share nothing but the
	// read-only inputs (each guard gets its own copy), so they run side by
	// side.
	var (
		wg           sync.WaitGroup
		verdicts     []guard.ActionVerdict
		recipeReplay *guardrecipesvc.Replay
		rstatus      int
		rerr         error
	)
	if p.recipe != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recipeReplay, rstatus, rerr = s.guardRecipeReplay(ctx, *p.recipe, inputs, rfs, eval)
		}()
	}
	verdicts = eval(g, append([]guard.ActionInput(nil), inputs...))
	wg.Wait()
	if stopped() {
		return
	}
	if rerr != nil {
		run.finishError(rstatus, rerr.Error())
		return
	}

	byRule := map[string]int{}
	byRuleBlocking := map[string]int{}
	byDecision := map[string]int{}
	wouldBlock := 0
	for _, v := range verdicts {
		byRule[v.Verdict.RuleID]++
		dec := v.Verdict.Decision.String()
		byDecision[dec]++
		if mode == "enforce" && (dec == "deny" || dec == "ask") {
			wouldBlock++
			byRuleBlocking[v.Verdict.RuleID]++
		}
	}
	resp := map[string]any{
		"window_hours": p.hours,
		"mode":         mode,
		"scanned":      len(inputs),
		"verdicts":     len(verdicts),
		"would_block":  wouldBlock,
		"capped":       len(inputs) == simulateReplayCap,
		"by_rule":      byRule,
		// by_rule_blocking splits would_block per rule (G2.1): only
		// deny/ask-class verdicts under the enforce projection, so the
		// readiness review ranks rules by what would actually block —
		// by_rule alone conflates flag-only noise with blocking load.
		"by_rule_blocking": byRuleBlocking,
		"by_decision":      byDecision,
		// When the run finished and how long it took: identical requests
		// within simulateResultKeep read this same answer.
		"computed_at": time.Now().UTC().Format(time.RFC3339),
		"elapsed_ms":  time.Since(run.started).Milliseconds(),
	}
	if recipeReplay != nil {
		resp["recipe_replay"] = recipeReplay
	}
	run.finishJSON(resp)
}
