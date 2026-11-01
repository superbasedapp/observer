//go:build !sbo_omit_benchmark

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/benchmark"
	"github.com/marmutapp/superbased-observer/internal/scrub"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// benchmark_run.go is the runner (plan §3.2): it drives each (task × config ×
// repeat) cell through an injectable HarnessDriver, correlates the produced
// session(s) to the attempt, accounts billed spend against the budget caps,
// and persists ledger rows — including failures with machine-readable reasons.
// os/exec for harness-driving lives in the driver, not here.

// workspaceProvisioner materializes a fresh, isolated repo checkout for one
// attempt (plan §3.9). The real impl clones repo@ref + runs setup; a fake makes
// a temp dir so the runner is unit-testable without git or the network.
type workspaceProvisioner interface {
	Provision(ctx context.Context, task benchmark.Task, attemptDir string) (workspacePath string, err error)
}

// homePreparer sets up an attempt's isolated HOME/CODEX_HOME — for codex it
// copies ~/.codex/auth.json in and writes a config.toml pointing base_url at the
// proxy (plan §3.9 / spike finding: a fresh CODEX_HOME has no credentials).
type homePreparer interface {
	Prepare(ctx context.Context, harness, homeDir, proxyURL string) error
}

// attemptScorer scores a completed attempt (implemented in P4). A nil scorer
// records attempts without scores (Scored=false) — never a silent pass.
type attemptScorer interface {
	Score(ctx context.Context, in scoreInput) ([]benchmark.ScoreRecord, error)
}

// scoreInput is one attempt's scoring context.
type scoreInput struct {
	Task         benchmark.Task
	Config       benchmark.Config
	AttemptID    int64
	RunID        string
	WorkspaceDir string
	FinalAnswer  string
	Status       benchmark.Status
}

// preflightDriver lets a driver reject a harness BEFORE any spend (the
// claude-code stub uses it to fail the run early, naming the re-spike gate).
type preflightDriver interface{ Preflight() error }

// RunOptions parameterize one benchmark run invocation.
type RunOptions struct {
	// DryRun prints the cost estimate + plan and persists NOTHING. The CLI
	// defaults this true; only --confirm-spend flips it off (plan §3.7 gate).
	DryRun bool
	// Confirmed is the operator's explicit spend confirmation (--confirm-spend).
	// Required to spend when the spec's [budget].require_confirm is set.
	Confirmed       bool
	ProxyURL        string
	RootDir         string // scratch root for per-attempt workspaces
	ObserverVersion string
	ProxyVersion    string
	// KeepWorkspaces retains EVERY per-attempt workspace (not just failed ones)
	// for inspection (#11). Failed attempts are always retained regardless.
	KeepWorkspaces bool
	// AllowUnpriced permits spending even when a config's model has no billed
	// history to estimate cost from (#5). Without it, an unknown-price cell
	// refuses to spend rather than presenting a false $0.00 estimate.
	AllowUnpriced bool
	// ResolveAttempts / ResolveDelay tune the async-finalization poll (ingestion
	// lags harness exit — spike Q1).
	ResolveAttempts int
	ResolveDelay    time.Duration
}

// benchmarkRunner orchestrates a run. All I/O boundaries are injected so the
// end-to-end runner test uses a fake driver + provisioner (no real sessions).
type benchmarkRunner struct {
	store       *store.Store
	drivers     map[string]HarnessDriver
	provisioner workspaceProvisioner
	homePrep    homePreparer
	scorer      attemptScorer
	scrubber    *scrub.Scrubber
	// estimateTurnUSD returns the historical per-turn cost for a model and
	// whether that price is KNOWN (ok=false ⇒ no billed history — must never be
	// treated as $0 at the spend gate, #5).
	estimateTurnUSD func(ctx context.Context, model string) (float64, bool)
	pricingSnapshot func(models []string) (string, error)
	now             func() time.Time
	out             io.Writer
}

const (
	finalAnswerExcerptCap = 4096
	defaultResolveDelay   = 750 * time.Millisecond
	defaultResolveTries   = 8
	dryRunTurnGuess       = 8
)

// Run executes (or, in DryRun, estimates) the whole matrix. It returns the
// run_id (empty on a dry run) so the CLI can print/report it.
func (r *benchmarkRunner) Run(ctx context.Context, spec benchmark.Spec, opts RunOptions) (string, error) {
	if r.now == nil {
		r.now = func() time.Time { return time.Now().UTC() }
	}
	if r.out == nil {
		r.out = os.Stdout
	}
	// Pre-flight: every config's harness must have a registered, supported
	// driver — fail the whole run BEFORE any spend on a typo/unsupported harness.
	if err := r.preflight(spec); err != nil {
		return "", err
	}

	cells := spec.ExpandCells()
	// Dry-run cost estimate (plan §3.7 step 1).
	est := r.estimateCost(ctx, spec)
	fmt.Fprintf(r.out, "benchmark %q: %d cells (%d tasks × %d configs × %d repeats)\n",
		spec.Name, len(cells), len(spec.Tasks), len(spec.Configs), spec.Repeats)
	if len(est.unpricedModels) > 0 {
		fmt.Fprintf(r.out, "estimated matrix cost: ~$%.2f + UNKNOWN (budget cap $%.2f)\n", est.total, spec.Budget.MaxTotalUSD)
		for _, m := range est.unpricedModels {
			fmt.Fprintf(r.out, "  model %q: unknown - cannot estimate (no billed history)\n", m)
		}
	} else {
		fmt.Fprintf(r.out, "estimated matrix cost: ~$%.2f (budget cap $%.2f)\n", est.total, spec.Budget.MaxTotalUSD)
	}

	if opts.DryRun {
		if len(est.unpricedModels) > 0 {
			fmt.Fprintln(r.out, "WARNING: one or more models have an UNKNOWN price - a real run needs --allow-unpriced.")
		}
		fmt.Fprintln(r.out, "DRY RUN - no sessions launched, nothing spent, nothing persisted.")
		fmt.Fprintln(r.out, "Re-run with --confirm-spend to execute (this spends real API budget).")
		return "", nil
	}
	if spec.Budget.RequireConfirm && !opts.Confirmed {
		return "", fmt.Errorf("benchmark: spec requires spend confirmation - re-run with --confirm-spend")
	}
	// #5: never spend on an unknown-price cell behind a false $0 estimate.
	if len(est.unpricedModels) > 0 && !opts.AllowUnpriced {
		return "", fmt.Errorf("benchmark: refusing to spend - no billed-history price for %v (the dry-run estimate cannot bound their cost); re-run with --allow-unpriced to override", est.unpricedModels)
	}

	runID := fmt.Sprintf("bench-%s-%d", sanitizeID(spec.Name), r.now().UnixNano())
	specJSON, _ := spec.CanonicalJSON()
	budgetJSON, _ := json.Marshal(spec.Budget)
	rec := benchmark.RunRecord{
		RunID: runID, SpecName: spec.Name, SpecHash: spec.SpecHash(), SpecJSON: specJSON,
		StartedAt: r.now(), Status: "running", PlannedCells: len(cells),
		BudgetJSON: string(budgetJSON),
	}
	if err := r.store.InsertBenchmarkRun(ctx, rec); err != nil {
		return "", err
	}

	man := newManifest(spec, opts)
	var runSpend, judgeSpend float64
	completed := 0
	budgetStopped := false

	if opts.ResolveAttempts <= 0 {
		opts.ResolveAttempts = defaultResolveTries
	}
	if opts.ResolveDelay <= 0 {
		opts.ResolveDelay = defaultResolveDelay
	}

	for _, cell := range cells {
		if budgetStopped || spec.Budget.RunCapExceeded(runSpend) {
			budgetStopped = true
			r.recordBudgetStopped(ctx, runID, cell)
			continue
		}
		attempt := r.runCell(ctx, runID, spec, cell, opts, &man)
		runSpend += attempt.spendUSD
		completed++
		fmt.Fprintf(r.out, "  [%s/%s/#%d] %s  $%.4f  %dms  %s\n",
			cell.Task.ID, cell.Config.ID, cell.RepeatIdx, attempt.status, attempt.spendUSD, attempt.wallMS, attempt.errorClass)

		rec.CompletedCells = completed
		rec.SpendUSD = runSpend
		rec.JudgeSpendUSD = judgeSpend
		if err := r.store.UpdateBenchmarkRun(ctx, rec); err != nil {
			return runID, err
		}
	}

	// Finalize: manifest + pricing snapshot at completion (plan §3.8 / §3.11).
	rec.FinishedAt = r.now()
	rec.Status = "completed"
	if budgetStopped {
		rec.Status = "budget_stop"
	}
	rec.ManifestJSON = man.marshal()
	if r.pricingSnapshot != nil {
		if snap, err := r.pricingSnapshot(man.requestedModels()); err == nil {
			rec.PricingSnapshotJSON = snap
		}
	}
	if err := r.store.UpdateBenchmarkRun(ctx, rec); err != nil {
		return runID, err
	}
	fmt.Fprintf(r.out, "run %s complete: %d/%d cells, $%.4f spent, status=%s\n",
		runID, completed, len(cells), runSpend, rec.Status)
	return runID, nil
}

// cellOutcome is the runner's internal per-cell result.
type cellOutcome struct {
	status     benchmark.Status
	spendUSD   float64
	wallMS     int64
	errorClass string
}

// runCell executes one cell with the pre-declared infra-retry policy, persists
// the attempt + members + scores, and returns the terminal outcome.
func (r *benchmarkRunner) runCell(ctx context.Context, runID string, spec benchmark.Spec, cell benchmark.Cell, opts RunOptions, man *manifest) cellOutcome {
	retries := spec.Retry.InfraRetries
	var out cellOutcome
	for attemptNo := 0; ; attemptNo++ {
		out = r.executeCell(ctx, runID, spec, cell, opts, man, attemptNo)
		if out.status.IsInfraFailure() && attemptNo < retries {
			fmt.Fprintf(r.out, "  [%s/%s/#%d] infra failure (%s) - retry %d/%d\n",
				cell.Task.ID, cell.Config.ID, cell.RepeatIdx, out.status, attemptNo+1, retries)
			continue
		}
		return out
	}
}

// executeCell provisions, drives, correlates, budgets, scores, and persists one
// attempt. Every terminal status is machine-readable and counted. attemptNo is
// the physical retry index (0 for the first try); it isolates each retry's
// workspace + persists as the distinct attempt_no row (migration 068).
func (r *benchmarkRunner) executeCell(ctx context.Context, runID string, spec benchmark.Spec, cell benchmark.Cell, opts RunOptions, man *manifest, attemptNo int) (out cellOutcome) {
	started := r.now()
	attemptDir := filepath.Join(opts.RootDir, runID, fmt.Sprintf("%s__%s__%d__a%d", sanitizeID(cell.Task.ID), sanitizeID(cell.Config.ID), cell.RepeatIdx, attemptNo))
	homeDir := filepath.Join(attemptDir, "home")
	// Bound disk (plan §3.9), BUT keep a failed attempt's workspace so it is
	// inspectable (audit P0.11 / #11). A successful (ok) attempt is cleaned;
	// any non-ok status, or --keep-workspaces, retains it and prints the path.
	defer func() {
		if out.status == benchmark.StatusOK && !opts.KeepWorkspaces {
			_ = os.RemoveAll(attemptDir)
			return
		}
		fmt.Fprintf(r.out, "  [%s/%s/#%d] workspace retained (%s): %s\n",
			cell.Task.ID, cell.Config.ID, cell.RepeatIdx, out.status, attemptDir)
	}()

	rec := benchmark.AttemptRecord{
		RunID: runID, TaskID: cell.Task.ID, ConfigID: cell.Config.ID,
		Harness: cell.Config.Harness, ModelRequested: cell.Config.Model,
		RepeatIdx: cell.RepeatIdx, AttemptNo: attemptNo, WorkspacePath: attemptDir, StartedAt: started,
	}

	// 1. Workspace + isolated home.
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return r.persistFailure(ctx, rec, benchmark.StatusSetupError, "mkdir_home: "+err.Error())
	}
	workspacePath, err := r.provisioner.Provision(ctx, cell.Task, attemptDir)
	if err != nil {
		return r.persistFailure(ctx, rec, benchmark.StatusSetupError, "provision: "+err.Error())
	}
	rec.WorkspacePath = workspacePath
	if r.homePrep != nil {
		if err := r.homePrep.Prepare(ctx, cell.Config.Harness, homeDir, opts.ProxyURL); err != nil {
			return r.persistFailure(ctx, rec, benchmark.StatusSetupError, "home_prep: "+err.Error())
		}
	}

	// 2. Drive the harness.
	driver := r.drivers[cell.Config.Harness]
	res, driveErr := driver.Drive(ctx, DriveRequest{
		Prompt: cell.Task.Prompt, Model: cell.Config.Model,
		WorkspaceDir: workspacePath, HomeDir: homeDir, ProxyURL: opts.ProxyURL,
		TimeoutSec: spec.Budget.MaxWallSecCell, MaxTurns: spec.Budget.MaxTurnsPerCell,
		TaskRepo: cell.Task.Repo,
	})
	rec.WallMS = res.WallMS
	ec := res.ExitCode
	rec.ExitCode = &ec
	if driveErr != nil {
		class := "harness_error"
		if isNotSupported(driveErr) {
			class = "harness_not_supported: " + driveErr.Error()
		}
		return r.persistFailure(ctx, rec, benchmark.StatusHarnessError, class)
	}

	// 3. Correlate sessions (fail-on-ambiguous, plan §3.3).
	members, modelReturned, corrErr := r.resolveSessions(ctx, runID, res.SessionIDs, workspacePath, opts)

	// 4. Base status from exit/timeout, then correlation/budget overrides.
	status := benchmark.StatusOK
	errClass := ""
	switch {
	case res.TimedOut:
		status = benchmark.StatusTimeout
		errClass = "wall_timeout"
	case res.ExitCode != 0:
		status = benchmark.StatusModelFail
		errClass = fmt.Sprintf("exit_%d", res.ExitCode)
	}
	if corrErr != nil && status == benchmark.StatusOK {
		status = benchmark.StatusOrphaned
		errClass = corrErr.Error()
	}

	// 5. Budget accounting from api_turns (success turns only).
	var spend float64
	var turns int
	for _, m := range members {
		if m.Role == benchmark.RoleJudge {
			continue
		}
		bill, berr := r.store.LoadSessionBilling(ctx, m.SessionID)
		if berr == nil {
			spend += bill.CostUSD
			turns += bill.Turns
		}
	}
	if stop, reason := spec.Budget.CellCapExceeded(spend, turns, int(res.WallMS/1000)); stop && status == benchmark.StatusOK {
		status = benchmark.StatusBudgetStop
		errClass = reason
	}
	rec.SpendUSD = spend
	rec.Turns = turns
	rec.Status = status
	rec.ErrorClass = errClass
	rec.FinalAnswerExcerpt = r.scrubExcerpt(res.FinalAnswer)
	rec.FinishedAt = r.now()

	// 6. Persist attempt, members, scores.
	attemptID, err := r.store.InsertBenchmarkAttempt(ctx, rec)
	if err != nil {
		fmt.Fprintf(r.out, "  persist attempt failed: %v\n", err)
		return cellOutcome{status: status, spendUSD: spend, wallMS: res.WallMS, errorClass: errClass}
	}
	for i := range members {
		members[i].AttemptID = attemptID
		members[i].RunID = runID
	}
	if err := r.store.InsertBenchmarkSessionMembers(ctx, members); err != nil {
		fmt.Fprintf(r.out, "  persist members failed: %v\n", err)
	}
	man.observe(cell.Config, modelReturned)

	// 7. Score (P4). Only a completed attempt with a recoverable answer is
	// scored; failures stay honest (no silent pass).
	if r.scorer != nil && status == benchmark.StatusOK {
		scores, serr := r.scorer.Score(ctx, scoreInput{
			Task: cell.Task, Config: cell.Config, AttemptID: attemptID, RunID: runID,
			WorkspaceDir: workspacePath, FinalAnswer: res.FinalAnswer, Status: status,
		})
		switch {
		case serr != nil:
			fmt.Fprintf(r.out, "  scoring error: %v\n", serr)
		case len(scores) == 0:
			// No scorer could produce a verdict → mark the attempt honestly.
			_ = r.store.UpdateBenchmarkAttemptStatus(ctx, attemptID, benchmark.StatusScorerUnavailable, "scorer_unavailable")
			status = benchmark.StatusScorerUnavailable
		default:
			if err := r.store.InsertBenchmarkScores(ctx, scores); err != nil {
				fmt.Fprintf(r.out, "  persist scores failed: %v\n", err)
			}
		}
	}

	return cellOutcome{status: status, spendUSD: spend, wallMS: res.WallMS, errorClass: errClass}
}

// resolveSessions maps captured/minted correlation ids to sessions, verifying
// the primary resolves to exactly one session under the expected workspace
// root (plan §3.3). Zero ids, an unresolvable primary, or a root mismatch ⇒ a
// loud error (the attempt becomes orphaned) — never a guess. Polls to absorb
// asynchronous ingestion (spike Q1).
func (r *benchmarkRunner) resolveSessions(ctx context.Context, runID string, ids []string, expectedRoot string, opts RunOptions) ([]benchmark.SessionMember, string, error) {
	if len(ids) == 0 {
		return nil, "", fmt.Errorf("orphaned: harness produced no correlation id")
	}
	primary := ids[0]
	var fact store.BenchmarkSessionFact
	var ok bool
	for i := 0; i < opts.ResolveAttempts; i++ {
		f, found, err := r.store.LoadSessionCorrelation(ctx, primary)
		if err != nil {
			return nil, "", fmt.Errorf("orphaned: correlation lookup: %w", err)
		}
		if found {
			fact, ok = f, true
			break
		}
		if r.sleep(ctx, opts.ResolveDelay) != nil {
			break
		}
	}
	if !ok {
		return nil, "", fmt.Errorf("orphaned: session %q never materialized", primary)
	}
	if !rootMatches(fact.RootPath, expectedRoot) {
		return nil, "", fmt.Errorf("orphaned: session %q root %q != workspace %q", primary, fact.RootPath, expectedRoot)
	}
	members := []benchmark.SessionMember{{
		SessionID: primary, Role: benchmark.RolePrimary, ModelReturned: fact.Model,
	}}
	// Attach any additional (sub-agent) sessions that resolve; ignore the rest.
	for _, id := range ids[1:] {
		if f, found, err := r.store.LoadSessionCorrelation(ctx, id); err == nil && found {
			members = append(members, benchmark.SessionMember{
				SessionID: id, Role: benchmark.RoleSubagent, ModelReturned: f.Model,
			})
		}
	}
	return members, fact.Model, nil
}

func (r *benchmarkRunner) preflight(spec benchmark.Spec) error {
	seen := map[string]bool{}
	for _, c := range spec.Configs {
		if seen[c.Harness] {
			continue
		}
		seen[c.Harness] = true
		d, ok := r.drivers[c.Harness]
		if !ok {
			return fmt.Errorf("benchmark: no driver for harness %q (config %q)", c.Harness, c.ID)
		}
		if pf, ok := d.(preflightDriver); ok {
			if err := pf.Preflight(); err != nil {
				return fmt.Errorf("benchmark: harness %q unavailable: %w", c.Harness, err)
			}
		}
	}
	return nil
}

// costEstimate is the dry-run estimate + the honest list of models whose price
// is UNKNOWN (no billed history) — those cells contribute $0 to the sum but are
// surfaced separately so an unknown price is never presented as $0.00 (#5).
type costEstimate struct {
	total          float64
	unpricedModels []string
}

func (r *benchmarkRunner) estimateCost(ctx context.Context, spec benchmark.Spec) costEstimate {
	turns := spec.Budget.MaxTurnsPerCell
	if turns <= 0 {
		turns = dryRunTurnGuess
	}
	var est costEstimate
	seenUnpriced := map[string]bool{}
	perConfig := len(spec.Tasks) * spec.Repeats
	for _, c := range spec.Configs {
		usd, known := 0.0, false
		if r.estimateTurnUSD != nil {
			usd, known = r.estimateTurnUSD(ctx, c.Model)
		}
		if !known {
			if !seenUnpriced[c.Model] {
				seenUnpriced[c.Model] = true
				est.unpricedModels = append(est.unpricedModels, c.Model)
			}
			continue
		}
		est.total += benchmark.EstimateMatrixCost(perConfig, turns, usd)
	}
	return est
}

func (r *benchmarkRunner) persistFailure(ctx context.Context, rec benchmark.AttemptRecord, status benchmark.Status, class string) cellOutcome {
	rec.Status = status
	rec.ErrorClass = class
	rec.FinishedAt = r.now()
	if _, err := r.store.InsertBenchmarkAttempt(ctx, rec); err != nil {
		fmt.Fprintf(r.out, "  persist failure attempt failed: %v\n", err)
	}
	return cellOutcome{status: status, wallMS: rec.WallMS, errorClass: class}
}

func (r *benchmarkRunner) recordBudgetStopped(ctx context.Context, runID string, cell benchmark.Cell) {
	rec := benchmark.AttemptRecord{
		RunID: runID, TaskID: cell.Task.ID, ConfigID: cell.Config.ID,
		Harness: cell.Config.Harness, ModelRequested: cell.Config.Model,
		RepeatIdx: cell.RepeatIdx, Status: benchmark.StatusBudgetStop,
		ErrorClass: "run_usd_cap", StartedAt: r.now(), FinishedAt: r.now(),
	}
	if _, err := r.store.InsertBenchmarkAttempt(ctx, rec); err != nil {
		fmt.Fprintf(r.out, "  persist budget-stop attempt failed: %v\n", err)
	}
}

func (r *benchmarkRunner) scrubExcerpt(answer string) string {
	if answer == "" {
		return ""
	}
	if len(answer) > finalAnswerExcerptCap {
		answer = answer[:finalAnswerExcerptCap]
	}
	if r.scrubber != nil {
		answer = r.scrubber.String(answer)
	}
	return answer
}

func (r *benchmarkRunner) sleep(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// --- reproducibility manifest (plan §3.8) ---

type manifest struct {
	SpecName        string              `json:"spec_name"`
	SpecHash        string              `json:"spec_hash"`
	ObserverVersion string              `json:"observer_version"`
	ProxyVersion    string              `json:"proxy_version,omitempty"`
	OS              string              `json:"os"`
	Arch            string              `json:"arch"`
	GoVersion       string              `json:"go_version"`
	ProxyURL        string              `json:"proxy_url"`
	RepoRefs        map[string]string   `json:"repo_refs"`        // task id → pinned ref
	RequestedModels map[string]string   `json:"requested_models"` // config id → model requested
	ReturnedModels  map[string][]string `json:"returned_models"`  // config id → observed served models
}

func newManifest(spec benchmark.Spec, opts RunOptions) manifest {
	m := manifest{
		SpecName: spec.Name, SpecHash: spec.SpecHash(),
		ObserverVersion: opts.ObserverVersion, ProxyVersion: opts.ProxyVersion,
		OS: runtime.GOOS, Arch: runtime.GOARCH, GoVersion: runtime.Version(),
		ProxyURL:        opts.ProxyURL,
		RepoRefs:        map[string]string{},
		RequestedModels: map[string]string{},
		ReturnedModels:  map[string][]string{},
	}
	for _, t := range spec.Tasks {
		m.RepoRefs[t.ID] = t.Ref
	}
	for _, c := range spec.Configs {
		m.RequestedModels[c.ID] = c.Model
	}
	return m
}

// observe records an actually-served model for a config (drift capture §3.8).
func (m *manifest) observe(cfg benchmark.Config, modelReturned string) {
	if modelReturned == "" {
		return
	}
	for _, existing := range m.ReturnedModels[cfg.ID] {
		if existing == modelReturned {
			return
		}
	}
	m.ReturnedModels[cfg.ID] = append(m.ReturnedModels[cfg.ID], modelReturned)
}

func (m *manifest) requestedModels() []string {
	set := map[string]bool{}
	for _, v := range m.RequestedModels {
		set[v] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *manifest) marshal() string {
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	return string(b)
}

// --- helpers ---

func isNotSupported(err error) bool {
	return err != nil && strings.Contains(err.Error(), ErrHarnessNotSupported.Error())
}

// rootMatches compares a session's project root to the expected workspace,
// tolerant of path cleaning and a workspace-subdir cwd (spike: exact equality,
// relaxed to prefix for harnesses that chdir into a subpackage).
func rootMatches(sessionRoot, workspace string) bool {
	if sessionRoot == "" {
		return false
	}
	sr := filepath.Clean(sessionRoot)
	ws := filepath.Clean(workspace)
	if sr == ws {
		return true
	}
	return strings.HasPrefix(sr, ws+string(filepath.Separator))
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b.WriteRune(c)
		default:
			b.WriteRune('-')
		}
	}
	return b.String()
}
