package jobs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// Attestation is the worker-facing verdict of the ContentLogging route-policy
// canary (plan §2.2). Verified=false parks the job provider_policy_unverified
// WITHOUT any provider call. The rich record + ARM read live in
// internal/cloudserver/attest; AttestationGate adapts them to this interface.
type Attestation struct {
	Verified bool
	Reason   string
}

// ProviderAttestor re-checks the route's ContentLogging attestation inside the
// execution lease, immediately before every provider attempt including retries
// (plan §2.2 / §6 CI-P4). It is passed the FULLY RESOLVED route snapshot the
// worker will execute under — NOT a route id it would re-resolve independently
// (FA1) — so the attestation is bound to the exact resource/generation the
// provider call uses, and cannot attest a different snapshot than the one
// executed.
type ProviderAttestor interface {
	Attest(ctx context.Context, route store.RouteInfo, now time.Time) (Attestation, error)
}

// UnverifiedAttestor always reports NOT verified — the fail-closed default when
// no gate is wired (models the pre-approval boundary).
type UnverifiedAttestor struct{}

// Attest always returns Verified=false.
func (UnverifiedAttestor) Attest(context.Context, store.RouteInfo, time.Time) (Attestation, error) {
	return Attestation{Verified: false, Reason: "no attestation gate configured (fail closed)"}, nil
}

// RefusingAttestor always reports NOT verified with a fixed reason and NEVER
// consults the persisted attestation cache - it is what cmd/observer-cloud
// wires when two operator attestation modes are configured at once. Unlike
// wrapping attest.RefusingAttestor in an AttestationGate, this cannot be
// bypassed for up to the gate's max-age by a healthy record persisted before
// the conflicting configuration was introduced.
type RefusingAttestor struct {
	Reason string
}

// Attest always returns Verified=false with the configured reason.
func (r RefusingAttestor) Attest(context.Context, store.RouteInfo, time.Time) (Attestation, error) {
	reason := r.Reason
	if reason == "" {
		reason = "attestation refused (fail closed)"
	}
	return Attestation{Verified: false, Reason: reason}, nil
}

// ExecOutcome classifies one provider attempt.
type ExecOutcome int

const (
	// ExecSucceeded ⇒ the executor already persisted the result and settled the
	// reservation atomically.
	ExecSucceeded ExecOutcome = iota
	// ExecInvalidOutput ⇒ the provider returned unparseable/invalid output;
	// retryable within the attempt budget.
	ExecInvalidOutput
	// ExecEvidenceExpired ⇒ the evidence bytes are gone (deleted/swept/missing).
	ExecEvidenceExpired
	// ExecProviderError ⇒ a provider quota/timeout/transport/5xx error;
	// retryable unless Terminal is set.
	ExecProviderError
	// ExecAborted ⇒ authorization changed between revalidation and the
	// completion write (job canceled/deleted/re-leased, account fenced, or
	// consent bumped): the completion CAS stored NOTHING (FA1/FA8). The worker
	// leaves the job to whatever transition superseded it; a still-running job
	// re-leases after lease expiry and parks on the next pass.
	ExecAborted
)

// ExecResult is one attempt's classified outcome. Terminal short-circuits the
// retry loop (e.g. a store:false persistence violation must never be retried).
type ExecResult struct {
	Outcome        ExecOutcome
	Terminal       bool
	TerminalReason string
	TokensIn       int64
	TokensOut      int64
	Detail         string
	// ParkReason, when non-empty, means the FINAL pre-dispatch gate (FA1/FA2/FA7)
	// found the job no longer admissible at the dispatch seam (route mutated /
	// deactivated, a kill switch flipped, evidence expired, attestation went
	// stale, consent bumped) AFTER the worker's per-attempt revalidation but
	// BEFORE the provider call. The worker parks the job with this reason (no
	// provider call happened). It takes precedence over Outcome.
	ParkReason string
}

// FinalGate re-runs the full execution-lease revalidation at the LAST point
// before the provider call, against a FRESHLY sampled instant (FA1/FA2/FA7). It
// returns the freshly resolved route + credential to dispatch under, or a
// non-empty park reason when the job is no longer admissible. It is the SAME
// gate set the worker runs per attempt (Worker.revalidate) — one owner, invoked
// twice: once before the executor is entered, once at the dispatch seam after
// the executor's blob-load + prompt-build — so a mutation in that window cannot
// slip a call through to a stale/deactivated/kill-switched route.
type FinalGate func(ctx context.Context, now time.Time) (store.RouteInfo, string, string, error)

// Executor performs ONE bounded provider attempt for a leased job and reports a
// classified outcome (plan §6 CI-P4). The worker owns the attempt loop and
// re-runs the full execution-lease revalidation before EACH call, and hands the
// executor a FinalGate to re-run it once more at the dispatch seam. clock is
// re-sampled at that seam (FA2) so a long blob-load/prompt-build cannot let the
// call dispatch against a snapshot that expired meanwhile. On ExecSucceeded the
// executor has already persisted the result and settled the reservation
// (atomic); on every other outcome it has persisted nothing.
//
// The worker dispatches to an Executor by the leased job's Feature through a
// small feature -> Executor table (W5): LunaExecutor handles
// store.FeatureSessionEnrichment, DigestExecutor handles
// store.FeatureProjectDigest. A feature with no wired Executor fails the job
// terminally (store.ReasonExecutorMissing) rather than silently declining
// forever or fabricating a result.
type Executor interface {
	Execute(ctx context.Context, lj *store.LeasedJob, route store.RouteInfo, apiKey string, attempt int, clock func() time.Time, finalGate FinalGate) (ExecResult, error)
}

// NoopExecutor declines every attempt (a placeholder when no real executor is
// wired). It reports a retryable provider error, so a worker wired with it (and
// a present credential + verified attestation) fails the job after its budget
// rather than fabricating a result.
type NoopExecutor struct{}

// Execute always declines.
func (NoopExecutor) Execute(context.Context, *store.LeasedJob, store.RouteInfo, string, int, func() time.Time, FinalGate) (ExecResult, error) {
	return ExecResult{Outcome: ExecProviderError, Detail: "no-op executor (no Foundry provider wired)"}, nil
}

// Config configures a Worker.
type Config struct {
	WorkerID     string
	Classes      []string      // feature classes this worker leases
	LeaseFor     time.Duration // visibility timeout per lease
	PollInterval time.Duration // sleep when nothing is due
	TTLHeadroom  time.Duration // required remaining evidence TTL before a provider attempt
	MaxAttempts  int           // provider attempts before failing (default 2: one retry)
	Logger       *slog.Logger
	// Clock samples the current instant. It is re-sampled FRESH before every
	// attempt's revalidation and dispatch (FA2), so a long first attempt cannot
	// let attempt 2 treat expired evidence/attestation as fresh against a frozen
	// timestamp. Nil ⇒ a clock that returns the `now` argument passed to
	// ProcessOnce (so a caller-supplied fixed now stays authoritative for tests).
	Clock func() time.Time
}

func (c *Config) applyDefaults() {
	if c.WorkerID == "" {
		c.WorkerID = "sbci-worker"
	}
	if len(c.Classes) == 0 {
		c.Classes = []string{store.FeatureSessionEnrichment}
	}
	if c.LeaseFor <= 0 {
		c.LeaseFor = 5 * time.Minute
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.TTLHeadroom <= 0 {
		c.TTLHeadroom = 2 * time.Minute
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 2
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
}

// Worker leases jobs and drives each through the execution-lease revalidation
// gates + the bounded provider attempt loop. It owns no HTTP or SQL — it
// composes the store, the queue, the attestation gate, the credential source,
// and the executor.
type Worker struct {
	cfg       Config
	queue     Queue
	store     *store.Store
	attestor  ProviderAttestor
	creds     CredentialSource
	executors map[string]Executor
}

// NewWorker assembles a worker. nil attestor ⇒ UnverifiedAttestor; nil creds ⇒
// AbsentCredentials (the pre-approval boundary); nil executors ⇒
// {store.FeatureSessionEnrichment: NoopExecutor{}} (the pre-W5 default: a
// single feature served by a no-op decliner). executors maps a job's Feature
// to the Executor that serves it (W5); a leased job whose Feature has no entry
// fails terminal store.ReasonExecutorMissing.
func NewWorker(cfg Config, q Queue, s *store.Store, attestor ProviderAttestor, creds CredentialSource, executors map[string]Executor) *Worker {
	cfg.applyDefaults()
	if attestor == nil {
		attestor = UnverifiedAttestor{}
	}
	if creds == nil {
		creds = AbsentCredentials{}
	}
	if executors == nil {
		executors = map[string]Executor{store.FeatureSessionEnrichment: NoopExecutor{}}
	}
	return &Worker{cfg: cfg, queue: q, store: s, attestor: attestor, creds: creds, executors: executors}
}

// Outcome describes what happened to one processed job.
type Outcome struct {
	JobID  string
	State  string // "parked", "failed", "succeeded", or "" when nothing leased
	Reason string
}

// Run loops until ctx is canceled.
func (w *Worker) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		out, err := w.ProcessOnce(ctx, time.Now())
		if err != nil {
			w.cfg.Logger.Warn("cloudserver/jobs: process error (continuing)", "err", err)
		}
		if out.JobID == "" {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(w.cfg.PollInterval):
			}
		}
	}
}

// ProcessOnce leases at most one job and runs it through the FULL
// execution-lease revalidation before EVERY provider attempt (plan §2.2 /
// §6 CI-P4). Any gate failure parks the job (releasing its reservation and
// deleting its evidence + bytes) WITHOUT a provider call; a provider error or
// invalid output retries within MaxAttempts, then fails terminally with a
// refund; success settles exactly one user unit.
func (w *Worker) ProcessOnce(ctx context.Context, now time.Time) (Outcome, error) {
	// FA2: a fresh instant per revalidation/dispatch. The default clock returns
	// the caller-supplied `now`, so a fixed test now stays authoritative; a real
	// clock (or an injected advancing fake) re-samples so a slow first attempt
	// cannot make attempt 2 see stale evidence/attestation as fresh.
	clock := w.cfg.Clock
	if clock == nil {
		clock = func() time.Time { return now }
	}

	lj, err := w.queue.Lease(ctx, w.cfg.WorkerID, w.cfg.Classes, w.cfg.LeaseFor, clock())
	if err != nil {
		return Outcome{}, fmt.Errorf("lease: %w", err)
	}
	if lj == nil {
		return Outcome{}, nil
	}
	// Stamp the lease owner so the completion CAS can require it to be unchanged
	// (FA8). The worker leased with its own id, so this is authoritative.
	lj.LeaseWorker = w.cfg.WorkerID

	// W5: dispatch by feature through the small table. A job whose feature has
	// no wired Executor fails terminal — never silently succeeds and never
	// retries forever — before the job is even marked running.
	executor, ok := w.executors[lj.Feature]
	if !ok {
		return w.fail(ctx, lj, store.ReasonExecutorMissing, clock())
	}

	markedRunning := false
	for attempt := 0; attempt < w.cfg.MaxAttempts; attempt++ {
		attemptNow := clock() // FRESH before every revalidation (FA2)
		route, apiKey, reason, err := w.revalidate(ctx, lj, attemptNow)
		if err != nil {
			return Outcome{}, err
		}
		if reason != "" {
			return w.park(ctx, lj, reason, attemptNow)
		}
		if !markedRunning {
			if err := w.store.MarkJobRunning(ctx, lj.AccountID, lj.JobID, attemptNow); err != nil {
				return Outcome{}, fmt.Errorf("mark running: %w", err)
			}
			markedRunning = true
		}

		// The executor re-runs the SAME revalidation gate at the dispatch seam via
		// this closure (FA1/FA2/FA7), against a fresh clock sample it takes there.
		finalGate := func(ctx context.Context, now time.Time) (store.RouteInfo, string, string, error) {
			return w.revalidate(ctx, lj, now)
		}
		res, err := executor.Execute(ctx, lj, route, apiKey, attempt, clock, finalGate)
		if err != nil {
			return Outcome{}, fmt.Errorf("execute: %w", err)
		}
		if res.Terminal {
			return w.fail(ctx, lj, res.TerminalReason, clock())
		}
		// FA1/FA2/FA7: the dispatch-seam gate found the job no longer admissible —
		// park it with that reason; no provider call happened.
		if res.ParkReason != "" {
			return w.park(ctx, lj, res.ParkReason, clock())
		}
		switch res.Outcome {
		case ExecSucceeded:
			return Outcome{JobID: lj.JobID, State: "succeeded"}, nil
		case ExecAborted:
			// Nothing stored; the job's authorization changed and another
			// transition (cancel/deletion) owns it, or it re-leases and parks
			// later. Do not park/fail here (that would race the superseding
			// transition).
			return Outcome{JobID: lj.JobID, State: "aborted", Reason: res.Detail}, nil
		case ExecEvidenceExpired:
			return w.park(ctx, lj, store.ReasonEvidenceExpired, clock())
		default: // ExecInvalidOutput / ExecProviderError — record internal cost, retry
			if err := w.store.RecordProviderAttempt(ctx, lj.AccountID, lj.JobID,
				res.TokensIn, res.TokensOut, lj.RouteVersion, attempt, `{"scope":"attempt","detail":"`+jsonSafe(res.Detail)+`"}`); err != nil {
				return Outcome{}, fmt.Errorf("record attempt: %w", err)
			}
		}
	}
	// Attempt budget exhausted without an accepted result.
	return w.fail(ctx, lj, store.ReasonProviderInvalidOutput, clock())
}

// revalidate runs every execution-lease gate in a fail-closed order and returns
// the resolved route + credential to use for the attempt, or a non-empty park
// reason. It resolves the route FRESH each attempt so a route/config change
// between attempts (or between enqueue and run) is caught.
func (w *Worker) revalidate(ctx context.Context, lj *store.LeasedJob, now time.Time) (store.RouteInfo, string, string, error) {
	// Gate 1: consent generation — a bump since admission invalidates the job.
	curGen, err := w.store.AccountConsentGeneration(ctx, lj.AccountID)
	if err != nil {
		return store.RouteInfo{}, "", "", fmt.Errorf("read consent generation: %w", err)
	}
	if curGen != lj.ConsentGeneration {
		return store.RouteInfo{}, "", store.ReasonReconfirmationRequired, nil
	}
	// Candidate selection and enqueue precede dispatch. A refund or downgrade
	// can remove Plus between any of those steps, including a provider retry.
	if lj.Feature == store.FeatureProjectDigest {
		allow, err := w.store.ResolveAllowance(ctx, lj.AccountID, lj.Feature, now)
		if err != nil {
			return store.RouteInfo{}, "", "", fmt.Errorf("read digest entitlement: %w", err)
		}
		if !allow.Plan.DigestWeekly {
			return store.RouteInfo{}, "", store.ReasonEntitlementRevoked, nil
		}
	}

	// Gate 2: kill switches (global + per-route).
	ks, err := w.store.KillSwitches(ctx, lj.RouteID)
	if err != nil {
		return store.RouteInfo{}, "", "", fmt.Errorf("read kill switches: %w", err)
	}
	if ks.GlobalActive || ks.RouteActive {
		return store.RouteInfo{}, "", store.ReasonKillSwitched, nil
	}

	// Gate 3: evidence TTL headroom (and a deleted/missing object ⇒ expired).
	eo, err := w.store.GetEvidence(ctx, lj.AccountID, lj.EvidencePK)
	if err != nil {
		return store.RouteInfo{}, "", "", fmt.Errorf("read evidence: %w", err)
	}
	if eo.DeletedAt != nil || !now.Add(w.cfg.TTLHeadroom).Before(eo.ExpiresAt) {
		return store.RouteInfo{}, "", store.ReasonEvidenceExpired, nil
	}

	// Resolve the route fresh (catches route/config change between attempts).
	route, err := w.store.RouteByID(ctx, lj.RouteID)
	if err != nil {
		return store.RouteInfo{}, "", store.ReasonProviderPolicyUnverified, nil
	}
	// FA7 fail-closed: an INACTIVE route is not admissible. RouteByID returns
	// inactive routes (it is a by-id lookup, not the active-only resolver), so
	// the execution lease must reject one explicitly — an operator flipping
	// route.active=false must stop the worker from calling it.
	if !route.Active {
		return store.RouteInfo{}, "", store.ReasonProviderPolicyUnverified, nil
	}
	// F10 mirror guard: the worker serves PRODUCTION routes only. The
	// fixture-only proving lane refuses anything that is not
	// route_registry.environment='nonproduction'; this is the other half of that
	// partition, so an operator who classifies a route for proving cannot leave
	// real developer evidence routed through it. The column defaults to
	// 'production', so an unclassified route stays serviceable here and the
	// guard is a refusal of an EXPLICIT classification, never of a silence.
	if route.Environment == store.RouteEnvironmentNonProduction {
		return store.RouteInfo{}, "", store.ReasonProviderPolicyUnverified, nil
	}

	// Gate 4: dialect verification — responses_store_false stays dark without a
	// live operator verification record BOUND to this exact route snapshot
	// (plan §2.3 / FA5). Passing the resolved route (not just id+dialect) binds
	// the check to the route generation + api_version + deployment.
	if route.Dialect == string(foundry.DialectResponsesStoreFalse) {
		ok, err := w.store.DialectVerified(ctx, route, now)
		if err != nil {
			return store.RouteInfo{}, "", "", fmt.Errorf("dialect verification: %w", err)
		}
		if !ok {
			return store.RouteInfo{}, "", store.ReasonDialectUnverified, nil
		}
	}

	// Gate 5: credential-absence boundary (plan §2.1) — no provisioned key ⇒ no
	// provider call, ever. This is the pre-approval gate that a normal account's
	// evidence can never bypass.
	apiKey, ok, err := w.creds.ProviderKey(ctx, route.RouteID)
	if err != nil {
		return store.RouteInfo{}, "", "", fmt.Errorf("credential source: %w", err)
	}
	if !ok {
		return store.RouteInfo{}, "", store.ReasonProviderPolicyUnverified, nil
	}

	// Gate 6: ContentLogging attestation (fresh + bound to THIS resolved route
	// snapshot, FA1), re-checked here every attempt including retries (plan §2.2).
	// The attestor is handed the resolved route, not an id it would re-resolve, so
	// it cannot attest a different generation than the one about to execute.
	att, err := w.attestor.Attest(ctx, route, now)
	if err != nil {
		return store.RouteInfo{}, "", "", fmt.Errorf("attest: %w", err)
	}
	if !att.Verified {
		return store.RouteInfo{}, "", store.ReasonProviderPolicyUnverified, nil
	}

	return route, apiKey, "", nil
}

func (w *Worker) park(ctx context.Context, lj *store.LeasedJob, reason string, now time.Time) (Outcome, error) {
	if err := w.store.ParkJob(ctx, lj.AccountID, lj.JobID, reason, now); err != nil {
		return Outcome{}, fmt.Errorf("park (%s): %w", reason, err)
	}
	return Outcome{JobID: lj.JobID, State: "parked", Reason: reason}, nil
}

func (w *Worker) fail(ctx context.Context, lj *store.LeasedJob, reason string, now time.Time) (Outcome, error) {
	if err := w.store.FailJob(ctx, lj.AccountID, lj.JobID, reason, now); err != nil {
		return Outcome{}, fmt.Errorf("fail (%s): %w", reason, err)
	}
	return Outcome{JobID: lj.JobID, State: "failed", Reason: reason}, nil
}

// jsonSafe strips quotes/backslashes/controls from a detail string so it can be
// interpolated into a small JSON ledger detail without breaking it.
func jsonSafe(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '"' || r == '\\' || r < 0x20 {
			out = append(out, ' ')
			continue
		}
		out = append(out, r)
	}
	if len(out) > 200 {
		out = out[:200]
	}
	return string(out)
}
