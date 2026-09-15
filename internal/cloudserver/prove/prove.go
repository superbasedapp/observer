package prove

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/foundry"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// ControlPlane is the narrow read seam the proving lane needs from the control
// tables: resolve a route snapshot by id, and check whether a live operator
// dialect-verification record binds that exact snapshot. *store.Store satisfies
// it. Both are READS of system tables; the lane never writes one, and never
// touches a tenant table.
type ControlPlane interface {
	RouteByID(ctx context.Context, routeID string) (store.RouteInfo, error)
	DialectVerified(ctx context.Context, route store.RouteInfo, now time.Time) (bool, error)
}

// Auditor appends one content-free, system-scoped audit event. It is optional:
// a nil Auditor simply records nothing, and the run reports that it did.
type Auditor func(ctx context.Context, eventType, detailJSON string) error

// Options configures one proving run. Every dependency is explicit — there is
// no ambient credential, no ambient route, and no ambient fixture source.
type Options struct {
	// FoundryAPIKey is the PROVE-lane provider credential, passed EXPLICITLY by
	// the caller. This is the whole credential-separation design: the lane can
	// only ever call the provider with a key handed to it here, so it cannot
	// reach the production worker's key and cannot weaken the worker's
	// credential-ABSENCE boundary. Empty ⇒ Run refuses.
	FoundryAPIKey string

	// RouteID names the route to prove against (a non-production route pinned by
	// the operator). Empty ⇒ Run refuses; the lane never guesses a route.
	RouteID string

	// Control reads the route snapshot + dialect verification record. Required.
	Control ControlPlane

	// Attestor is the SAME jobs.ProviderAttestor the worker uses (in production
	// a jobs.AttestationGate over the ARM ContentLogging reader). Required, and
	// fail-closed: nil would be an unattested provider call.
	Attestor jobs.ProviderAttestor

	// Provider is the Foundry client. Required.
	Provider foundry.Provider

	// Fixtures is the catalog to run. Nil ⇒ Catalog(). A caller may pass a
	// SUBSET of the compiled-in catalog; it may not pass evidence from anywhere
	// else, because Fixture's envelope field is unexported and this package
	// constructs the only instances that exist.
	Fixtures []Fixture

	// Now samples the instant each gate is evaluated at. Nil ⇒ time.Now.
	Now func() time.Time

	// Audit, when non-nil, records one content-free system-scoped audit row for
	// the run.
	Audit Auditor
}

// Step names one stage of the pipeline. The order here is the order the worker
// runs them in, and the order the report prints.
type Step string

// The proving-lane steps, in execution order.
const (
	// StepFixture validates the compiled-in fixture (schema bounds + digests)
	// before anything leaves the process.
	StepFixture Step = "fixture_validate"
	// StepRoute resolves the route snapshot and rejects an inactive one (FA7).
	StepRoute Step = "route_resolve"
	// StepAttestation re-checks the ContentLogging canary bound to that snapshot.
	StepAttestation Step = "attestation"
	// StepDialect checks the operator dialect-verification record (FA5).
	StepDialect Step = "dialect_record"
	// StepProvider builds the evidence-as-data prompt and makes the one bounded
	// Foundry call.
	StepProvider Step = "foundry_call"
	// StepNormalize normalizes, scrubs, and grounds the completion (FE1/FE3).
	StepNormalize Step = "normalize_scrub_ground"
)

// Steps lists the pipeline steps in execution order.
func Steps() []Step {
	return []Step{StepFixture, StepRoute, StepAttestation, StepDialect, StepProvider, StepNormalize}
}

// Status is one step's verdict.
type Status string

// Step verdicts. SKIP is honest, not a pass: it means the step did not run.
const (
	// StatusPass means the step ran and succeeded.
	StatusPass Status = "PASS"
	// StatusFail means the step ran and failed (the run's exit is non-zero).
	StatusFail Status = "FAIL"
	// StatusSkip means the step did not run because an earlier step failed, or
	// because it is not applicable to this route (a chat_completions route needs
	// no dialect verification record).
	StatusSkip Status = "SKIP"
)

// StepResult is one step's outcome. Detail is content-free apart from text the
// synthetic fixtures themselves contributed.
type StepResult struct {
	Step   Step
	Status Status
	Detail string
}

// FixtureReport is one fixture's per-step outcome.
type FixtureReport struct {
	Fixture string
	Purpose string
	Steps   []StepResult
}

// Passed reports whether every step of this fixture passed (a SKIP that is not
// a failure — e.g. an inapplicable dialect check — does not fail the fixture; a
// SKIP caused by an earlier FAIL is accompanied by that FAIL).
func (fr FixtureReport) Passed() bool {
	for _, s := range fr.Steps {
		if s.Status == StatusFail {
			return false
		}
	}
	return true
}

// Report is the whole run's outcome.
type Report struct {
	RouteID   string
	Dialect   string
	StartedAt time.Time
	Fixtures  []FixtureReport
	// AuditRecorded reports whether the content-free system audit row was
	// written. False with no Auditor configured is normal, and said so in the
	// printed report rather than silently omitted.
	AuditRecorded bool
	AuditDetail   string
}

// Passed reports whether every fixture passed.
func (r Report) Passed() bool {
	if len(r.Fixtures) == 0 {
		return false
	}
	for _, f := range r.Fixtures {
		if !f.Passed() {
			return false
		}
	}
	return true
}

// Print writes a per-fixture, per-step PASS/FAIL report. The only free text it
// can emit beyond fixed labels is derived from the synthetic fixtures (their own
// authored content, and the model's answer about it).
func (r Report) Print(w io.Writer) {
	fmt.Fprintf(w, "observer-cloud prove: fixture-only Foundry proving lane\n")
	fmt.Fprintf(w, "  route: %s (dialect %s)\n", r.RouteID, r.Dialect)
	fmt.Fprintf(w, "  started: %s\n", r.StartedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  fixtures: %d (compiled-in catalog; no client evidence)\n\n", len(r.Fixtures))
	for _, f := range r.Fixtures {
		verdict := "FAIL"
		if f.Passed() {
			verdict = "PASS"
		}
		fmt.Fprintf(w, "[%s] fixture %s — %s\n", verdict, f.Fixture, f.Purpose)
		for _, s := range f.Steps {
			line := fmt.Sprintf("    %-6s %-24s", s.Status, s.Step)
			if s.Detail != "" {
				line += " " + s.Detail
			}
			fmt.Fprintln(w, line)
		}
		fmt.Fprintln(w)
	}
	if r.AuditRecorded {
		fmt.Fprintf(w, "audit: recorded one system-scoped %s event (%s)\n", AuditEventType, r.AuditDetail)
	} else {
		fmt.Fprintf(w, "audit: NOT recorded (%s)\n", r.AuditDetail)
	}
	if r.Passed() {
		fmt.Fprintln(w, "result: PASS — every fixture completed the full pipeline")
		return
	}
	fmt.Fprintln(w, "result: FAIL — at least one fixture did not complete the pipeline")
}

// AuditEventType is the security_audit_events event_type this lane writes.
const AuditEventType = "prove_run"

// ErrNoProveCredential is returned when no prove-lane credential was supplied.
// It is deliberately distinct from any worker error: the fix is to set the
// prove-lane variable, never to reach for the production worker's key.
var ErrNoProveCredential = errors.New(
	"prove: no prove-lane Foundry credential supplied — set SBCI_PROVE_FOUNDRY_API_KEY " +
		"(this lane NEVER reads SBCI_FOUNDRY_API_KEY: the production worker's credential-absence boundary is untouched)",
)

// Run executes the proving lane: for every fixture, the same pipeline stages the
// worker runs, in the same fail-closed order, using the worker's own functions.
//
// It writes NOTHING to analysis_jobs, evidence_objects, reservations, results,
// or any other tenant table. It leases nothing. Its only optional write is the
// content-free system-scoped audit row.
//
// A configuration fault (no credential, no route, a missing dependency) returns
// an error and runs nothing. A pipeline failure is reported per step in the
// Report — the caller decides the exit code from Report.Passed.
func Run(ctx context.Context, opts Options) (Report, error) {
	if strings.TrimSpace(opts.FoundryAPIKey) == "" {
		return Report{}, ErrNoProveCredential
	}
	if strings.TrimSpace(opts.RouteID) == "" {
		return Report{}, errors.New("prove: no route selected — set SBCI_PROVE_ROUTE (or --route) to the non-production route id to prove against")
	}
	if opts.Control == nil {
		return Report{}, errors.New("prove: no control-plane reader configured")
	}
	if opts.Attestor == nil {
		return Report{}, errors.New("prove: no attestor configured — an unattested provider call is never allowed (fail closed)")
	}
	if opts.Provider == nil {
		return Report{}, errors.New("prove: no Foundry provider configured")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	fixtures := opts.Fixtures
	if len(fixtures) == 0 {
		fixtures = Catalog()
	}

	rep := Report{RouteID: opts.RouteID, StartedAt: now()}
	for _, f := range fixtures {
		fr, dialect := runFixture(ctx, opts, f, now)
		if dialect != "" {
			rep.Dialect = dialect
		}
		rep.Fixtures = append(rep.Fixtures, fr)
	}
	if rep.Dialect == "" {
		rep.Dialect = "unresolved"
	}

	rep.AuditRecorded, rep.AuditDetail = recordAudit(ctx, opts, rep)
	return rep, nil
}

// fixtureRun accumulates one fixture's step results. It exists so each step
// reads as one linear pass/fail decision rather than a nest of early returns
// that each have to remember to fill in the skipped tail.
type fixtureRun struct {
	report  FixtureReport
	dialect string
}

func (fx *fixtureRun) pass(step Step, format string, args ...any) {
	fx.report.Steps = append(fx.report.Steps, StepResult{
		Step: step, Status: StatusPass, Detail: fmt.Sprintf(format, args...),
	})
}

func (fx *fixtureRun) skip(step Step, format string, args ...any) {
	fx.report.Steps = append(fx.report.Steps, StepResult{
		Step: step, Status: StatusSkip, Detail: fmt.Sprintf(format, args...),
	})
}

// fail records the step's failure and marks every LATER step SKIP — an honest
// "did not run", never a pass.
func (fx *fixtureRun) fail(step Step, format string, args ...any) {
	fx.report.Steps = append(fx.report.Steps, StepResult{
		Step: step, Status: StatusFail, Detail: fmt.Sprintf(format, args...),
	})
	seen := false
	for _, s := range Steps() {
		if s == step {
			seen = true
			continue
		}
		if seen {
			fx.report.Steps = append(fx.report.Steps, StepResult{
				Step: s, Status: StatusSkip, Detail: "not run (an earlier step failed)",
			})
		}
	}
}

// runFixture drives one fixture through every step in the worker's own
// fail-closed order, stopping at the first failure. It returns the fixture
// report and the route dialect it observed (empty when the route never
// resolved).
func runFixture(ctx context.Context, opts Options, f Fixture, now func() time.Time) (FixtureReport, string) {
	fx := &fixtureRun{report: FixtureReport{Fixture: f.Name, Purpose: f.Purpose}}

	// Step 1 — the fixture itself. A malformed compiled-in fixture must never
	// become a wasted provider call.
	env, evidence, digests, err := materialize(f)
	if err != nil {
		fx.fail(StepFixture, "%v", err)
		return fx.report, fx.dialect
	}
	fx.pass(StepFixture, "%d bytes, evidence=%s upload=%s", len(evidence),
		shortDigest(digests.EvidenceContent), shortDigest(digests.Upload))

	// Step 2 — route resolve. Mirrors the worker's FA7 posture: an INACTIVE
	// route is not admissible, even by id. And the lane accepts ONLY a route the
	// operator has classified non-production (F10) — see the Environment check
	// below.
	route, err := opts.Control.RouteByID(ctx, opts.RouteID)
	if err != nil {
		fx.fail(StepRoute, "route %q not resolvable: %v", opts.RouteID, err)
		return fx.report, fx.dialect
	}
	fx.dialect = route.Dialect
	if !route.Active {
		fx.fail(StepRoute, "route %q is INACTIVE (fail closed)", route.RouteID)
		return fx.report, fx.dialect
	}
	// F10: fail CLOSED unless the route is explicitly non-production. The column
	// defaults to 'production', so an unclassified route — and the real one — is
	// refused here, and the worker refuses the mirror case. The two lanes' route
	// sets are therefore disjoint BY CONSTRUCTION, which is the whole reason they
	// may keep sharing the provider_attestations cache (see doc.go).
	if route.Environment != store.RouteEnvironmentNonProduction {
		fx.fail(StepRoute,
			"route %q has route_registry.environment=%q — the proving lane accepts only %q. "+
				"Provision a separate non-production route and classify it; the lane never proves against a route the worker serves",
			route.RouteID, route.Environment, store.RouteEnvironmentNonProduction)
		return fx.report, fx.dialect
	}
	fx.pass(StepRoute, "gen=%d deployment=%s api=%s dialect=%s environment=%s",
		route.Generation, route.Deployment, route.APIVersion, route.Dialect, route.Environment)

	// Step 3 — ContentLogging attestation, bound to the resolved snapshot.
	att, err := opts.Attestor.Attest(ctx, route, now())
	switch {
	case err != nil:
		fx.fail(StepAttestation, "attestation error: %v", err)
		return fx.report, fx.dialect
	case !att.Verified:
		fx.fail(StepAttestation, "NOT verified: %s", att.Reason)
		return fx.report, fx.dialect
	}
	fx.pass(StepAttestation, "verified: %s", att.Reason)

	// Step 4 — dialect verification record. Only responses_store_false requires
	// one; chat_completions is stateless by design.
	if route.Dialect == string(foundry.DialectResponsesStoreFalse) {
		ok, err := opts.Control.DialectVerified(ctx, route, now())
		switch {
		case err != nil:
			fx.fail(StepDialect, "verification lookup failed: %v", err)
			return fx.report, fx.dialect
		case !ok:
			fx.fail(StepDialect, "no live record bound to this route snapshot (fail closed)")
			return fx.report, fx.dialect
		}
		fx.pass(StepDialect, "live record bound to gen=%d", route.Generation)
	} else {
		fx.skip(StepDialect, "not applicable: dialect %q needs no verification record", route.Dialect)
	}

	// Step 5 — the one bounded provider call, built by the worker's own
	// functions and dispatched with the EXPLICIT prove-lane credential.
	prompt, err := jobs.BuildLunaPrompt(evidence)
	if err != nil {
		fx.fail(StepProvider, "evidence delimiter collision: %v", err)
		return fx.report, fx.dialect
	}
	res, err := opts.Provider.Complete(ctx, jobs.BuildLunaRequest(route, opts.FoundryAPIKey, prompt))
	if err != nil {
		if errors.Is(err, foundry.ErrPersistenceViolation) {
			fx.fail(StepProvider, "PERSISTENCE VIOLATION — the endpoint indicated it stored the prompt/completion despite store:false")
		} else {
			fx.fail(StepProvider, "provider error: %v", err)
		}
		return fx.report, fx.dialect
	}
	fx.pass(StepProvider, "tokens in=%d out=%d, prompt=%s", res.TokensIn, res.TokensOut, shortHash(prompt.PromptHash))

	// Step 6 — normalize, scrub, and ground the completion. The allowed-ref set
	// comes from the fixture's own envelope, so an invented citation fails here
	// exactly as it would for a real job.
	cleaned, rejection := jobs.ProcessLunaCompletion(res.Content, cloudcontract.AllowedEvidenceRefs(env))
	if rejection != "" {
		fx.fail(StepNormalize, "rejected: %s", rejection)
		return fx.report, fx.dialect
	}
	fx.pass(StepNormalize, "title=%q confidence=%s tags=%d refs=%d",
		cleaned.Title.String(), cleaned.Confidence, len(cleaned.TaxonomyTags), len(cleaned.EvidenceRefs))
	return fx.report, fx.dialect
}

// materialize validates a fixture and derives everything the pipeline needs
// from it: the envelope (for the allowed-ref set), the exact upload bytes, and
// the two-digest pair.
func materialize(f Fixture) (cloudcontract.Envelope, []byte, cloudcontract.Digests, error) {
	if err := f.Validate(); err != nil {
		return cloudcontract.Envelope{}, nil, cloudcontract.Digests{}, err
	}
	env, err := f.Envelope()
	if err != nil {
		return cloudcontract.Envelope{}, nil, cloudcontract.Digests{}, err
	}
	evidence, err := f.UploadBytes()
	if err != nil {
		return cloudcontract.Envelope{}, nil, cloudcontract.Digests{}, err
	}
	digests, err := f.Digests()
	if err != nil {
		return cloudcontract.Envelope{}, nil, cloudcontract.Digests{}, err
	}
	return env, evidence, digests, nil
}

// recordAudit appends the run's content-free system-scoped audit row. It carries
// counts and the route id only — never fixture text, never a completion.
func recordAudit(ctx context.Context, opts Options, rep Report) (bool, string) {
	passed, failed := 0, 0
	for _, f := range rep.Fixtures {
		if f.Passed() {
			passed++
			continue
		}
		failed++
	}
	detail := fmt.Sprintf(`{"scope":"prove","route_id":%q,"fixtures":%d,"passed":%d,"failed":%d}`,
		jsonSafeToken(opts.RouteID), len(rep.Fixtures), passed, failed)
	summary := fmt.Sprintf("route=%s fixtures=%d passed=%d failed=%d", opts.RouteID, len(rep.Fixtures), passed, failed)
	if opts.Audit == nil {
		return false, "no auditor configured; " + summary
	}
	if err := opts.Audit(ctx, AuditEventType, detail); err != nil {
		return false, "audit write failed: " + err.Error()
	}
	return true, summary
}

// jsonSafeToken strips quote/backslash/control bytes so an identifier can be
// interpolated into the small JSON audit detail without breaking it.
func jsonSafeToken(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '"' || r == '\\' || r < 0x20 {
			continue
		}
		out = append(out, r)
	}
	if len(out) > 128 {
		out = out[:128]
	}
	return string(out)
}

func shortDigest(d string) string {
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
