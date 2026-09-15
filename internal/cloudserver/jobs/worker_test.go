package jobs_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

func setup(t *testing.T) (*store.Store, *pgxpool.Pool, string) {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	ctx := context.Background()
	now := time.Now()
	nonce, _ := s.MintNonce(ctx, store.DefaultNonceTTL, now)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	res, err := s.Exchange(ctx, store.ExchangeInput{Provider: "dev", Subject: "w", PublicKey: pub, RawNonce: nonce, Now: now})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	// overrides_plan=true makes this row the explicit per-account cap override
	// (migration 0012); without it the account resolves the free plan's caps.
	_, _ = pool.Exec(ctx, `UPDATE entitlements SET daily_cap=100, monthly_cap=1000, concurrency_cap=100, overrides_plan=true WHERE account_id=$1::uuid`, res.AccountID)
	return s, pool, res.AccountID
}

func submit(t *testing.T, s *store.Store, acct, key string, now time.Time) store.JobSubmission {
	t.Helper()
	sub, err := s.SubmitJob(context.Background(), store.SubmitJobInput{
		AccountID: acct, CloudProjectID: "p", CloudSessionID: "s-" + key,
		Tool: "codex", ModelFamily: "gpt-5.6", Feature: store.FeatureSessionEnrichment,
		RouteID: "session_enrichment.luna.v1", RouteVersion: 1, PromptVersion: 1,
		CanonicalKey: key, UploadDigest: "sha256:" + key, ContentDigest: "sha256:c",
		BlobRef: "b", SizeBytes: 1, ConsentGeneration: 0, Now: now,
	})
	if err != nil {
		t.Fatalf("SubmitJob: %v", err)
	}
	return sub
}

type verifiedAttestor struct{}

func (verifiedAttestor) Attest(context.Context, store.RouteInfo, time.Time) (jobs.Attestation, error) {
	return jobs.Attestation{Verified: true}, nil
}

func newWorker(s *store.Store, attestor jobs.ProviderAttestor) *jobs.Worker {
	// Default creds ABSENT (the pre-approval boundary), Noop executor.
	return jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour}, jobs.NewPGQueue(s), s, attestor, nil, nil)
}

func TestProcessOnceNothingDue(t *testing.T) {
	s, _, _ := setup(t)
	w := newWorker(s, nil)
	out, err := w.ProcessOnce(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.JobID != "" {
		t.Fatalf("expected nothing due, got %+v", out)
	}
}

func TestProcessOnceParksProviderUnverified(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	sub := submit(t, s, acct, "canon-unv", now)

	w := newWorker(s, nil) // default UnverifiedAttestor
	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "parked" || out.Reason != store.ReasonProviderPolicyUnverified {
		t.Fatalf("want parked/provider_policy_unverified, got %+v", out)
	}
	// Reservation refunded, evidence deleted, job parked.
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 0 {
		t.Fatalf("unit not refunded on park: daily=%d", snap.DailyUsed)
	}
	j, _ := s.GetJob(ctx, acct, sub.JobID)
	if j.State != "parked" {
		t.Fatalf("job state=%s, want parked", j.State)
	}
}

func TestProcessOnceKillSwitch(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	submit(t, s, acct, "canon-ks", now)
	if err := s.SetKillSwitch(ctx, "global", "all", true); err != nil {
		t.Fatalf("SetKillSwitch: %v", err)
	}
	// Even with a verified attestor, the kill switch parks first.
	w := newWorker(s, verifiedAttestor{})
	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "parked" || out.Reason != store.ReasonKillSwitched {
		t.Fatalf("want parked/kill_switched, got %+v", out)
	}
}

func TestProcessOnceConsentBumpParksReconfirmation(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	submit(t, s, acct, "canon-consent", now)
	// Bump the consent generation after admission.
	if _, err := s.SetConsent(ctx, acct, []string{"bounded_context_enrichment"}, now); err != nil {
		t.Fatalf("SetConsent: %v", err)
	}
	w := newWorker(s, verifiedAttestor{})
	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "parked" || out.Reason != store.ReasonReconfirmationRequired {
		t.Fatalf("want parked/reconfirmation_required, got %+v", out)
	}
}

func TestProcessOnceTTLExpired(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	t0 := time.Now()
	submit(t, s, acct, "canon-ttl", t0)
	// Process near the end of the 1h TTL so headroom cannot be covered.
	late := t0.Add(59 * time.Minute)
	w := newWorker(s, verifiedAttestor{})
	out, err := w.ProcessOnce(ctx, late)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "parked" || out.Reason != store.ReasonEvidenceExpired {
		t.Fatalf("want parked/evidence_expired, got %+v", out)
	}
}

func TestProcessOnceCredentialAbsentParks(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	submit(t, s, acct, "canon-cred", now)
	// Verified attestation, but the DEFAULT worker holds NO provider credential
	// (the §2.1 pre-approval boundary) ⇒ park provider_policy_unverified with no
	// provider call. This is the adversarial guarantee: a normal account's
	// evidence cannot reach a provider while the credential is absent.
	w := newWorker(s, verifiedAttestor{})
	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "parked" || out.Reason != store.ReasonProviderPolicyUnverified {
		t.Fatalf("want parked/provider_policy_unverified (credential absent), got %+v", out)
	}
}

func TestProcessOnceExecutorDeclinesFailsAfterRetries(t *testing.T) {
	s, _, acct := setup(t)
	ctx := context.Background()
	now := time.Now()
	submit(t, s, acct, "canon-exec", now)
	// All gates pass (verified attestation + present credential); the Noop
	// executor declines each attempt ⇒ after the retry budget the job FAILS
	// terminally with a refund (never a fabricated result).
	w := jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour},
		jobs.NewPGQueue(s), s, verifiedAttestor{}, jobs.StaticCredentials{Key: "k"}, nil)
	out, err := w.ProcessOnce(ctx, now)
	if err != nil {
		t.Fatalf("ProcessOnce: %v", err)
	}
	if out.State != "failed" || out.Reason != store.ReasonProviderInvalidOutput {
		t.Fatalf("want failed/provider_invalid_output, got %+v", out)
	}
	// The user unit was refunded (no result produced).
	snap, _ := s.Usage(ctx, acct, store.FeatureSessionEnrichment, now)
	if snap.DailyUsed != 0 {
		t.Fatalf("unit not refunded on terminal fail: daily=%d", snap.DailyUsed)
	}
}

// TestWorkerRefusesNonProductionRoute is the F10 mirror guard. The fixture-only
// proving lane accepts ONLY route_registry.environment='nonproduction'; this is
// the other half of that partition, so the two lanes' route sets are disjoint by
// construction and an operator who classifies a route for proving cannot leave
// real developer evidence routed through it.
//
// It is an A/B on one variable. Everything else is held identical and set to
// PASS — verified attestation, a present credential, the same job — so the only
// thing that can explain the difference in outcome is the environment column:
// a production route reaches the executor (which declines, terminally), a
// non-production one is parked before the credential gate is even consulted.
func TestWorkerRefusesNonProductionRoute(t *testing.T) {
	const routeID = "session_enrichment.luna.v1"
	cases := []struct {
		name        string
		environment string
		wantState   string
		wantReason  string
	}{
		{
			name:        "production route is served",
			environment: store.RouteEnvironmentProduction,
			wantState:   "failed",
			wantReason:  store.ReasonProviderInvalidOutput,
		},
		{
			name:        "nonproduction route is refused",
			environment: store.RouteEnvironmentNonProduction,
			wantState:   "parked",
			wantReason:  store.ReasonProviderPolicyUnverified,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, acct := setup(t)
			ctx := context.Background()
			now := time.Now()
			submit(t, s, acct, "canon-env-"+c.environment, now)

			if err := s.SetRouteEnvironment(ctx, routeID, c.environment); err != nil {
				t.Fatalf("SetRouteEnvironment(%s): %v", c.environment, err)
			}
			// Verified attestation AND a present credential: every other gate
			// passes, so the outcome isolates the environment check.
			w := jobs.NewWorker(jobs.Config{WorkerID: "w1", LeaseFor: time.Hour},
				jobs.NewPGQueue(s), s, verifiedAttestor{}, jobs.StaticCredentials{Key: "k"}, nil)
			out, err := w.ProcessOnce(ctx, now)
			if err != nil {
				t.Fatalf("ProcessOnce: %v", err)
			}
			if out.State != c.wantState || out.Reason != c.wantReason {
				t.Fatalf("environment=%s ⇒ %s/%s, want %s/%s",
					c.environment, out.State, out.Reason, c.wantState, c.wantReason)
			}
		})
	}
}

// TestRouteEnvironmentDefaultsToProduction pins the fail-closed direction of the
// F10 column: a route nobody classified is PRODUCTION, so the worker serves it
// and the proving lane refuses it. The opposite default would silently make
// every existing route provable.
func TestRouteEnvironmentDefaultsToProduction(t *testing.T) {
	s, _, _ := setup(t)
	r, err := s.RouteByID(context.Background(), "session_enrichment.luna.v1")
	if err != nil {
		t.Fatalf("RouteByID: %v", err)
	}
	if r.Environment != store.RouteEnvironmentProduction {
		t.Fatalf("the seeded route's environment = %q, want %q",
			r.Environment, store.RouteEnvironmentProduction)
	}
}

// TestRefusingAttestorNeverVerifies pins the cache-free conflict attestor:
// it reports NOT verified with its reason, regardless of any persisted
// attestation record (it never touches the store).
func TestRefusingAttestorNeverVerifies(t *testing.T) {
	t.Parallel()
	a, err := jobs.RefusingAttestor{Reason: "conflicting attestation modes configured (fail closed)"}.Attest(context.Background(), store.RouteInfo{RouteID: "r"}, time.Now())
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if a.Verified || a.Reason != "conflicting attestation modes configured (fail closed)" {
		t.Fatalf("got %+v, want unverified with the configured reason", a)
	}
	if d, _ := (jobs.RefusingAttestor{}).Attest(context.Background(), store.RouteInfo{}, time.Now()); d.Verified || d.Reason == "" {
		t.Fatalf("zero-value RefusingAttestor: got %+v, want unverified with a default reason", d)
	}
}
