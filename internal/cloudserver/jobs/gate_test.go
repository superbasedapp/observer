package jobs_test

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/attest"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

const gateRoute = "session_enrichment.luna.v1"

// mustRoute resolves the current route snapshot the way the worker does, so the
// gate is handed the same immutable snapshot it must attest against (FA1). It is
// resolved at each call site so a generation bump between calls is reflected.
func mustRoute(t *testing.T, s *store.Store) store.RouteInfo {
	t.Helper()
	r, err := s.RouteByID(context.Background(), gateRoute)
	if err != nil {
		t.Fatalf("RouteByID: %v", err)
	}
	return r
}

func bindRoute(t *testing.T, s *store.Store) {
	t.Helper()
	if err := s.SetRouteBinding(context.Background(), gateRoute, store.RouteBinding{
		TenantID: "t-1", SubscriptionID: "s-1",
		ARMResourceID:    "/subscriptions/s-1/providers/Microsoft.CognitiveServices/accounts/luna",
		EndpointAudience: "https://management.azure.com",
	}); err != nil {
		t.Fatalf("SetRouteBinding: %v", err)
	}
}

func TestAttestationGateFreshReadPersistsAndCaches(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	bindRoute(t, s)
	fake := &attest.FakeAttestor{Result: attest.Attestation{Healthy: true, ContentLoggingValue: "false", Reason: "disabled"}}
	gate := jobs.NewAttestationGate(s, fake, 15*time.Minute)

	t0 := time.Now()
	att, err := gate.Attest(ctx, mustRoute(t, s), t0)
	if err != nil || !att.Verified {
		t.Fatalf("fresh read not verified: %+v err=%v", att, err)
	}
	if fake.Calls != 1 {
		t.Fatalf("want 1 ARM read, got %d", fake.Calls)
	}
	// Persisted.
	if rec, err := s.LatestAttestation(ctx, gateRoute); err != nil || !rec.Healthy {
		t.Fatalf("attestation not persisted healthy: %+v err=%v", rec, err)
	}
	// Within maxAge ⇒ cached, no second ARM read.
	att2, err := gate.Attest(ctx, mustRoute(t, s), t0.Add(time.Minute))
	if err != nil || !att2.Verified {
		t.Fatalf("cached read not verified: %+v", att2)
	}
	if fake.Calls != 1 {
		t.Fatalf("cache not reused: ARM read %d times", fake.Calls)
	}
}

func TestAttestationGateDoesNotInheritAnotherConfiguration(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	bindRoute(t, s)
	route := mustRoute(t, s)
	now := time.Now()
	old := jobs.NewAttestationGate(s, attest.DisclosedAttestor{
		AttestedResourceID: route.ARMResourceID, PolicyVersion: "1",
	}, time.Hour)
	for _, tc := range []struct {
		name     string
		attestor attest.Attestor
	}{
		{"ARM without credentials", &attest.ARMAttestor{}},
		{"missing disclosure version", attest.DisclosedAttestor{AttestedResourceID: route.ARMResourceID}},
		{"different disclosed resource", attest.DisclosedAttestor{AttestedResourceID: "/other", PolicyVersion: "1"}},
		{"operator without covered resource", attest.OperatorAttestor{}},
		{"refusing configuration", attest.RefusingAttestor{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An older replica can keep refreshing the shared audit record.
			if got, err := old.Attest(ctx, route, now); err != nil || !got.Verified {
				t.Fatalf("seed disclosed verdict: %+v, %v", got, err)
			}
			fresh := jobs.NewAttestationGate(s, tc.attestor, time.Hour)
			if got, err := fresh.Attest(ctx, route, now.Add(time.Second)); err != nil || got.Verified {
				t.Fatalf("new configuration inherited disclosed authorization: %+v, %v", got, err)
			}
		})
	}
}

func TestAttestationGateStalenessReReads(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	bindRoute(t, s)
	fake := &attest.FakeAttestor{Result: attest.Attestation{Healthy: true, ContentLoggingValue: "false"}}
	gate := jobs.NewAttestationGate(s, fake, 15*time.Minute)

	t0 := time.Now()
	if _, err := gate.Attest(ctx, mustRoute(t, s), t0); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Past maxAge ⇒ stale cache ⇒ fresh ARM read.
	if _, err := gate.Attest(ctx, mustRoute(t, s), t0.Add(16*time.Minute)); err != nil {
		t.Fatalf("second: %v", err)
	}
	if fake.Calls != 2 {
		t.Fatalf("stale cache not re-read: ARM read %d times", fake.Calls)
	}
}

func TestAttestationGateGenerationFlipInvalidatesCacheAndUnhealthyFailsClosed(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	bindRoute(t, s)
	fake := &attest.FakeAttestor{Result: attest.Attestation{Healthy: true, ContentLoggingValue: "false"}}
	gate := jobs.NewAttestationGate(s, fake, 15*time.Minute)

	t0 := time.Now()
	if att, _ := gate.Attest(ctx, mustRoute(t, s), t0); !att.Verified {
		t.Fatal("first read not verified")
	}
	// A route/config change bumps the generation; the cached attestation no
	// longer matches ⇒ re-read. And now the resource reports ContentLogging
	// FLIPPED ON ⇒ unhealthy ⇒ fail closed.
	bindRoute(t, s) // bumps generation
	fake.Result = attest.Attestation{Healthy: false, ContentLoggingValue: "true", Reason: "content logging enabled"}
	att, err := gate.Attest(ctx, mustRoute(t, s), t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("post-flip: %v", err)
	}
	if att.Verified {
		t.Fatalf("generation flip + unhealthy must fail closed, got verified: %+v", att)
	}
	if fake.Calls != 2 {
		t.Fatalf("generation flip did not invalidate cache: ARM read %d times", fake.Calls)
	}
}

func TestAttestationGateAttestorErrorFailsClosed(t *testing.T) {
	s, _, _ := setup(t)
	ctx := context.Background()
	bindRoute(t, s)
	fake := &attest.FakeAttestor{Result: attest.Attestation{Healthy: true}, Func: func(context.Context, attest.Binding, time.Time) (attest.Attestation, error) {
		return attest.Attestation{}, context.DeadlineExceeded
	}}
	gate := jobs.NewAttestationGate(s, fake, 15*time.Minute)
	att, err := gate.Attest(ctx, mustRoute(t, s), time.Now())
	if err != nil {
		t.Fatalf("gate returned hard error: %v", err)
	}
	if att.Verified {
		t.Fatalf("attestor error must fail closed, got verified")
	}
}
