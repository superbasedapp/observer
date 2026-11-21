package orgdeletion

import (
	"testing"
	"time"
)

// TestDecideStepUp: one case per row of the step-up table (FR-23), plus the
// passkey window's edges.
func TestDecideStepUp(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		f     StepUpFacts
		want  StepUpVerdict
		allow bool
	}{
		{name: "dev sign-in with a credential", f: StepUpFacts{DevAuth: true, BrokerTokenPresented: true}, want: StepUpVerifyBroker, allow: true},
		{name: "dev sign-in without one", f: StepUpFacts{DevAuth: true, AuthorizationPresented: true}, want: StepUpRefuseReauth},
		{name: "a step-up authorization on a live leg", f: StepUpFacts{WorkOSStepUp: true, AuthorizationPresented: true}, want: StepUpConsumeAuthorization, allow: true},
		{name: "a fresh passkey", f: StepUpFacts{WorkOSStepUp: true, PasskeyEnrolled: true, PasskeyAt: now.Add(-time.Minute), Now: now}, want: StepUpFreshPasskey, allow: true},
		{name: "a stale passkey on a live leg", f: StepUpFacts{WorkOSStepUp: true, PasskeyEnrolled: true, PasskeyAt: now.Add(-FreshPasskeyWindow - time.Second), Now: now}, want: StepUpRefuseStepUp},
		{name: "a passkey time in the future", f: StepUpFacts{WorkOSStepUp: true, PasskeyEnrolled: true, PasskeyAt: now.Add(2 * time.Minute), Now: now}, want: StepUpRefuseStepUp},
		{name: "a passkey use without an enrolled passkey", f: StepUpFacts{WorkOSStepUp: true, PasskeyAt: now, Now: now}, want: StepUpRefuseStepUp},
		{name: "a live leg and nothing presented", f: StepUpFacts{WorkOSStepUp: true}, want: StepUpRefuseStepUp},
		{name: "an authorization with the leg dark", f: StepUpFacts{AuthorizationPresented: true}, want: StepUpRefuseUnavailable},
		{name: "a fresh passkey with the leg dark", f: StepUpFacts{PasskeyEnrolled: true, PasskeyAt: now, Now: now}, want: StepUpFreshPasskey, allow: true},
		{name: "nothing at all", f: StepUpFacts{}, want: StepUpRefuseUnavailable},
	} {
		got := DecideStepUp(tc.f)
		if got != tc.want || got.Allows() != tc.allow {
			t.Errorf("%s: DecideStepUp = %s (allows %v), want %s (allows %v)", tc.name, got, got.Allows(), tc.want, tc.allow)
		}
	}
}

// TestReauthKind: one row per kind.
func TestReauthKind(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		dev, workos bool
		want        string
	}{
		{true, false, "broker_token"},
		{true, true, "broker_token"},
		{false, true, "step_up"},
		{false, false, "unavailable"},
	} {
		if got := ReauthKind(tc.dev, tc.workos); got != tc.want {
			t.Errorf("ReauthKind(%v, %v) = %q, want %q", tc.dev, tc.workos, got, tc.want)
		}
	}
}
