package orgdeletion

import "time"

// stepup.go is the org deletion's re-authentication rule (FR-23): opening a
// team's deletion is irreversible once the window ends, so a session alone
// is not enough. The console route asks [DecideStepUp] what the request
// must show; the table is walked top-down and the first match decides.

// StepUpVerdict is what an org deletion request must do to prove the person
// is present.
type StepUpVerdict string

// The verdicts.
const (
	// StepUpVerifyBroker: dev sign-in; verify the re-presented broker
	// credential resolves to the caller's account.
	StepUpVerifyBroker StepUpVerdict = "verify_broker_token"
	// StepUpConsumeAuthorization: consume the one-use step-up authorization
	// in the transaction that opens the deletion.
	StepUpConsumeAuthorization StepUpVerdict = "consume_authorization"
	// StepUpFreshPasskey: the account has a passkey and this session used it
	// within [FreshPasskeyWindow]; nothing more is asked.
	StepUpFreshPasskey StepUpVerdict = "fresh_passkey"
	// StepUpRefuseReauth: dev sign-in with no credential re-presented.
	StepUpRefuseReauth StepUpVerdict = "refuse_reauth_required"
	// StepUpRefuseStepUp: re-authenticate (the WorkOS step-up leg) first.
	StepUpRefuseStepUp StepUpVerdict = "refuse_step_up_required"
	// StepUpRefuseUnavailable: no re-authentication path is available on
	// this deployment, so the deletion cannot be confirmed.
	StepUpRefuseUnavailable StepUpVerdict = "refuse_unavailable"
)

// Allows reports a verdict that lets the request through (after its check).
func (v StepUpVerdict) Allows() bool {
	switch v {
	case StepUpVerifyBroker, StepUpConsumeAuthorization, StepUpFreshPasskey:
		return true
	}
	return false
}

// FreshPasskeyWindow is how recent a passkey use in the session must be to
// stand in for a step-up.
const FreshPasskeyWindow = 5 * time.Minute

// StepUpFacts is what the decision reads.
type StepUpFacts struct {
	// DevAuth: the deployment signs in with the dev broker.
	DevAuth bool
	// WorkOSStepUp: the WorkOS step-up leg is live.
	WorkOSStepUp bool
	// BrokerTokenPresented and AuthorizationPresented say what the request
	// carries.
	BrokerTokenPresented   bool
	AuthorizationPresented bool
	// PasskeyEnrolled: the account has an active passkey.
	PasskeyEnrolled bool
	// PasskeyAt is the session's last passkey use (zero: none).
	PasskeyAt time.Time
	Now       time.Time
}

// passkeyFresh reports a passkey use within the window and not in the
// future (a minute of clock skew allowed).
func passkeyFresh(f StepUpFacts) bool {
	if !f.PasskeyEnrolled || f.PasskeyAt.IsZero() || f.PasskeyAt.After(f.Now.Add(time.Minute)) {
		return false
	}
	return f.Now.Sub(f.PasskeyAt) <= FreshPasskeyWindow
}

// stepUpRule is one row of the step-up table.
type stepUpRule struct {
	name    string
	match   func(f StepUpFacts) bool
	verdict StepUpVerdict
}

// stepUpRules is the table, walked top-down; the last row always matches.
// One test case per row.
func stepUpRules() []stepUpRule {
	return []stepUpRule{
		{
			name:    "dev sign-in with a re-presented credential: verify it",
			match:   func(f StepUpFacts) bool { return f.DevAuth && f.BrokerTokenPresented },
			verdict: StepUpVerifyBroker,
		},
		{
			name:    "dev sign-in without one: ask for it",
			match:   func(f StepUpFacts) bool { return f.DevAuth },
			verdict: StepUpRefuseReauth,
		},
		{
			name:    "a step-up authorization on a live step-up leg: consume it with the deletion",
			match:   func(f StepUpFacts) bool { return f.WorkOSStepUp && f.AuthorizationPresented },
			verdict: StepUpConsumeAuthorization,
		},
		{
			name:    "a passkey used in this session within the window: enough",
			match:   passkeyFresh,
			verdict: StepUpFreshPasskey,
		},
		{
			name:    "a live step-up leg: re-authenticate first",
			match:   func(f StepUpFacts) bool { return f.WorkOSStepUp },
			verdict: StepUpRefuseStepUp,
		},
		{
			name:    "no way to re-authenticate on this deployment",
			match:   func(StepUpFacts) bool { return true },
			verdict: StepUpRefuseUnavailable,
		},
	}
}

// DecideStepUp returns the deciding row's verdict for f.
func DecideStepUp(f StepUpFacts) StepUpVerdict {
	rules := stepUpRules()
	for _, r := range rules {
		if r.match(f) {
			return r.verdict
		}
	}
	return rules[len(rules)-1].verdict
}

// ReauthKind is what the console's preview tells the page to collect before
// it asks: "step_up" (the WorkOS step-up leg), "broker_token" (dev sign-in)
// or "unavailable".
func ReauthKind(devAuth, workOSStepUp bool) string {
	switch {
	case devAuth:
		return "broker_token"
	case workOSStepUp:
		return "step_up"
	}
	return "unavailable"
}
