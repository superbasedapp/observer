package attest

import (
	"context"
	"strings"
	"time"
)

// ModeProviderRetentionDisclosed names the third attestation mode (operator
// ruling 2026-09-15, option C of docs/modified-abuse-monitoring-filing.md s7):
// the provider's DEFAULT abuse-monitoring posture is accepted and DISCLOSED
// rather than asserted away. Its healthy verdict means "prompts and completions
// are processed statelessly and never used for training; classifier-flagged
// samples may be stored by the provider for abuse review; that posture is
// published on the privacy page under the named policy version" — it never
// means ContentLogging is disabled, and the record says so in its own words.
const ModeProviderRetentionDisclosed = "provider_retention_disclosed"

// DisclosedAttestor is the explicit, operator-asserted disclosed-posture mode.
// It exists so that a resource whose ContentLogging capability is NOT false
// (the default for every Azure AI Foundry resource without Modified Abuse
// Monitoring approval) can be authorized honestly: OperatorAttestor asserts
// "false (operator-attested)", which would be a lie on such a resource, and
// ARMAttestor reads the capability live and fails closed on it. This mode
// records the disclosure, the policy version it was made under, the exact
// resource and the asserting identity, and the ContentLoggingValue it persists
// is explicitly "not-disabled". It performs no network read and holds no
// credential; it is scoped to exactly one resource and fails closed on every
// other binding, on an incomplete binding, and on an empty policy version
// (an undisclosed posture is not a disclosed one).
type DisclosedAttestor struct {
	// AttestedResourceID is the exact route.ARMResourceID the disclosure covers.
	// Empty verifies nothing (fail closed).
	AttestedResourceID string
	// PolicyVersion is the published privacy-policy version the disclosure was
	// made under (e.g. "1"). Empty verifies nothing (fail closed).
	PolicyVersion string
	// AttestedBy is the operator identity recorded in the verdict for audit.
	AttestedBy string
}

var _ Attestor = DisclosedAttestor{}

// Attest returns a healthy verdict ONLY for the exact attested resource under a
// non-empty policy version; every other binding (or an incomplete one) fails
// closed. The verdict names the mode, the policy version, the resource and the
// attester, and its ContentLoggingValue never reads as "false".
func (d DisclosedAttestor) Attest(_ context.Context, b Binding, now time.Time) (Attestation, error) {
	res := Attestation{Binding: b, FetchedAt: now, Healthy: false}
	if !b.Complete() {
		res.Reason = ModeProviderRetentionDisclosed + ": route not bound to a resource (fail closed)"
		return res, nil
	}
	want := strings.TrimSpace(d.AttestedResourceID)
	if want == "" || b.ARMResourceID != want {
		res.Reason = ModeProviderRetentionDisclosed + ": resource not covered by the disclosure (fail closed)"
		return res, nil
	}
	ver := strings.TrimSpace(d.PolicyVersion)
	if ver == "" {
		res.Reason = ModeProviderRetentionDisclosed + ": no policy version named (fail closed)"
		return res, nil
	}
	by := strings.TrimSpace(d.AttestedBy)
	if by == "" {
		by = "operator"
	}
	res.Healthy = true
	res.ContentLoggingValue = "not-disabled (" + ModeProviderRetentionDisclosed + "; policy v" + ver + ")"
	res.Reason = ModeProviderRetentionDisclosed + ": provider flagged-sample retention disclosed under privacy policy v" + ver +
		" for " + want + " by " + by
	return res, nil
}

// RefusingAttestor always fails closed with a fixed reason. It is what a
// deployment gets when its attestation configuration is ambiguous (two modes
// set at once): the ambiguity is logged at startup and every job parks
// provider_policy_unverified until an operator picks one mode.
type RefusingAttestor struct {
	Reason string
}

var _ Attestor = RefusingAttestor{}

// Attest always returns an unhealthy verdict carrying the configured reason.
func (r RefusingAttestor) Attest(_ context.Context, b Binding, now time.Time) (Attestation, error) {
	reason := strings.TrimSpace(r.Reason)
	if reason == "" {
		reason = "attestation refused (fail closed)"
	}
	return Attestation{Binding: b, FetchedAt: now, Healthy: false, Reason: reason}, nil
}
