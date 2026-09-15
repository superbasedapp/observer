package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/marmutapp/superbased-observer/internal/policyfam"
)

// PolicyResourceSelectorCapability is the capability token this agent
// advertises on every GET /api/agent/policy/{family} — the design's R2
// mixed-fleet compatibility gate
// (docs/plans/policy-targeting-rollback-design-2026-08-13.md §8 R2).
//
// Pre-P0-10 agents reject EVERY targeted envelope outright (their closed-
// envelope gate required selectors_json == "{}"), so the server must only
// serve a targeted resource to a subject that positively advertises it can
// evaluate selectors. SELF-DECLARATION IS SAFE HERE because the marker is
// strictly DOWNGRADE-ONLY: omitting it can only yield untargeted resources
// (or "no applicable policy"), and claiming it falsely only makes the agent
// reject envelopes it cannot evaluate. It grants nothing — an attacker
// cannot use it to widen what they are served, because the server still
// resolves the audience from attributes bound to the verified identity, not
// from anything the fetching node presents.
const PolicyResourceSelectorCapability = "selectors"

// policyResourceFetchURL builds the agent-side policy-resource GET URL,
// including the R2 capability marker. It is the ONE place that URL is
// composed (receivePolicyResource calls it), so the marker can never be
// present on one code path and missing on another.
func policyResourceFetchURL(orgURL, family string) string {
	q := url.Values{"policy_caps": []string{PolicyResourceSelectorCapability}}
	return NormalizeOrgURL(orgURL) + "/api/agent/policy/" + family + "?" + q.Encode()
}

// PolicyResourcePollResult pairs one v1 policy-resource family's fetch
// outcome for PolicyResourcePollLoop's callback (Plane-A P0-5 Phase W, plan
// §6.6/§6.9). Err is the raw FetchAndAcceptPolicyResource error (possibly
// wrapping ErrNotEnrolled/ErrAuthFailed/a transport failure) — the zero
// Result is meaningless whenever Err != nil.
type PolicyResourcePollResult struct {
	Family string
	Result PolicyResourceResult
	Err    error
}

// PolicyResourcePollLoop fetches EVERY v1 policy-resource family
// (policyfam.SupportedFamilies) once immediately, then on every poll
// interval, until ctx is cancelled or the server rejects the bearer (plan
// §6.6: "poll both families whenever enrolled, independent of
// accept_families or share.policy_state"). onResult, when non-nil, is
// called for EVERY family on EVERY cycle — including a not-enrolled or
// transport-failure cycle — so the caller can apply PublishOrg/ClearOrg
// under its own admission-service fence exactly as plan §6.9 requires
// ("When a poll returns ErrNotEnrolled, it must use this same outcome path
// rather than merely skip its callback").
//
// This reuses the SAME jittered-backoff loop contract as PolicyPollLoop/
// PushLoop (c.runLoop): a not-enrolled cycle is treated like errIdle (retry
// at the plain interval, no backoff — not-enrolled is an expected steady
// state, not a failure), an auth failure stops the loop, and any other
// error backs off exponentially.
func (c *Client) PolicyResourcePollLoop(ctx context.Context, opts PolicyResourceOptions, onResult func(PolicyResourcePollResult)) error {
	cycle := func(ctx context.Context) error {
		var notEnrolled, authFailed bool
		for _, family := range policyfam.SupportedFamilies {
			res, err := c.FetchAndAcceptPolicyResource(ctx, family, opts)
			if onResult != nil {
				onResult(PolicyResourcePollResult{Family: family, Result: res, Err: err})
			}
			switch {
			case errors.Is(err, ErrNotEnrolled):
				notEnrolled = true
			case errors.Is(err, ErrAuthFailed):
				authFailed = true
			case err != nil && !errors.Is(err, context.Canceled):
				c.logger.Warn("org policy resource: fetch failed", "family", family, "err", err)
			}
		}
		switch {
		case authFailed:
			return ErrAuthFailed
		case notEnrolled:
			return errIdle
		default:
			return nil
		}
	}
	// Immediate first fetch; its failure classes repeat through the loop
	// anyway, so a failure here only logs (an auth failure still stops).
	if err := cycle(ctx); errors.Is(err, ErrAuthFailed) {
		c.logger.Error("org policy resource: authentication failed, stopping poll", "err", err)
		return nil
	} else if err != nil && !errors.Is(err, errIdle) && !errors.Is(err, context.Canceled) {
		c.logger.Warn("org policy resource: initial fetch failed", "err", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return c.runLoopKick(ctx, c.policyPollInterval(), c.policyResourceKick, cycle)
}

// maybeKickPolicyResourceFetch is the receiving half of the push-ack
// policy-propagation nudge (2026-09-01; see orgcontract.PushResponse
// .PolicyVersions). It decodes the version map from the RAW push response —
// the same raw-body pattern as maybeApplyGrantReplacement, so no client
// regeneration — and wakes PolicyResourcePollLoop when any family's latest
// version advanced past what the previous acknowledgment reported. The very
// first acknowledgment after boot never kicks: the poll loop's own immediate
// first fetch already covered it. The kick carries NO policy content — the
// woken cycle fetches, verifies, and gates acceptance exactly as a timed one
// does.
func (c *Client) maybeKickPolicyResourceFetch(body []byte) {
	var ack struct {
		PolicyVersions map[string]int64 `json:"policy_versions"`
	}
	if err := json.Unmarshal(body, &ack); err != nil || len(ack.PolicyVersions) == 0 {
		return
	}
	c.policyVersMu.Lock()
	prev := c.lastPolicyVersions
	c.lastPolicyVersions = ack.PolicyVersions
	c.policyVersMu.Unlock()
	if prev == nil {
		return
	}
	advanced := false
	for family, v := range ack.PolicyVersions {
		if v > prev[family] {
			advanced = true
			break
		}
	}
	if !advanced {
		return
	}
	select {
	case c.policyResourceKick <- struct{}{}:
		c.logger.Info("org policy resource: newer version published — fetching now (push-ack nudge)")
	default:
		// A kick is already pending; one cycle covers both.
	}
}
