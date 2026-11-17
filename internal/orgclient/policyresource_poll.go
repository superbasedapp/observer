package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
)

// PolicyResourceSelectorCapability is the capability token this agent
// advertises on every GET /api/agent/policy/{family} — the design's R2
// mixed-fleet compatibility gate
// (docs/plans/policy-targeting-rollback-design-2026-08-13.md §8 R2).
//
// Pre-P0-10 agents reject EVERY targeted envelope outright (their closed-
// envelope gate required selectors_json == "{}"), so the server must only
// serve a targeted resource to a subject that positively advertises it can
// evaluate selectors. The marker grants nothing: the server still resolves
// the audience from attributes bound to the verified identity, not from
// anything the fetching node presents, and claiming it falsely only makes the
// agent reject envelopes it cannot evaluate. It is NOT simply downgrade-only,
// though: omitting it can turn a delivery into "no applicable policy", which
// since the signed withdrawal (D-192) may be a signed tombstone. The server
// therefore re-resolves a marker-less request as selector capable and
// withdraws only when that finds nothing either (C156-17).
const PolicyResourceSelectorCapability = "selectors"

// policyResourceFetchURL builds the agent-side policy-resource GET URL,
// including the R2 capability marker. It is the ONE place that URL is
// composed (receivePolicyResource calls it), so the marker can never be
// present on one code path and missing on another.
//
// The other markers are the node.governance target (nodegov.CapabilityTokens:
// the section vocabulary level, the highest body schema and the key
// vocabulary generation this build compiles): the server projects the body it
// serves onto exactly that, so a page, schema or pinned key only newer builds
// have never costs this node the rest of its governance. They ride as
// repeated values so a server reading only the first policy_caps value still
// sees "selectors", and a server that predates a token ignores it. The last
// marker asks for a v2 (org-, member- and target-bound) signature
// (orgcontract.PolicyBindingCapability); a server that predates it keeps
// serving v1.
func policyResourceFetchURL(orgURL, family string) string {
	caps := append([]string{PolicyResourceSelectorCapability}, nodegov.CapabilityTokens()...)
	caps = append(caps, orgcontract.PolicyBindingCapability)
	q := url.Values{"policy_caps": caps}
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
	return c.PolicyResourcePollLoopLive(ctx, func() PolicyResourceOptions { return opts }, onResult)
}

// PolicyResourcePollLoopLive is PolicyResourcePollLoop with the options
// resolved again at the start of EVERY cycle (demo finding #23, 2026-11-10).
// The accept and preauthorize lists live in config.toml, and a managed
// enrolment made while the daemon runs (`observer enroll` in another
// process, or the dashboard) writes them there: with options captured once
// at daemon start, a node that started individual and was re-enrolled
// managed kept fetching node.governance and reporting it delivered but not
// accepted until a restart. opts must be cheap and must not block; a nil
// opts is the zero options.
func (c *Client) PolicyResourcePollLoopLive(ctx context.Context, opts func() PolicyResourceOptions, onResult func(PolicyResourcePollResult)) error {
	if opts == nil {
		opts = func() PolicyResourceOptions { return PolicyResourceOptions{} }
	}
	cycle := func(ctx context.Context) error {
		var notEnrolled, authFailed bool
		cycleOpts := opts()
		for _, family := range policyfam.SupportedFamilies {
			res, err := c.FetchAndAcceptPolicyResource(ctx, family, cycleOpts)
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

// KickPolicyResourcePoll wakes PolicyResourcePollLoop for an immediate fetch
// cycle (non-blocking; a pending kick coalesces). The daemon calls it when
// its enrolment identity or its policy accept lists change, and after a
// dashboard push-now, so a change made while it runs is fetched in seconds
// instead of at the next hourly poll. Like every kick it only advances the
// poll: the fetch applies every gate unchanged. Nil-safe.
func (c *Client) KickPolicyResourcePoll() {
	if c == nil || c.policyResourceKick == nil {
		return
	}
	select {
	case c.policyResourceKick <- struct{}{}:
	default:
	}
}

// ActiveIdentity is ActiveEnrolmentIdentity over this client's store: the
// live (org key, generation) of the enrolment, read fresh. ok=false when not
// enrolled or tombstoned. Nil-safe.
func (c *Client) ActiveIdentity(ctx context.Context) (orgKey string, generation int64, ok bool) {
	if c == nil {
		return "", 0, false
	}
	return ActiveEnrolmentIdentity(ctx, c.store)
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
		RailVersions   map[string]int64 `json:"rail_versions"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return
	}
	// The rail half (2026-10-02 budget-latency arc) only records the
	// freshness checker's baseline: this same push cycle already refreshed
	// those rails.
	c.recordRailVersions(ack.RailVersions)
	// ONE comparison shared with the policy-version probe
	// (policyfreshness.go notePolicyVersions), so the ack and the probe can
	// never disagree about what "advanced" means.
	if !c.notePolicyVersions(ack.PolicyVersions) {
		return
	}
	select {
	case c.policyResourceKick <- struct{}{}:
		c.logger.Info("org policy resource: newer version published - fetching now (push-ack nudge)")
	default:
		// A kick is already pending; one cycle covers both.
	}
}
