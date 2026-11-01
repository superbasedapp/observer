package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfresh"
)

// The node's policy-freshness checker (2026-10-02 budget-latency arc, P2).
//
// Activity on the node (a proxied request, a prompt hook) wakes this loop; the
// pure table (internal/policyfresh) decides whether to probe now, later, or
// not at all; a probe is ONE conditional GET of the org's version vector
// (GET /api/agent/policy-version, usually a bodiless 304); and only the rails
// whose version moved are fetched - each through its OWN signed, pinned,
// monotonic path, unchanged. The probe answer is a hint and nothing else: it
// can never apply, lower, raise or clear anything (docs/security.md
// POLICY-PROBE-1).
//
// The push loop keeps refreshing the budget/pricing/routing/announcement
// rails on its ceiling tick and the policy loops keep their own polls; this
// checker only makes a CHANGE arrive sooner. A server without the probe
// answers 404: the checker goes quiet for an hour and everything converges
// exactly as before.
//
// HELD PROBES (T-474). While the node is active its probe asks the server to
// hold the request open until a version moves (policyfresh.DefaultHold), and
// a finished probe is re-armed at once, so a change reaches an active node
// in about a second instead of up to the 30 s activity floor, at about one
// request per hold. The probe runs on its own goroutine so a held request
// never delays the ack-queued dispatch; its answer is applied on this loop.
// A server that does not hold never sets orgcontract.HeaderPolicyVersionsHold,
// and the node then keeps the pre-hold cadence.

// freshState is the checker's memory (one owner: PolicyFreshnessLoop, plus
// the push-ack path that records the rail baseline).
type freshState struct {
	mu       sync.Mutex
	st       policyfresh.State
	etag     string
	lastRail map[string]int64
	// pending is the set of rails a push acknowledgment reported moved that
	// the push cycle itself does not refresh; PolicyFreshnessLoop drains it
	// (freshDispatch wakes it).
	pending map[string]bool
	// loggedUnsupported dedups the 404 info line.
	loggedUnsupported bool
}

// pushCycleRails are the rails a rail-refreshing push cycle fetches itself:
// budget + pricing before the push, routing + announcement + display + grants after
// it. The guard bundle is NOT one of them (PolicyPollLoop owns it), so a
// bundle move seen on an ack is always dispatched.
var pushCycleRails = map[string]bool{
	orgcontract.RailBudget:       true,
	orgcontract.RailPricing:      true,
	orgcontract.RailRouting:      true,
	orgcontract.RailAnnouncement: true,
	orgcontract.RailDisplay:      true,
	orgcontract.RailGrants:       true,
	orgcontract.RailAgentConfig:  true,
	orgcontract.RailMessages:     true,
}

// railFetch is one row of the dispatch table: the rail keys it answers for
// and the ONE fetch that refreshes them through that rail's own signed path.
type railFetch struct {
	keys  []string
	fetch func(c *Client, ctx context.Context)
}

// railFetchers is THE table mapping a moved rail onto its fetch (CLAUDE.md
// #5); the server's railVersionRows (orgserver/api/policyversions.go) is its
// other half. A row whose keys moved runs once per dispatch.
var railFetchers = []railFetch{
	{
		// The two rails are one governance fact (a cap and the rate it is
		// measured in) and are always refreshed together.
		keys: []string{orgcontract.RailBudget, orgcontract.RailPricing},
		fetch: func(c *Client, ctx context.Context) {
			c.logger.Info("org budget/pricing changed - fetching now (policy-version probe)")
			c.refreshBudgetRails(ctx)
		},
	},
	{
		keys: []string{orgcontract.RailBundle},
		fetch: func(c *Client, _ context.Context) {
			select {
			case c.policyBundleKick <- struct{}{}:
				c.logger.Info("org guard policy bundle changed - fetching now (policy-version probe)")
			default:
			}
		},
	},
	{
		keys: []string{orgcontract.RailRouting},
		fetch: func(c *Client, ctx context.Context) {
			c.routingNotFound.Reset()
			c.railsMu.Lock()
			_, outcome, _ := c.FetchRoutingPolicy(ctx)
			c.railsMu.Unlock()
			if outcome != nil && c.routingOutcomeSink != nil {
				c.routingOutcomeSink(*outcome)
			}
		},
	},
	{
		keys: []string{orgcontract.RailAnnouncement},
		fetch: func(c *Client, ctx context.Context) {
			c.announcementNotFound.Reset()
			c.railsMu.Lock()
			_, _ = c.FetchOrgAnnouncement(ctx)
			c.railsMu.Unlock()
		},
	},
	{
		keys: []string{orgcontract.RailDisplay},
		fetch: func(c *Client, ctx context.Context) {
			if changed, err := c.refreshDisplayPolicy(ctx); err == nil && changed {
				c.logger.Info("org developer cost display changed - applied (policy-version probe)")
			}
		},
	},
	{
		keys: []string{orgcontract.RailGrants},
		fetch: func(c *Client, ctx context.Context) {
			if out, err := c.refreshAccessGrants(ctx); err == nil && out.State == GrantFetchApplied {
				c.logger.Info("org access grants changed - applied (policy-version probe)", "version", out.Version)
			}
		},
	},
	{
		// The org AI tool policy (adapter config P6): its own signed,
		// pinned, monotonic path, gated to managed nodes.
		keys: []string{orgcontract.RailAgentConfig},
		fetch: func(c *Client, ctx context.Context) {
			if changed, err := c.refreshAgentConfigPolicy(ctx); err == nil && changed {
				c.logger.Info("org AI tool policy changed - applying (policy-version probe)")
			}
		},
	},
	{
		// Admin and developer messaging (T-854): a send, reply, close or
		// settings change moves the org's message version, so a new message
		// reaches an active node in seconds instead of a push interval. The
		// 404 backoff is re-armed first: the org just said the rail exists.
		keys: []string{orgcontract.RailMessages},
		fetch: func(c *Client, ctx context.Context) {
			c.messages.notFound.Reset()
			if res, err := c.SyncOrgMessages(ctx); err == nil && res.Received > 0 {
				c.logger.Info("org messages received (policy-version probe)", "count", res.Received)
			}
		},
	},
}

// NoteActivity reports node activity to the freshness checker. Non-blocking;
// bursts coalesce.
func (c *Client) NoteActivity() {
	if c == nil {
		return
	}
	select {
	case c.freshActivity <- struct{}{}:
	default:
	}
}

// recordRailVersions takes a rail version map seen on a push acknowledgment:
// it becomes the checker's baseline, and every rail that moved but that the
// current push cycle does not refresh itself (cycleRails reports whether this
// cycle refreshes the pushCycleRails at all) is queued for
// PolicyFreshnessLoop to fetch. Without the queue an ack would advance the
// baseline past a bundle the node never fetched, and the probe would then
// read "unchanged" for it.
func (c *Client) recordRailVersions(rails map[string]int64) {
	if len(rails) == 0 {
		return
	}
	covered := c.cycleRails.Load()
	c.fresh.mu.Lock()
	changed := policyfresh.Changed(c.fresh.lastRail, rails)
	c.fresh.lastRail = copyVersions(rails)
	queued := false
	for _, k := range changed {
		if covered && pushCycleRails[k] {
			continue
		}
		if c.fresh.pending == nil {
			c.fresh.pending = map[string]bool{}
		}
		c.fresh.pending[k] = true
		queued = true
	}
	c.fresh.mu.Unlock()
	if queued {
		select {
		case c.freshDispatch <- struct{}{}:
		default:
		}
	}
}

// takePendingRails drains the ack-queued rail set.
func (c *Client) takePendingRails() []string {
	c.fresh.mu.Lock()
	defer c.fresh.mu.Unlock()
	out := make([]string, 0, len(c.fresh.pending))
	for k := range c.fresh.pending {
		out = append(out, k)
	}
	c.fresh.pending = nil
	return out
}

// PolicyFreshnessLoop runs the checker until ctx is cancelled.
func (c *Client) PolicyFreshnessLoop(ctx context.Context) error {
	cfg := policyfresh.Config{}
	backstop := time.NewTimer(policyfresh.BackstopDelay(policyfresh.DefaultBackstop, jitterFrac()))
	defer backstop.Stop()
	// probeDone carries the one in-flight probe's answer back to this loop
	// (buffered, so a probe finishing after cancellation never blocks).
	probeDone := make(chan probeAnswer, 1)
	startProbe := func(hold bool) {
		var wait time.Duration
		if hold {
			wait = policyfresh.DefaultHold
		}
		etag := c.beginProbe(time.Now())
		go func() { probeDone <- c.fetchProbe(ctx, etag, wait) }()
	}
	var scheduled *time.Timer
	var scheduledC <-chan time.Time
	stopScheduled := func() {
		if scheduled != nil {
			scheduled.Stop()
		}
		scheduled, scheduledC = nil, nil
		c.fresh.mu.Lock()
		c.fresh.st.Scheduled = time.Time{}
		c.fresh.mu.Unlock()
	}
	for {
		var trig policyfresh.Trigger
		select {
		case <-ctx.Done():
			stopScheduled()
			return ctx.Err()
		case <-c.freshDispatch:
			// An ack already told us what moved: fetch it, no probe needed.
			c.dispatchRailChanges(ctx, c.takePendingRails())
			continue
		case <-c.freshActivity:
			trig = policyfresh.TriggerActivity
		case ans := <-probeDone:
			c.finishProbe(ctx, ans)
			trig = policyfresh.TriggerProbeDone
		case <-scheduledC:
			// The timer is spent: clear it first, so a scheduled wake that
			// lands while a probe is in flight cannot leave a stale
			// "already scheduled" mark that would swallow later activity.
			stopScheduled()
			trig = policyfresh.TriggerScheduled
		case <-backstop.C:
			trig = policyfresh.TriggerBackstop
			backstop.Reset(policyfresh.BackstopDelay(policyfresh.DefaultBackstop, jitterFrac()))
		}
		now := time.Now()
		c.fresh.mu.Lock()
		st := c.fresh.st
		c.fresh.mu.Unlock()
		d := policyfresh.Decide(cfg, st, trig, now, jitterFrac())
		if trig == policyfresh.TriggerActivity {
			c.fresh.mu.Lock()
			c.fresh.st.LastActivity = now
			c.fresh.mu.Unlock()
		}
		switch d.Action {
		case policyfresh.ActionCheckNow:
			stopScheduled()
			startProbe(d.Hold)
		case policyfresh.ActionSchedule:
			stopScheduled()
			scheduled = time.NewTimer(time.Until(d.At))
			scheduledC = scheduled.C
			c.fresh.mu.Lock()
			c.fresh.st.Scheduled = d.At
			c.fresh.mu.Unlock()
		case policyfresh.ActionNone:
		}
	}
}

// probeAnswer is one probe's outcome, carried from its goroutine back to
// the loop.
type probeAnswer struct {
	doc    orgcontract.PolicyVersionsDoc
	etag   string
	status int
	// held is true when the server granted the hold
	// (orgcontract.HeaderPolicyVersionsHold on the answer).
	held bool
	err  error
}

// probePolicyVersions performs ONE probe synchronously and dispatches what
// moved. hold > 0 asks the server to hold it (a held probe).
func (c *Client) probePolicyVersions(ctx context.Context, now time.Time, hold time.Duration) {
	etag := c.beginProbe(now)
	c.finishProbe(ctx, c.fetchProbe(ctx, etag, hold))
}

// beginProbe marks a probe in flight and returns the ETag it sends.
func (c *Client) beginProbe(now time.Time) string {
	c.fresh.mu.Lock()
	defer c.fresh.mu.Unlock()
	c.fresh.st.LastCheck, c.fresh.st.InFlight = now, true
	return c.fresh.etag
}

// fetchProbe performs the probe's HTTP exchange (no state change).
func (c *Client) fetchProbe(ctx context.Context, etag string, hold time.Duration) probeAnswer {
	doc, newETag, status, held, err := c.fetchPolicyVersions(ctx, etag, hold)
	return probeAnswer{doc: doc, etag: newETag, status: status, held: held, err: err}
}

// finishProbe applies a probe's answer: the in-flight flag, the outcome the
// re-arm rule reads (failed / held), the 404 silence, the new baseline, and
// the dispatch of every rail or family that moved.
func (c *Client) finishProbe(ctx context.Context, ans probeAnswer) {
	now := time.Now()
	c.fresh.mu.Lock()
	c.fresh.st.InFlight = false
	c.fresh.st.LastProbeFailed = ans.err != nil
	if ans.err == nil {
		c.fresh.st.HoldSupported = ans.held
	}
	c.fresh.mu.Unlock()

	// Any answer from the org (a version map, a 304, even a 404 from an
	// older server) proves it is reachable again, so a message rail the
	// outage stalled retries now rather than on the next push cycle.
	if ans.err == nil {
		c.retryStalledOrgMessages(ctx)
	}

	switch {
	case ans.err != nil:
		if !errors.Is(ans.err, ErrNotEnrolled) && !errors.Is(ans.err, context.Canceled) {
			c.logger.Debug("org policy-version probe failed", "err", ans.err)
		}
		return
	case ans.status == http.StatusNotFound:
		c.fresh.mu.Lock()
		c.fresh.st.UnsupportedUntil = now.Add(policyfresh.DefaultUnsupportedBackoff)
		c.fresh.st.HoldSupported = false
		first := !c.fresh.loggedUnsupported
		c.fresh.loggedUnsupported = true
		c.fresh.mu.Unlock()
		if first {
			c.logger.Info("org server has no policy-version probe (404); policy changes arrive on the push and poll cycles as before")
		}
		return
	case ans.status == http.StatusNotModified:
		return
	}
	doc, newETag := ans.doc, ans.etag
	c.fresh.mu.Lock()
	c.fresh.etag = newETag
	prevRail := c.fresh.lastRail
	c.fresh.lastRail = copyVersions(doc.RailVersions)
	c.fresh.mu.Unlock()

	if c.notePolicyVersions(doc.PolicyVersions) {
		select {
		case c.policyResourceKick <- struct{}{}:
			c.logger.Info("org policy resource: newer version published - fetching now (policy-version probe)")
		default:
		}
	}
	c.dispatchRailChanges(ctx, policyfresh.Changed(prevRail, doc.RailVersions))
}

// dispatchRailChanges fetches every rail whose version moved, through that
// rail's own signed path, walking railFetchers (the ONE place a rail key maps
// onto a fetch). An unknown key (a newer server's rail) fetches nothing.
func (c *Client) dispatchRailChanges(ctx context.Context, changed []string) {
	if len(changed) == 0 {
		return
	}
	set := map[string]bool{}
	for _, k := range changed {
		set[k] = true
	}
	for _, row := range railFetchers {
		for _, k := range row.keys {
			if set[k] {
				row.fetch(c, ctx)
				break
			}
		}
	}
}

// refreshDisplayPolicy fetches the developer cost-display rail under railsMu
// and, when a NEW verified version was cached, runs the display sink (the
// daemon re-renders its developer surfaces at once). The push cycle and the
// freshness dispatch both call it, so the two paths cannot diverge. Every
// state rule (signature required, org + key pin, monotonic version, 404 and
// any refusal keep the last verified value) is FetchOrgDisplayPolicy's.
func (c *Client) refreshDisplayPolicy(ctx context.Context) (bool, error) {
	c.railsMu.Lock()
	changed, err := c.FetchOrgDisplayPolicy(ctx)
	c.railsMu.Unlock()
	if changed && err == nil && c.displayPolicySink != nil {
		c.displayPolicySink()
	}
	return changed, err
}

// fetchPolicyVersions performs the conditional GET. It returns the decoded
// doc and new ETag on 200; status alone on 304/404. hold > 0 asks the server
// to hold the request (orgcontract.PolicyVersionsHoldParam); held reports
// whether the server granted it (an older server never does).
func (c *Client) fetchPolicyVersions(ctx context.Context, etag string, hold time.Duration) (orgcontract.PolicyVersionsDoc, string, int, bool, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return orgcontract.PolicyVersionsDoc{}, "", 0, false, fmt.Errorf("orgclient.fetchPolicyVersions: enrolment: %w", err)
	}
	if enr == nil {
		return orgcontract.PolicyVersionsDoc{}, "", 0, false, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return orgcontract.PolicyVersionsDoc{}, "", 0, false, fmt.Errorf("orgclient.fetchPolicyVersions: bearer: %w", err)
	}
	target := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.PolicyVersionsPath
	if secs := int(hold / time.Second); secs > 0 {
		target += "?" + url.Values{orgcontract.PolicyVersionsHoldParam: {strconv.Itoa(secs)}}.Encode()
	}
	// The request deadline covers the hold plus the plain probe budget.
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second+hold)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target, nil)
	if err != nil {
		return orgcontract.PolicyVersionsDoc{}, "", 0, false, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.httpClient.Do(req)
	c.noteRenewalFromResponse(RenewalPathOther, resp, err)
	if err != nil {
		return orgcontract.PolicyVersionsDoc{}, "", 0, false, fmt.Errorf("orgclient.fetchPolicyVersions: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	held := false
	if v, perr := strconv.Atoi(strings.TrimSpace(resp.Header.Get(orgcontract.HeaderPolicyVersionsHold))); perr == nil && v > 0 {
		held = true
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return orgcontract.PolicyVersionsDoc{}, "", resp.StatusCode, held, nil
	case http.StatusNotFound:
		return orgcontract.PolicyVersionsDoc{}, "", resp.StatusCode, false, nil
	default:
		return orgcontract.PolicyVersionsDoc{}, "", resp.StatusCode, false,
			fmt.Errorf("orgclient.fetchPolicyVersions: server returned %d", resp.StatusCode)
	}
	var doc orgcontract.PolicyVersionsDoc
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc); err != nil {
		return orgcontract.PolicyVersionsDoc{}, "", resp.StatusCode, false, fmt.Errorf("orgclient.fetchPolicyVersions: decode: %w", err)
	}
	return doc, resp.Header.Get("ETag"), http.StatusOK, held, nil
}

// notePolicyVersions records a policy-resource version map (from a push ack or
// a probe) and reports whether any family advanced past the previous one. The
// first observation never reports an advance (the poll loop's own immediate
// first fetch covered it).
//
// An EMPTY (or absent) map is an observation too: it is what an org that has
// published no policy resource yet reports. It used to be ignored without
// recording a baseline, so the org's FIRST publish of any family arrived as
// the node's "first observation" and never kicked a fetch; the node then
// waited for the hourly poll (DefaultPolicyPollIntervalSeconds), which is how
// an admin exposing a page on a fresh org saw nothing change for up to an
// hour (found live, managed-node visibility arc). Recording the empty
// baseline makes that first publish an advance like any other.
func (c *Client) notePolicyVersions(vers map[string]int64) bool {
	if vers == nil {
		vers = map[string]int64{}
	}
	c.policyVersMu.Lock()
	prev := c.lastPolicyVersions
	c.lastPolicyVersions = copyVersions(vers)
	c.policyVersMu.Unlock()
	return len(policyfresh.Changed(prev, vers)) > 0
}

func copyVersions(in map[string]int64) map[string]int64 {
	if in == nil {
		return nil
	}
	out := make(map[string]int64, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// jitterFrac is the checker's jitter source: it spreads probe timing across a
// fleet and is not a security value.
func jitterFrac() float64 {
	return rand.Float64() //nolint:gosec // G404: scheduling jitter, not a secret
}
