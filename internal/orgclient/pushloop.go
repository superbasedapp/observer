package orgclient

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pushsched"
)

// The activity-driven push loop (2026-10-02 budget-latency arc, P3).
//
// A committed turn or captured row kicks the loop (NotePushActivity); the pure
// table in internal/pushsched decides when the next cycle runs and whether it
// is a RAIL cycle (the ceiling: budget/pricing before the push, routing/
// intelligence/announcement/integrity after it - exactly the pre-P3 cycle) or
// a LIGHT cycle (the push alone). Policy changes between rail cycles arrive
// through the policy-freshness checker (policyfreshness.go), so light pushes
// never fetch a rail. Failure handling is the shared loopRetry ladder, so a
// failing org server backs off exactly as before.

// NotePushActivity reports that new pushable data was committed on the node.
// Non-blocking; bursts coalesce in the one-slot channel and in the
// scheduler's coalesce window.
func (c *Client) NotePushActivity() {
	if c == nil {
		return
	}
	select {
	case c.pushActivity <- struct{}{}:
	default:
	}
}

// notePushMinInterval records the org's backpressure hint
// (orgcontract.HeaderPushMinInterval, whole seconds) from an accepted push.
// An absent or unparseable header clears it: the hint is per-response, so an
// org that stops sending it stops throttling.
func (c *Client) notePushMinInterval(resp *http.Response) {
	var d time.Duration
	if resp != nil {
		if v := strings.TrimSpace(resp.Header.Get(orgcontract.HeaderPushMinInterval)); v != "" {
			if secs, err := strconv.Atoi(v); err == nil {
				d = pushsched.ClampServerMin(time.Duration(secs) * time.Second)
			}
		}
	}
	c.serverPushMin.Store(int64(d))
}

// pushSchedConfig is the scheduler's input: the live ceiling (governance pin
// included) and the org's current hint; floor/coalesce take the defaults.
func (c *Client) pushSchedConfig() pushsched.Config {
	return pushsched.Config{
		Ceiling:   c.pushInterval(),
		ServerMin: time.Duration(c.serverPushMin.Load()),
	}
}

// loopRetry is the failure ladder every org loop shares (formerly inline in
// runLoopKickFn): exponential jittered backoff for retryable failures, a
// separate higher-capped track for a rejected credential, a fixed pause for
// an oversized batch, and WARN dedup per stream.
type loopRetry struct {
	backoff, authBackoff         time.Duration
	failDeduper, authFailDeduper failureDeduper
	// backingOff is true while the last cycle failed on the retryable ladder.
	// runLoopKickFn then holds kicks until the backoff elapses (D-704): a
	// kick must not defeat the backoff, or a waker that is itself fed by the
	// failing cycle (the policy-state reporter kicking the bundle poll on a
	// missing bundle, the poll's outcome poking the reporter) turns a
	// persistent local failure into a tight loop.
	backingOff bool
}

// retryFailureMessage is the WARN a retryable cycle failure logs, chosen
// from an ordered table (first match wins; the last row is the default). A
// failure the node caused locally must not send the operator after the org
// server or tell them to unenrol (D-704: a directory planted at the bundle
// path read "org push failed ... run `observer unenroll`").
type retryFailureMessage struct {
	match func(err error) bool
	msg   string
}

var retryFailureMessages = []retryFailureMessage{
	{
		func(err error) bool { return errors.Is(err, errPolicyLocalPreResponse) },
		"org policy fetch failed on this node, backing off - a local file or database error (see err), not an org server or enrolment problem; fix the local error and the next retry recovers",
	},
	{
		func(error) bool { return true },
		"org push failed, backing off - if the org server stays unreachable, fix it, run `observer unenroll`, or set [org_client].enabled = false to stop retrying",
	},
}

// retryFailureMessageFor returns the table's WARN for err.
func retryFailureMessageFor(err error) string {
	for _, row := range retryFailureMessages {
		if row.match(err) {
			return row.msg
		}
	}
	return retryFailureMessages[len(retryFailureMessages)-1].msg
}

func newLoopRetry() *loopRetry {
	return &loopRetry{backoff: initialBackoff, authBackoff: initialBackoff}
}

// after classifies a cycle's error. sleep is the wait the ladder imposes
// (interval for success / errIdle), stop reports a cancelled context, and ok
// reports a success.
func (r *loopRetry) after(c *Client, err error, interval time.Duration) (sleep time.Duration, stop, ok bool) {
	r.backingOff = false
	switch {
	case errors.Is(err, context.Canceled):
		return 0, true, false
	case errors.Is(err, errIdle):
		return interval, false, false
	case errors.Is(err, ErrAuthFailed):
		// A rejected credential is RETRYABLE, not terminal. Each cycle
		// re-reads the bearer + signing key from the store, so a re-enrol or
		// key rotation writes fresh credentials that the next cycle loads and
		// recovers from WITHOUT a process restart — the proxy/data plane is
		// never bounced. Back off on a dedicated, higher-capped track so a
		// genuinely-revoked node settles to a slow cadence instead of
		// spamming, while a prompt re-enrol still recovers within the first
		// (fast) retries.
		warnOnce(c.logger, &r.authFailDeduper, err,
			"org push: authentication failed, retrying (re-enrol or rotate to recover)",
			"backoff", r.authBackoff.String())
		sleep = jitter(r.authBackoff)
		r.authBackoff = nextBackoffCapped(r.authBackoff, authFailMaxBackoff)
		return sleep, false, false
	case errors.Is(err, ErrBatchTooLarge):
		// Deliberately silent: PushLoop's own handler (noteOversizedBatch)
		// already logged the operator-facing explanation on this same cycle
		// AND persisted the pause for the dashboard / CLI. Logging again
		// here would double-report it with strictly less detail.
		return oversizedBatchBackoff, false, false
	case err != nil:
		warnOnce(c.logger, &r.failDeduper, err, retryFailureMessageFor(err),
			"backoff", r.backoff.String())
		r.backingOff = true
		// The server's Retry-After (503 log_full / unavailable, 429) is a
		// floor under the jittered ladder, never a ceiling: the unpushed rows
		// stay in the store and the loop retries without end (T-823).
		sleep = max(jitter(r.backoff), retryAfterOf(err))
		r.backoff = nextBackoff(r.backoff)
		return sleep, false, false
	default:
		r.backoff = initialBackoff
		r.authBackoff = initialBackoff
		// A successful cycle is a recovery: re-arm both trackers so a
		// LATER failure — even one identical to whatever failed before
		// — gets a fresh WARN instead of being mistaken for the same
		// ongoing outage.
		r.failDeduper.observe("")
		r.authFailDeduper.observe("")
		return interval, false, true
	}
}

// PushLoop runs PushOnce on the activity-driven schedule until ctx is
// cancelled. Retryable failures shorten the next wait to the current backoff
// (exponential, jittered); a success resets the backoff. The first cycle runs
// immediately and refreshes every rail (org-observer fundamentals finding
// H3b: a restarted daemon must not spend an interval without governance).
//
// Every enrolment / credential / config change written by another process is
// picked up on the next cycle without a restart, including recovery from a
// rejected credential (ErrAuthFailed is retryable, not terminal).
func (c *Client) PushLoop(ctx context.Context) error {
	// One failureDeduper PER independent failure stream, scoped to this
	// single PushLoop call — the enrolment-read, routing-policy, and
	// announcement fetches ride the cycle but are logged directly by
	// pushCycle, so the retry ladder's dedupers can't cover them.
	state := &pushCycleState{}
	return c.runPushLoop(ctx, func(ctx context.Context, kind cycleKind) (PushResult, error) {
		return c.pushCycle(ctx, state, kind)
	})
}

// runPushLoop is PushLoop's scheduler with the cycle injected, so a test can
// drive the timing with a fake cycle.
func (c *Client) runPushLoop(ctx context.Context, cycle func(ctx context.Context, kind cycleKind) (PushResult, error)) error {
	retry := newLoopRetry()
	var st pushsched.State
	var notBefore time.Time
	for {
		dec := pushsched.Next(c.pushSchedConfig(), st)
		at := dec.At
		if at.Before(notBefore) {
			at = notBefore
		}
		timer := time.NewTimer(time.Until(at))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-c.pushActivity:
			timer.Stop()
			now := time.Now()
			if st.FirstPending.IsZero() {
				st.FirstPending = now
			}
			st.LastPending = now
			continue
		case <-timer.C:
		}

		start := time.Now()
		res, err := cycle(ctx, cycleKind{rails: dec.Rails, railsOnly: dec.RailsOnly})
		if !dec.RailsOnly {
			// A rail-only cycle uploaded nothing, so it neither starts a new
			// backpressure window nor ships the pending activity.
			st.LastPush = start
		}
		sleep, stop, ok := retry.after(c, err, c.pushInterval())
		if stop {
			return ctx.Err()
		}
		if ok {
			// Only a SUCCESSFUL rail cycle restarts the ceiling: a failed
			// one (org down at daemon start) is retried as a rail cycle on
			// the backoff, as before P3, so governance is never an interval
			// late after a restart.
			if dec.Rails {
				st.LastRails = start
			}
			if dec.RailsOnly {
				notBefore = time.Time{}
				continue
			}
			// Everything committed before this cycle started is shipped (or
			// held by the settle rule, which a later cycle releases).
			if !st.FirstPending.After(start) {
				st.FirstPending, st.LastPending = time.Time{}, time.Time{}
			}
			st.Backlog = res.More
			notBefore = time.Time{}
			continue
		}
		if !dec.RailsOnly {
			st.Backlog = false
		}
		notBefore = time.Now().Add(sleep)
	}
}
