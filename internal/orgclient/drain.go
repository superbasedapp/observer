package orgclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// Drain before a switch (R3-78, operator ruling D-22, 2026-11-11).
//
// The push cursor is per node, not per organization: enrolment reseeds it at
// the current high-water ids so only post-enrolment activity is ever shared,
// and leaving removes the credentials that could ship anything. Either one,
// done while rows captured for the CURRENT organization still sit above the
// cursor, used to drop that tail silently: those rows never reached the
// organization they were captured for.
//
// DrainPending closes that gap with the push path the loop already uses: it
// runs PushOnce (the one envelope builder, cursor CAS and acknowledgement)
// against the current enrolment until a cycle finds nothing to send, bounded
// by a time budget and a cycle cap. The caller (Enroll for a different
// organization, the leave in cmd/observer) refuses to proceed when the drain
// did not finish, unless the person chose to drop the rows explicitly
// (DrainOptions.DropUnsent, `--drop-unsent`, the dashboard's "Switch anyway").
//
// Dropped rows stay in the local database. They are never sent to the next
// organization automatically: its enrolment reseeds the cursor above them. The
// only way they ever leave the machine afterwards is `observer org backfill
// --all --confirm`, which rewinds the cursor and sends the machine's whole
// history to the organization it is enrolled in THEN, under the D-273
// cross-enrolment warning.

// Drain defaults: a whole drain never takes longer than DefaultDrainBudget
// and never runs more than DefaultDrainMaxCycles push cycles. A batch is up to
// [org_client].max_push_bytes, so the cap covers a very large tail; a tail
// bigger than that reports what is left instead of running on.
const (
	DefaultDrainBudget    = 60 * time.Second
	DefaultDrainMaxCycles = 200
	// drainMaxRetries is how many times one failing cycle is retried when the
	// failure is transient (network, 5xx, 429), within the budget.
	drainMaxRetries = 2
	// defaultDrainRetryDelay is the pause before such a retry.
	defaultDrainRetryDelay = time.Second
)

// ErrUnsentRows is returned (wrapped in *UnsentRowsError) when an enrolment
// switch or a leave was refused because rows captured for the current
// organization could not be sent to it first.
var ErrUnsentRows = errors.New("orgclient: rows for the current organization are still unsent")

// DrainOptions bounds and steers one drain.
type DrainOptions struct {
	// DropUnsent lets the caller proceed when the drain did not finish. The
	// rows stay unsent (see the package note above).
	DropUnsent bool
	// Budget bounds the whole drain (zero = DefaultDrainBudget).
	Budget time.Duration
	// MaxCycles bounds the number of push cycles (zero = DefaultDrainMaxCycles).
	MaxCycles int
	// PushOffReason, when set, says why org push is switched off on this node
	// ([org_client] enabled = false). The drain then sends nothing, because the
	// person turned sharing off, and reports this as the reason.
	PushOffReason string
}

// DrainReport is what one drain did, for the CLI and the dashboard.
type DrainReport struct {
	// Attempted is false when there was no enrolment to drain.
	Attempted bool
	// OrgID / OrgName / OrgServerURL name the organization drained to.
	OrgID        string
	OrgName      string
	OrgServerURL string
	// Pending is how many captured rows sat above the push cursor before the
	// drain (sessions, actions, api_turns, token_usage, guard_events: the
	// same count `observer org push-status` shows).
	Pending int64
	// Sent is how many rows the accepted batches carried.
	Sent int
	// Cycles is how many push cycles ran.
	Cycles int
	// Complete is true when a cycle found nothing left to send, or when no
	// captured row is left above the cursor.
	Complete bool
	// Remaining is how many captured rows are still above the cursor
	// (0 when Complete).
	Remaining int64
	// Reason says why the drain stopped short (empty when Complete).
	Reason string
	// Dropped is true when the caller proceeded anyway (DropUnsent) with
	// Remaining rows unsent.
	Dropped bool
}

// UnsentRowsError is the refusal: the drain did not finish and the caller did
// not choose to drop the rows. errors.Is(err, ErrUnsentRows) holds.
type UnsentRowsError struct {
	Report DrainReport
}

func (e *UnsentRowsError) Error() string {
	return fmt.Sprintf("%v: %d rows captured for %s were not sent (%s)",
		ErrUnsentRows, e.Report.Remaining, drainOrgLabel(e.Report), e.Report.Reason)
}

// Unwrap makes errors.Is(err, ErrUnsentRows) hold.
func (e *UnsentRowsError) Unwrap() error { return ErrUnsentRows }

// drainOrgLabel names the drained organization for an error string.
func drainOrgLabel(r DrainReport) string {
	switch {
	case r.OrgName != "":
		return r.OrgName
	case r.OrgID != "":
		return r.OrgID
	case r.OrgServerURL != "":
		return r.OrgServerURL
	}
	return "the current organization"
}

// drainStopRule classifies a failed push cycle: whether the drain may retry it
// and the reason the report gives when it stops. Rows are walked top-down; the
// first whose match holds decides (CLAUDE.md #5).
type drainStopRule struct {
	name      string
	match     func(err error) bool
	retryable bool
	reason    func(err error) string
}

func isNetErr(err error) bool {
	var ne net.Error
	var ue *url.Error
	return errors.As(err, &ne) || errors.As(err, &ue)
}

var drainStopRules = []drainStopRule{
	{
		name:  "budget",
		match: func(err error) bool { return errors.Is(err, context.DeadlineExceeded) },
		reason: func(error) string {
			return "the time allowed for sending them ran out"
		},
	},
	{
		name:  "auth",
		match: func(err error) bool { return errors.Is(err, ErrAuthFailed) },
		reason: func(error) string {
			return "the organization refused this machine's credential (it may have been revoked)"
		},
	},
	{
		name:  "too-old",
		match: func(err error) bool { return errors.Is(err, ErrAgentTooOld) },
		reason: func(error) string {
			return "the organization refuses this Observer version; update it, then try again"
		},
	},
	{
		name:  "too-large",
		match: func(err error) bool { return errors.Is(err, ErrBatchTooLarge) },
		reason: func(error) string {
			return "the organization refused a batch as too large"
		},
	},
	{
		name:  "not-enrolled",
		match: func(err error) bool { return errors.Is(err, ErrNotEnrolled) },
		reason: func(error) string {
			return "this machine's organization credential is missing"
		},
	},
	{
		name:      "unreachable",
		match:     isNetErr,
		retryable: true,
		reason: func(err error) string {
			return "the organization server could not be reached (" + err.Error() + ")"
		},
	},
	{
		name:      "other",
		match:     func(error) bool { return true },
		retryable: true,
		reason: func(err error) string {
			return "the organization did not accept the push (" + err.Error() + ")"
		},
	},
}

func classifyDrainErr(err error) drainStopRule {
	for _, r := range drainStopRules {
		if r.match(err) {
			return r
		}
	}
	return drainStopRules[len(drainStopRules)-1]
}

// pendingRows is the captured-row count above the stored cursor.
func (c *Client) pendingRows(ctx context.Context) (int64, error) {
	cur, err := c.store.LoadPushCursor(ctx)
	if err != nil {
		return 0, err
	}
	n, err := c.store.PushEligibleCounts(ctx, cur)
	if err != nil {
		return 0, err
	}
	return pendingTotal(n), nil
}

// pendingTotal sums the per-table counts PushEligibleCounts returns.
func pendingTotal(n store.PushCursor) int64 {
	return n.Sessions + n.Actions + n.APITurns + n.TokenUsage + n.GuardEvents
}

// DrainPending sends the rows still waiting for the current organization,
// through PushOnce, until a cycle finds nothing left, the budget runs out or
// a cycle fails for good. It never returns an error for a drain that stopped
// short: the report says so (Complete false, Remaining, Reason). An error is
// returned only when the local database could not be read.
func (c *Client) DrainPending(ctx context.Context, opts DrainOptions) (DrainReport, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return DrainReport{}, fmt.Errorf("orgclient.DrainPending: %w", err)
	}
	if enr == nil {
		return DrainReport{Complete: true}, nil
	}
	rep := DrainReport{
		Attempted: true, OrgID: enr.OrgID, OrgName: enr.OrgName, OrgServerURL: enr.OrgServerURL,
	}
	if rep.Pending, err = c.pendingRows(ctx); err != nil {
		return rep, fmt.Errorf("orgclient.DrainPending: %w", err)
	}
	if opts.PushOffReason != "" {
		// Sharing is off by the person's own choice: send nothing.
		rep.Remaining = rep.Pending
		rep.Complete = rep.Remaining == 0
		if !rep.Complete {
			rep.Reason = opts.PushOffReason
		}
		return rep, nil
	}
	budget, maxCycles := opts.Budget, opts.MaxCycles
	if budget <= 0 {
		budget = DefaultDrainBudget
	}
	if maxCycles <= 0 {
		maxCycles = DefaultDrainMaxCycles
	}
	retryDelay := c.drainRetryDelay
	if retryDelay <= 0 {
		retryDelay = defaultDrainRetryDelay
	}
	dctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	retries := 0
	for rep.Cycles < maxCycles {
		rep.Cycles++
		res, perr := c.PushOnce(dctx)
		if perr == nil {
			retries = 0
			if res.Empty {
				rep.Complete = true
				break
			}
			rep.Sent += res.RowCount
			continue
		}
		if dctx.Err() != nil {
			perr = context.DeadlineExceeded
		}
		rule := classifyDrainErr(perr)
		if rule.retryable && retries < drainMaxRetries {
			retries++
			select {
			case <-time.After(retryDelay):
				continue
			case <-dctx.Done():
				perr = context.DeadlineExceeded
				rule = classifyDrainErr(perr)
			}
		}
		rep.Reason = rule.reason(perr)
		break
	}
	if !rep.Complete && rep.Reason == "" {
		rep.Reason = fmt.Sprintf("it needed more than %d push cycles", maxCycles)
	}
	if rep.Complete {
		return rep, nil
	}
	// Count what is left from the stored cursor (with the caller's context:
	// the drain's own may have expired).
	if rep.Remaining, err = c.pendingRows(ctx); err != nil {
		return rep, fmt.Errorf("orgclient.DrainPending: %w", err)
	}
	if rep.Remaining == 0 {
		// Every captured row reached the organization; what failed was a
		// later cycle carrying only recomputed summaries, which the next
		// organization's enrolment recomputes anyway.
		rep.Complete, rep.Reason = true, ""
	}
	return rep, nil
}

// drainOrRefuse runs DrainPending and applies the switch rule: a finished
// drain proceeds, an unfinished one proceeds only with opts.DropUnsent
// (marking the report Dropped) and otherwise returns *UnsentRowsError.
func (c *Client) drainOrRefuse(ctx context.Context, opts DrainOptions) (DrainReport, error) {
	rep, err := c.DrainPending(ctx, opts)
	if err != nil {
		return rep, err
	}
	if rep.Complete {
		return rep, nil
	}
	if opts.DropUnsent {
		rep.Dropped = true
		c.logger.Warn("org switch: proceeding with unsent rows (drop-unsent)",
			"org_id", rep.OrgID, "remaining", rep.Remaining, "reason", rep.Reason)
		return rep, nil
	}
	return rep, &UnsentRowsError{Report: rep}
}

// DrainBeforeSwitch is the pre-exchange half of the switch rule (Enroll runs
// it, and a sign-in enrolment runs it before the browser step so a refusal
// never costs the person a sign-in): when this machine is enrolled with a
// DIFFERENT server than orgURL, the rows still waiting for that organization
// are sent to it first, and *UnsentRowsError is returned when they could not
// be and opts.DropUnsent is not set. Not enrolled, or the same server: no-op
// (Attempted false), because a same-server re-enrolment is decided after the
// code is exchanged (EnrollWithOptions).
func (c *Client) DrainBeforeSwitch(ctx context.Context, orgURL string, opts DrainOptions) (DrainReport, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return DrainReport{}, fmt.Errorf("orgclient.DrainBeforeSwitch: %w", err)
	}
	if enr == nil || NormalizeOrgURL(enr.OrgServerURL) == NormalizeOrgURL(orgURL) {
		return DrainReport{Complete: true}, nil
	}
	return c.drainOrRefuse(ctx, opts)
}

// DrainBeforeLeave is the leave's drain (the same rule as a switch): it sends
// the rows still waiting for the current organization and returns
// *UnsentRowsError when it could not and opts.DropUnsent is not set.
func (c *Client) DrainBeforeLeave(ctx context.Context, opts DrainOptions) (DrainReport, error) {
	return c.drainOrRefuse(ctx, opts)
}
