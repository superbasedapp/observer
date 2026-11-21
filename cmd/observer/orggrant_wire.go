package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// orggrant_wire.go - the ONE adapter from the guard's org-grant question
// (guard.OrgGrantClaim) to the node's verified grant cache
// (orgclient.ClaimAccessGrant / PeekAccessGrant). The hook process and the
// daemon both compose it, so both read the same re-verified cache and count
// uses through the same conditional UPDATE (request-grants G3).

// orgGrantStoreOpener yields a store for one grant question and a release
// func. The daemon hands its long-lived handle (release is a no-op); a hook
// process opens the database lazily, only on the rare blocking path, the
// SetApprovalLookup precedent.
type orgGrantStoreOpener func(ctx context.Context) (*store.Store, func(), error)

// orgGrantBudget is how long the next grant question may take, asked when
// the question is asked: a hook process sizes it from what is left on its own
// watchdog (hookOrgGrantBudget), the daemon from a constant.
type orgGrantBudget func() time.Duration

// constOrgGrantBudget is a fixed per-question budget.
func constOrgGrantBudget(d time.Duration) orgGrantBudget {
	return func() time.Duration { return d }
}

// newOrgGrantSession builds the guard's org-grant conversation over open
// (guard.OrgGrantSession): the questions one verdict asks (the peek, then the
// claim) share ONE store from ONE open, released by done, so a hook process
// does not open the database a second time right after the peek. Each
// question runs under its own budget, read when it is asked. Any failure (a
// database that cannot be opened or read in time) answers "no grant", so
// enforcement stands, and says why in Failed, which the guard writes on the
// verdict: "no grant covers this" and "the grants could not be read" are
// different facts, and only the first should send a developer to request.
func newOrgGrantSession(open orgGrantStoreOpener, budget orgGrantBudget) guard.OrgGrantSession {
	return func() (guard.OrgGrantClaim, func()) {
		var (
			st      *store.Store
			release func()
			openErr error
			opened  bool
		)
		claim := func(q guard.OrgGrantQuery) guard.OrgGrantResult {
			ctx, cancel := context.WithTimeout(context.Background(), budget())
			defer cancel()
			if !opened || (openErr != nil && retryableOrgGrantOpen(openErr)) {
				// A failed open is tried again by the next question only when
				// it ran out of time or waited on a lock; any other answer
				// stands for the whole conversation.
				st, release, openErr = openOrgGrantStore(ctx, open)
				opened = true
			}
			if errors.Is(openErr, fs.ErrNotExist) {
				// No database yet: a node with no grant cache holds no grants,
				// which is an answer, not a failure.
				return guard.OrgGrantResult{}
			}
			if openErr != nil {
				return guard.OrgGrantResult{Failed: "open: " + openErr.Error()}
			}
			if st == nil {
				return guard.OrgGrantResult{}
			}
			aq := accessgrant.Query{
				RuleID: q.RuleID, Lane: q.Lane, CommandClass: q.CommandClass, OperandHash: q.OperandHash,
				ProjectRootHash: q.ProjectRootHash, Decision: q.Decision, RuleLocked: q.RuleLocked,
			}
			var c orgclient.GrantClaim
			if q.Consume {
				c = orgclient.ClaimAccessGrant(ctx, st, aq, time.Now())
			} else {
				c = orgclient.PeekAccessGrant(ctx, st, aq, time.Now())
			}
			out := guard.OrgGrantResult{
				OK: c.OK, GrantID: c.Hit.GrantID, Effect: c.Hit.Effect, ExpiresAtNs: c.Hit.ExpiresAtNs,
				UsesLeft: c.Hit.UsesLeft, LockRefused: c.LockRefused, Unverified: c.Unverified,
				ScopeMissID: c.ScopeMissID,
			}
			if c.Err != nil {
				out.Failed = c.Err.Error()
			}
			return out
		}
		done := func() {
			if release != nil {
				release()
			}
		}
		return claim, done
	}
}

// newOrgGrantClaim is newOrgGrantSession for a caller that asks one question
// at a time (the daemon, whose opener hands out its long-lived handle): every
// question is a conversation of its own.
func newOrgGrantClaim(open orgGrantStoreOpener, timeout time.Duration) guard.OrgGrantClaim {
	session := newOrgGrantSession(open, constOrgGrantBudget(timeout))
	return func(q guard.OrgGrantQuery) guard.OrgGrantResult {
		claim, done := session()
		defer done()
		return claim(q)
	}
}

// orgGrantOpenRetryMin is the least time a retried open must have left; a
// retry with less would fail the same way and only delay the reply.
const orgGrantOpenRetryMin = 100 * time.Millisecond

// openOrgGrantStore opens the grant store inside ctx with ONE bounded retry:
// the first attempt gets two thirds of what is left, so an attempt that
// stalls (a cold open on a loaded machine, a lock wait) leaves time for a
// second one; the retry runs only for a timeout or a lock wait and only with
// orgGrantOpenRetryMin or more left. Every other answer (no database, an
// unreadable file) is final at once.
func openOrgGrantStore(ctx context.Context, open orgGrantStoreOpener) (*store.Store, func(), error) {
	first := ctx
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		first, cancel = context.WithTimeout(ctx, time.Until(dl)*2/3)
		defer cancel()
	}
	st, release, err := open(first)
	if err == nil || !retryableOrgGrantOpen(err) || ctx.Err() != nil {
		return st, release, err
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < orgGrantOpenRetryMin {
		return st, release, err
	}
	return open(ctx)
}

// retryableOrgGrantOpen reports an open failure worth one more attempt: it
// ran out of time, or SQLite was busy or locked. Anything else would fail the
// same way again.
func retryableOrgGrantOpen(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, s := range []string{"database is locked", "database table is locked", "sqlite_busy", "sqlite_locked"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// hookOrgGrantOpener opens the daemon's database for one grant conversation
// (a hook process is short-lived and holds no handle).
//
// It used to be a full db.Open per question: a ping, the pragmas and the
// migration plan against the node's whole database, twice per blocking
// verdict (the peek, then the claim), each under the hook timeout, with any
// overrun read as "no grant" and nothing recorded. That is the defect P-232
// fixed for the local approval lookup (hook_approvals.go) and left here: on
// a large busy node an in-force org grant was skipped now and then, and the
// developer asked for the same grant again (operator report 2026-11-13:
// S-793 asked 6 times in 152 calls under a perpetual grant). Now the open is
// the same migration-free one, writable only because a use-limited grant
// counts its use: a hook is never the process that migrates the node. The
// busy wait is half of what is left on ctx (never below 20 ms), so a write
// that cannot get the lock returns in time for the reply; the decision
// itself needs no write (orgclient.ClaimAccessGrant).
//
// A database file that does not exist yet, or one the daemon has not
// migrated yet (no grant cache table), is fs.ErrNotExist: a node with no
// grant cache holds no grants, which is an answer and not a failure.
func hookOrgGrantOpener(dbPath string) orgGrantStoreOpener {
	return func(ctx context.Context) (*store.Store, func(), error) {
		if dbPath == "" {
			return nil, nil, errors.New("no database path configured")
		}
		if _, err := os.Stat(dbPath); err != nil {
			return nil, nil, err
		}
		database, err := sql.Open("sqlite", hookOrgGrantDSN(dbPath, hookApprovalBusy(ctxRemaining(ctx))))
		if err != nil {
			return nil, nil, err
		}
		database.SetMaxOpenConns(1)
		var one int
		err = database.QueryRowContext(ctx,
			`SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'org_access_grant_state'`).Scan(&one)
		if err != nil {
			_ = database.Close()
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil, fs.ErrNotExist
			}
			return nil, nil, err
		}
		return store.New(database), func() { _ = database.Close() }, nil
	}
}

// ctxRemaining is the time left on ctx's deadline (0 = no deadline, which
// hookApprovalBusy reads as its default budget).
func ctxRemaining(ctx context.Context) time.Duration {
	dl, ok := ctx.Deadline()
	if !ok {
		return 0
	}
	if r := time.Until(dl); r > 0 {
		return r
	}
	return time.Nanosecond
}

// The org grant question's budget in a hook process (operator report
// 2026-11-13, 14:19 UTC: S-793 enforced as an ask with "could not be
// consulted (open: context deadline exceeded)" while a perpetual exempt
// grant was in force, load average about 17). The question used to run under
// the 500 ms [observer.hooks] timeout_ms, the local approval read's budget,
// and it only runs on a call that would block or ask, after the quick scan,
// so a cold open on a loaded machine overran it. It has its own budget now.
const (
	// defaultHookOrgGrantBudget is the most one grant question may take.
	defaultHookOrgGrantBudget = 4 * time.Second
	// hookOrgGrantReplyMargin is what a question leaves on the hook's
	// watchdog for the rest of the evaluation and the reply.
	hookOrgGrantReplyMargin = time.Second
	// hookOrgGrantHostMargin is what a question leaves below the host's own
	// hook timeout when no watchdog is armed.
	hookOrgGrantHostMargin = 3 * time.Second
	// hookOrgGrantMinBudget is the floor of an exhausted budget: the
	// question fails at once and the verdict says so.
	hookOrgGrantMinBudget = time.Millisecond
)

// hookOrgGrantBudgetRules sizes the grant question's budget, an ordered
// table walked top down: the first row whose condition holds sizes it, and
// the result is never more than defaultHookOrgGrantBudget.
//
//	| # | the invocation has                  | budget                               |
//	|---|-------------------------------------|--------------------------------------|
//	| 1 | a watchdog deadline (plan.Deadline) | left - 1 s; left/2 when that is <= 0 |
//	| 2 | no watchdog, a known host timeout   | host - 3 s; host/3 when that is <= 0 |
//	| 3 | neither                             | the default                          |
//
// Row 1 is every production invocation: the watchdog's deadline is fixed at
// the start (30 s by default, at most the host's hook timeout minus 2 s for
// a gate event, hookGateBudget) and already counts the time the payload
// read and the quick scan spent, so the question always ends before the
// watchdog writes its fail-closed block.
var hookOrgGrantBudgetRules = []struct {
	name  string
	holds func(plan hookFailurePlan) bool
	size  func(plan hookFailurePlan, now time.Time) time.Duration
}{
	{
		"watchdog deadline",
		func(p hookFailurePlan) bool { return !p.Deadline.IsZero() },
		func(p hookFailurePlan, now time.Time) time.Duration {
			left := p.Deadline.Sub(now)
			if c := left - hookOrgGrantReplyMargin; c > 0 {
				return c
			}
			return left / 2
		},
	},
	{
		"host timeout",
		func(p hookFailurePlan) bool { return p.HostTimeout > 0 },
		func(p hookFailurePlan, _ time.Time) time.Duration {
			if c := p.HostTimeout - hookOrgGrantHostMargin; c > 0 {
				return c
			}
			return p.HostTimeout / 3
		},
	},
	{
		"default",
		func(hookFailurePlan) bool { return true },
		func(hookFailurePlan, time.Time) time.Duration { return defaultHookOrgGrantBudget },
	},
}

// hookOrgGrantBudget walks hookOrgGrantBudgetRules for plan at now.
func hookOrgGrantBudget(plan hookFailurePlan, now time.Time) time.Duration {
	b := defaultHookOrgGrantBudget
	for _, r := range hookOrgGrantBudgetRules {
		if r.holds(plan) {
			if c := r.size(plan, now); c < b {
				b = c
			}
			break
		}
	}
	if b < hookOrgGrantMinBudget {
		b = hookOrgGrantMinBudget
	}
	return b
}

// hookOrgGrantQuestionBudget is the hook process's orgGrantBudget: the
// current invocation's plan, read when the question is asked.
func hookOrgGrantQuestionBudget() time.Duration {
	return hookOrgGrantBudget(currentHookPlan(), time.Now())
}

// hookOrgGrantDSN is the migration-free DSN of the hook's grant question:
// mode=rw never creates a database file, the busy wait is the hook's, and
// synchronous is the node's own setting (db.Open: NORMAL) for the one
// counter write a use-limited grant makes.
func hookOrgGrantDSN(dbPath string, busy time.Duration) string {
	return fmt.Sprintf("file:%s?mode=rw&_pragma=busy_timeout(%d)&_pragma=synchronous(1)", sqlitedsn.Escape(dbPath), busy.Milliseconds())
}

// daemonOrgGrantOpener hands out the daemon's own store handle.
func daemonOrgGrantOpener(st *store.Store) orgGrantStoreOpener {
	return func(context.Context) (*store.Store, func(), error) { return st, func() {}, nil }
}

// requestAccessBase is the node dashboard origin the guard's org-locked deny
// line links its request form under (request-grants G4): the configured
// dashboard address, a wildcard bind ("", 0.0.0.0, ::) mapped to loopback
// because the link is opened by a browser on THIS machine. "" when the
// address cannot be parsed: the line then offers the CLI command only.
// Never a network call; the hook process composes it from config alone.
func requestAccessBase(cfg config.Config) string {
	if !dashboardInBuild {
		// No request form to link to in a build without the dashboard
		// (ui.dashboard, MP-L1M): the line offers the CLI command only.
		return ""
	}
	addr := resolveDashboardAddr("", cfg.Dashboard.Addr, "127.0.0.1:8081")
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return ""
	}
	if ip := net.ParseIP(host); host == "" || (ip != nil && ip.IsUnspecified()) {
		host = "127.0.0.1"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// claimToolGrant answers a launch gate's tool access question (request-grants
// G8) over open and counts one use: a verified grant for exactly this tool.
// Any failure is "no grant", so the org's disallow stands.
func claimToolGrant(open orgGrantStoreOpener, timeout time.Duration, tool string) orgclient.TargetClaim {
	if tool == "" {
		return orgclient.TargetClaim{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, release, err := open(ctx)
	if err != nil || st == nil {
		return orgclient.TargetClaim{}
	}
	defer release()
	return orgclient.ClaimTargetGrant(ctx, st, accessgrant.TargetQuery{Type: accessgrant.TypeToolAllow, Target: tool}, time.Now())
}

// peekToolGrant is claimToolGrant without counting a use: the same verified
// read and the same match, for a gate that decides but does not start the
// tool itself.
func peekToolGrant(open orgGrantStoreOpener, timeout time.Duration, tool string) orgclient.TargetClaim {
	if tool == "" {
		return orgclient.TargetClaim{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, release, err := open(ctx)
	if err != nil || st == nil {
		return orgclient.TargetClaim{}
	}
	defer release()
	return orgclient.PeekTargetGrant(ctx, st, accessgrant.TargetQuery{Type: accessgrant.TypeToolAllow, Target: tool}, time.Now())
}

// daemonToolGrant is the dashboard launch gate's grant reader over the
// daemon's own store (nodeFeaturesHandle.SetToolGrant). It PEEKS (review
// M3-10): a dashboard launch runs the inner `observer <tool>` launcher, and
// that launcher is the one place a launch's use is counted
// (refuseIfToolDisallowed), so a one-use grant is spent once per launch,
// and never by a launch the dashboard then refuses for another reason.
func daemonToolGrant(st *store.Store) func(tool string) (int64, bool) {
	return func(tool string) (int64, bool) {
		c := peekToolGrant(daemonOrgGrantOpener(st), 2*time.Second, tool)
		return c.Hit.GrantID, c.OK
	}
}

// grantWindowWords renders a grant's remaining window for a launch note:
// "until 2026-10-04 18:00 UTC, 2 uses left" (either part may be absent).
func grantWindowWords(expiresAtNs, usesLeft int64) string {
	var parts []string
	if expiresAtNs > 0 {
		parts = append(parts, "until "+time.Unix(0, expiresAtNs).UTC().Format("2006-01-02 15:04 UTC"))
	}
	if usesLeft >= 0 {
		parts = append(parts, fmt.Sprintf("%d uses left", usesLeft))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// daemonFeatureGrant is the node.features gate's feature access reader over
// the daemon's own store (nodeFeaturesHandle.SetFeatureGrant). A feature
// grant is time-bound only, so this peeks and counts nothing.
func daemonFeatureGrant(st *store.Store) func(feature string) (int64, bool) {
	return func(feature string) (int64, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		c := orgclient.PeekTargetGrant(ctx, st, accessgrant.TargetQuery{Type: accessgrant.TypeFeatureEnable, Target: feature}, time.Now())
		return c.Hit.GrantID, c.OK
	}
}
