package orgclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// The structured unenrol (T-718, operator ruling D-502).
//
// Leaving an organization retires EVERYTHING the enrolment conferred, in one
// place, in an order that never blocks an agent session at any point:
//
//  1. FENCE the enrolment epoch first (tombstone the generation), so no fetch
//     already in flight can re-install a document after the steps below
//     clear it. A tombstoned generation reads as "not enrolled" everywhere,
//     and with the B-625 fail-safe (internal/guard orgBudgetLiveness) "not
//     enrolled" never refuses a request.
//  2. RETIRE ENFORCEMENT: the org budget and its fail-closed requirement, the
//     identity-bound documents (policies, grants, prices, manifests), the
//     governance and node.features sidecars and the policy-resource state.
//  3. NOTIFY the organization (best effort, bounded, never blocking): one
//     audited POST so the org's audit log shows that this node left.
//  4. RETIRE IDENTITY: the enrolment grant (the authority tokens, in the
//     enforcement prefix above), the credentials, then the enrolment row
//     LAST, so any failure leaves a fenced row a retry can act on.
//
// unenrolSteps is that order as a table (CLAUDE.md #5). UnenrolPlan renders it
// for the preview (`observer unenroll --plan`, the dashboard's Leave dialog),
// and Unenroll walks it, so the preview and the apply cannot disagree. Every
// row has a test (TestUnenrolStepTable).
//
// What leaving does NOT touch is stated in the plan too: the node's own
// config.toml and every local session, action and cost row stay, so the node
// ends as a plain individual node with all of its data.

// UnenrolStep is one row of the conferred -> retired table as the preview
// shows it.
type UnenrolStep struct {
	// ID is stable and machine-readable (tests, the dashboard).
	ID string
	// Conferred is what the enrolment gave this node.
	Conferred string
	// Retired is what leaving does with it.
	Retired string
	// Phase is "fence", "enforcement", "notify" or "identity".
	Phase string
	// Required steps abort the leave when they fail (the enrolment then stays,
	// fenced, and a retry is safe); every other step is best effort.
	Required bool
}

// UnenrolStepResult is one row's outcome.
type UnenrolStepResult struct {
	ID string
	// Ran is false when there was nothing to act on (no enrolment row).
	Ran bool
	// Err is set when a best-effort step failed; the leave still completed.
	Err string
}

// UnenrolResult is what Unenroll did.
type UnenrolResult struct {
	WasEnrolled bool
	// OrgNotified is true when the organization recorded the leave.
	OrgNotified bool
	// OrgNotice explains why it did not (unreachable, an older server).
	OrgNotice string
	Steps     []UnenrolStepResult
}

// unenrolRun is the state one walk threads through its steps.
type unenrolRun struct {
	enr    *store.Enrolment
	orgKey string
	res    *UnenrolResult
	// managed is NodeManagedFor, resolved before any step fences the
	// enrolment generation (the leave notice names the machine of a
	// managed node, switched ones included).
	managed bool
}

type unenrolStep struct {
	UnenrolStep
	// needsEnrolment skips the row when no enrolment row exists.
	needsEnrolment bool
	run            func(ctx context.Context, c *Client, r *unenrolRun) error
}

// leaveNoticeTimeout bounds the one network call a leave makes.
const leaveNoticeTimeout = 3 * time.Second

var unenrolSteps = []unenrolStep{
	{
		UnenrolStep: UnenrolStep{
			ID: "generation_fence", Phase: "fence", Required: true,
			Conferred: "the enrolment epoch every organization document is bound to",
			Retired:   "tombstoned first, so nothing in flight can re-install a document; from here every reader sees no enrolment",
		},
		needsEnrolment: true,
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			_, err := c.store.BumpEnrolmentGeneration(ctx, r.orgKey, true)
			return err
		},
	},
	{
		// In the fail-closed prefix right after the fence (spec §5.1): the
		// grant is the only artifact that could govern this machine, so it goes
		// before anything else can fail.
		UnenrolStep: UnenrolStep{
			ID: "enrolment_grant", Phase: "enforcement", Required: true,
			Conferred: "the enrolment grant: enforce.* authority, extract.managed full-content capture, settings and capture pins",
			Retired:   "deleted, so no authority remains that could govern this machine",
		},
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			if r.enr != nil {
				if err := c.store.DeleteEnrolmentGrant(ctx, r.orgKey); err != nil {
					return err
				}
			}
			// An orphan grant is authority with no owner: clear unconditionally.
			return c.store.DeleteAllEnrolmentGrants(ctx)
		},
	},
	{
		UnenrolStep: UnenrolStep{
			ID: "org_budget", Phase: "enforcement",
			Conferred: "the organization's budget caps, hard enforcement and the managed budget requirement (rule B-625)",
			Retired:   "cached budget document dropped; the guard admits at once and recomposes onto your own [guard.budget] numbers",
		},
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			c.budget.clear()
			return c.store.ClearOrgBudget(ctx)
		},
	},
	{
		UnenrolStep: UnenrolStep{
			ID: "org_documents", Phase: "enforcement",
			Conferred: "signed organization documents: routing, display, AI tool and announcement policies, access grants and requests, Cloud Intelligence terms and results, org prices, the update manifest",
			Retired:   "every identity-bound document and its in-memory copy dropped; org prices fall back to the node's own price table",
		},
		needsEnrolment: true,
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			var errs []error
			for _, cache := range identityBoundCaches {
				if cache.name == "org budget" || cache.name == "governance sidecar" || cache.name == "node.features sidecar" {
					continue // own rows in this table
				}
				if err := cache.clear(ctx, c, r.enr); err != nil {
					errs = append(errs, fmt.Errorf("%s: %w", cache.name, err))
				}
			}
			return errors.Join(errs...)
		},
	},
	{
		UnenrolStep: UnenrolStep{
			ID: "governance", Phase: "enforcement", Required: true,
			Conferred: "node governance: pinned settings (guard.budget.from_org / hard / fail_closed, ...), hidden dashboard sections, managed policy families, tool disallow lists",
			Retired:   "governance and node.features sidecars removed and every policy-resource cache cleared; your own settings apply again: the budget fail_closed posture at once, other pinned settings (guard.mode, guard.budget.hard, ...) when the daemon next restarts",
		},
		needsEnrolment: true,
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			c.removeGovernanceSidecar()
			c.removeFeaturesSidecar()
			if err := c.store.ClearPolicyResourceState(ctx, r.orgKey); err != nil {
				return err
			}
			c.clearPolicyResourceCacheTree(r.orgKey)
			return nil
		},
	},
	{
		UnenrolStep: UnenrolStep{
			ID: "org_notice", Phase: "notify",
			Conferred: "membership of this node in the organization's fleet",
			Retired:   "the organization is told this node left (one audited request, 3 s at most); unreachable or older servers are skipped, never blocking",
		},
		needsEnrolment: true,
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			ok, why := c.notifyLeave(ctx, r.enr, r.managed)
			r.res.OrgNotified, r.res.OrgNotice = ok, why
			return nil
		},
	},
	{
		// BEFORE the enrolment row (REVIEW-4 P4-12): a credentials failure (a
		// locked keychain, no Secret Service) must leave the fenced row in
		// place, so a retried leave still sees an enrolment and reaches this
		// step again. With the row deleted first, a retry printed "Not
		// enrolled; nothing to do." and the org bearer and keys stayed.
		UnenrolStep: UnenrolStep{
			ID: "credentials", Phase: "identity", Required: true,
			Conferred: "the org bearer, the signing key, the agent-access key and break-glass leases",
			Retired:   "removed from the keychain and the credential files",
		},
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			if err := c.bearers.Clear(); err != nil {
				return err
			}
			if err := c.clearAgentAccessKeys(); err != nil {
				return err
			}
			c.clearBreakGlass()
			return nil
		},
	},
	{
		// LAST: the row is what makes a retry possible, so it goes only after
		// every Required step before it has succeeded.
		UnenrolStep: UnenrolStep{
			ID: "enrolment", Phase: "identity", Required: true,
			Conferred: "the enrolment itself: org push loop, policy-state reports, managed tenancy and its defaults (update auto-apply)",
			Retired:   "enrolment row deleted last; pushes and reports stop, the node is individual again (tenancy defaults revert at the next daemon start)",
		},
		run: func(ctx context.Context, c *Client, r *unenrolRun) error {
			return c.store.DeleteEnrolment(ctx)
		},
	},
}

// UnenrolPlan is the ordered conferred -> retired table, for the preview. It
// does no I/O.
func UnenrolPlan() []UnenrolStep {
	out := make([]UnenrolStep, 0, len(unenrolSteps))
	for _, s := range unenrolSteps {
		out = append(out, s.UnenrolStep)
	}
	return out
}

// UnenrollWithReport walks unenrolSteps and reports each row. Absent state is
// not an error (idempotent): on a node with no enrolment row only the rows that
// need none run, which still clears an orphan grant and the credentials.
func (c *Client) UnenrollWithReport(ctx context.Context) (UnenrolResult, error) {
	enr, _ := c.store.LoadEnrolment(ctx) //nolint:errcheck // best-effort snapshot; absent is fine
	res := UnenrolResult{WasEnrolled: enr != nil}
	run := &unenrolRun{enr: enr, res: &res}
	if enr != nil {
		run.orgKey = OrgKey(enr.OrgServerURL, enr.OrgID)
		run.managed, _ = NodeManagedFor(ctx, c.store, enr) //nolint:errcheck // a read error names no machine, as before
	}
	for _, s := range unenrolSteps {
		if s.needsEnrolment && enr == nil {
			res.Steps = append(res.Steps, UnenrolStepResult{ID: s.ID})
			continue
		}
		err := s.run(ctx, c, run)
		row := UnenrolStepResult{ID: s.ID, Ran: true}
		if err != nil {
			if s.Required {
				return res, fmt.Errorf("orgclient.Unenroll: %s: %w", s.ID, err)
			}
			row.Err = err.Error()
			c.logger.Warn("unenroll: a best-effort step failed; the leave continues", "step", s.ID, "err", err)
		}
		res.Steps = append(res.Steps, row)
	}
	if c.orgIdentityChangedSink != nil {
		c.orgIdentityChangedSink()
	}
	c.logger.Info("unenrolled from org")
	return res, nil
}

// notifyLeave is the one network call of a leave: POST /api/agent/leave with
// the still-present bearer, bounded by leaveNoticeTimeout. It never fails the
// leave; it reports whether the organization recorded it and, if not, why.
func (c *Client) notifyLeave(ctx context.Context, enr *store.Enrolment, managed bool) (bool, string) {
	if enr == nil || c.httpClient == nil {
		return false, "not sent: no enrolment"
	}
	bearer, err := c.bearers.LoadBearer()
	if err != nil {
		return false, "not sent: no org credential on this machine"
	}
	cctx, cancel := context.WithTimeout(ctx, leaveNoticeTimeout)
	defer cancel()
	url := strings.TrimRight(enr.OrgServerURL, "/") + orgcontract.AgentLeavePath
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, url, bytes.NewReader([]byte("{}")))
	if err != nil {
		return false, "not sent: " + err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	// T-747: a managed node names its machine and proves it with the machine
	// key it already holds, so the server retires that key and a later
	// re-enrolment of this machine (a reinstall with a new key) is not a 409.
	c.attachLeaveProof(req, enr, managedMachineIdentityOf(enr, managed))
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, "the organization server could not be reached; it will see this node stop reporting"
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, ""
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return false, "the organization server predates leave notices; it will see this node stop reporting"
	default:
		return false, fmt.Sprintf("the organization server answered %d; it will see this node stop reporting", resp.StatusCode)
	}
}
