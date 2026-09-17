package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/intervention"
	"github.com/marmutapp/superbased-observer/internal/orgbudget"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// nodeInterventionGuardUnavailableReason is the single operator-facing
// statement for the fail-closed stop a managed node performs when its shared
// guard could not be composed. It is used verbatim by the audit reason and by
// the controller status report so the two can never diverge.
const nodeInterventionGuardUnavailableReason = "guard unavailable on a managed node; AI tool processes are stopped until [guard] is enabled"

// nodeInterventionAuthority resolves the accepted managed grant on every
// operation. It binds signals to the enrollment member and daemon's OS user;
// holding an org budget alone never grants authority over another user's work.
func nodeInterventionAuthority(ctx context.Context, st *store.Store, uid int, now time.Time) (intervention.PolicyDecision, error) {
	if st == nil || uid < 0 || now.IsZero() {
		return intervention.PolicyDecision{}, errors.New("node intervention: authority inputs unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	enr, err := st.LoadEnrolment(ctx)
	if err != nil {
		return intervention.PolicyDecision{}, err
	}
	if !enr.IsManaged() {
		return intervention.PolicyDecision{}, nil
	}
	grant, live, err := governanceIdentityLoader(st)(ctx)
	if err != nil {
		return intervention.PolicyDecision{}, err
	}
	// The second enrollment read fences same-org member replacement while
	// loading the grant. The actual signal uses a transaction fence below.
	current, err := st.LoadEnrolment(ctx)
	if err != nil {
		return intervention.PolicyDecision{}, err
	}
	if current == nil || *current != *enr {
		return intervention.PolicyDecision{}, errors.New("node intervention: enrollment changed during authority read")
	}
	return nodeInterventionPermit(enr, grant, live, uid, now)
}

func nodeInterventionPermit(enr *store.Enrolment, grant *govern.Grant, live govern.LiveIdentity, uid int, now time.Time) (intervention.PolicyDecision, error) {
	if !enr.IsManaged() || uid < 0 || now.IsZero() {
		return intervention.PolicyDecision{}, nil
	}
	if grant == nil {
		return intervention.PolicyDecision{}, errors.New("node intervention: managed grant unavailable")
	}
	if !govern.Resolve(govern.Delivered{}, grant, live, now).GrantsBudgetEnforcement() {
		return intervention.PolicyDecision{}, nil
	}
	if enr.UserID == "" || enr.OrgID != grant.OrgID ||
		orgclient.OrgKey(enr.OrgServerURL, enr.OrgID) != live.OrgKey {
		return intervention.PolicyDecision{}, errors.New("node intervention: enrollment changed during authority read")
	}
	raw, err := json.Marshal(struct {
		OrgKey     string
		Member     string
		Generation int64
		Receipt    string
		EnrolledAt string
		UID        int
	}{live.OrgKey, enr.UserID, live.Generation, grant.ReceiptHash, enr.EnrolledAt, uid})
	if err != nil {
		return intervention.PolicyDecision{}, err
	}
	sum := sha256.Sum256(raw)
	until := now.Add(5 * time.Second)
	if !grant.ExpiresAt.IsZero() && grant.ExpiresAt.Before(until) {
		until = grant.ExpiresAt
	}
	return intervention.PolicyDecision{
		Authorized: true, Authority: hex.EncodeToString(sum[:]),
		BudgetBinding: orgclient.BudgetPolicyBinding(enr, live.Generation), ValidUntil: until,
	}, nil
}

// nodeInterventionSignalFence closes the authority check/use window. The
// bounded OS operation holds the database's write reservation, so another
// process cannot replace/revoke enrollment or the grant between validation
// and signal delivery. No store read, pricing lookup or network call occurs
// in the action callback. TERM and KILL each acquire their own fresh fence.
func nodeInterventionSignalFence(st *store.Store, gd *guard.Guard) func(context.Context, intervention.Workload, intervention.PolicyDecision, func(context.Context) (intervention.ExitResult, error)) (intervention.ExitResult, error) {
	return func(ctx context.Context, w intervention.Workload, expected intervention.PolicyDecision, action func(context.Context) (intervention.ExitResult, error)) (intervention.ExitResult, error) {
		var result intervention.ExitResult
		if st == nil || !expected.Authorized || !expected.Stop || action == nil {
			return result, errors.New("node intervention: signal has no scoped stop authority")
		}
		enr, err := st.LoadEnrolment(ctx)
		if err != nil || !enr.IsManaged() {
			return result, errors.New("node intervention: signal enrollment unavailable")
		}
		key := orgclient.OrgKey(enr.OrgServerURL, enr.OrgID)
		expectedWitness := store.OrgBudgetWitness{
			Known: expected.BudgetDocumentKnown, Present: expected.BudgetDocumentPresent, SHA256: expected.BudgetDocumentSHA256,
		}
		var expectedPricing *store.OrgPricingWitness
		if expected.PricingDocumentRequired {
			if expected.AccountingFence == nil {
				return result, errors.New("node intervention: pricing table fence unavailable")
			}
			witness := store.OrgPricingWitness{
				Known: expected.PricingDocumentKnown, Present: expected.PricingDocumentPresent, SHA256: expected.PricingDocumentSHA256,
			}
			if !witness.Valid() {
				return result, errors.New("node intervention: pricing document witness unavailable")
			}
			expectedPricing = &witness
		}
		err = st.WithInterventionFence(ctx, key, orgclient.PolicyKeyPinPath(enr.OrgServerURL), expectedWitness, expectedPricing, func(snapshot store.InterventionAuthority) error {
			live := govern.LiveIdentity{Enrolled: true, OrgKey: key, KeyPinSHA256: snapshot.KeyPinSHA256}
			if snapshot.HaveGeneration {
				live.Generation = snapshot.Generation.Generation
				live.Enrolled = !snapshot.Generation.Tombstoned
			}
			var grant *govern.Grant
			if snapshot.HaveGrant {
				grant = grantFromStore(snapshot.Grant)
			}
			now := time.Now().UTC()
			current, err := nodeInterventionPermit(snapshot.Enrolment, grant, live, w.Identity.UID, now)
			if err != nil || !current.Authorized || current.Authority != expected.Authority ||
				current.BudgetBinding != expected.BudgetBinding || !expected.ValidUntil.After(now) {
				return errors.New("node intervention: signal authority changed or expired")
			}
			actionCtx, actionCancel := context.WithDeadline(ctx, expected.ValidUntil)
			defer actionCancel()
			if err := actionCtx.Err(); err != nil {
				return err
			}
			operate := func() error {
				result, err = action(actionCtx)
				return err
			}
			accountedOperation := func() error {
				if expected.AccountingFence != nil {
					return expected.AccountingFence(actionCtx, operate)
				}
				return operate()
			}
			if gd != nil {
				return gd.WithInterventionRevision(actionCtx, expected.PolicyRevision, accountedOperation)
			}
			return accountedOperation()
		})
		return result, err
	}
}

// nodeInterventionBudget uses the daemon's shared effective guard, including
// hot-applied org budget/pricing state. Source readiness is separate evidence
// from native capture; an empty successful SQL read cannot set it. The source
// evidence is per TOOL: one adapter's broken capture never denies another
// adapter's processes.
func nodeInterventionBudget(ctx context.Context, st *store.Store, cfg config.Config, gd *guard.Guard, w intervention.Workload, source nodeInterventionSource, now time.Time) (intervention.PolicyDecision, error) {
	d, err := nodeInterventionAuthority(ctx, st, w.Identity.UID, now)
	if err != nil || !d.Authorized {
		return d, err
	}
	if gd == nil {
		cached, cacheErr := loadVerifiedOrgBudgetCache(ctx, cfg, st)
		setPolicyBudgetWitness(&d, guardBudgetDocumentWitness(cached.Witness))
		fetchState := initialFetchState(cfg.Guard.Budget.FromOrg)
		switch {
		case cacheErr != nil:
			fetchState = orgcontract.BudgetFetchUnverified
		case cached.Have:
			fetchState = orgcontract.BudgetFetchUnreachable
		}
		haveBody := cacheErr == nil && cached.Have && cached.Binding == d.BudgetBinding
		if cached.Have && !haveBody {
			fetchState = orgcontract.BudgetFetchUnverified
		}
		effective, _ := orgbudget.Compose(thresholdsOf(cfg.Guard.Budget), cached.Body, orgbudget.Capabilities{
			FromOrg: cfg.Guard.Budget.FromOrg, OrgAuthoritative: true, RequireOrgBudget: true,
			HaveBody: haveBody, FetchState: fetchState, GuardMode: cfg.Guard.Mode,
		})
		d.Stop = effective.BudgetRequired || effective.Protection.Any()
		if d.Stop {
			d.RuleID = "B-625"
			switch {
			case cacheErr != nil && cached.Witness.Valid() && cached.Witness.Present:
				d.Reason = "managed budget document is malformed or unverified"
			case cacheErr != nil:
				d.Reason = "managed budget document state is unavailable"
			case !cached.Have && cached.Witness.Valid() && !cached.Witness.Present:
				d.Reason = "managed budget document is missing"
			default:
				d.Reason = "managed budget document could not be evaluated"
			}
			// Every branch here runs because the shared guard itself is absent.
			// Stopping is still the fail-closed answer on a managed node, but
			// the operator must be told that the fix is enabling the guard, not
			// chasing the budget document.
			d.Reason += "; " + nodeInterventionGuardUnavailableReason
		}
		return d, nil
	}
	// MODEL IS NOT PASSED, and that is the design, not an omission
	// (BUD-GUARD-1, docs/audits/codebase-audit-2026-09-16.md). The process
	// controller knows a surface and a tool; it does not know which model the
	// running agent is talking to. The ONE resolver of that fact is the
	// accounting snapshot's SessionModel — the exact sibling of SessionTool —
	// which the guard applies to the event under the same precedence rule as
	// the tool: a caller that KNOWS the model (the proxy, from the request
	// body) keeps its own, and a caller that does not falls back to the
	// session's own captured rows when they name exactly one. Resolving it a
	// second time here would be a second owner of one fact and a second
	// database read per decision, and the two could disagree.
	//
	// What that means for the org's per-model caps (B-628/B-629): they reach a
	// RUNNING session whose captured rows agree on a model, and they reach no
	// session for which they do not — an empty w.SessionID, a session whose
	// rows name two models, a session with no rows yet. Those are honest
	// misses, flagged by the unanimity rule rather than guessed at, and
	// docs/budgets.md states them.
	budget := gd.CheckInterventionBudget(guard.InterventionBudgetInput{
		SessionID: w.SessionID, SourceReady: source.Ready, SourceReason: source.Reason,
		Tool: source.Tool, Now: now, BudgetBinding: d.BudgetBinding,
	})
	d.Stop = budget.Deny
	d.PolicyRevision = budget.Revision
	if !budget.ValidUntil.IsZero() && budget.ValidUntil.Before(d.ValidUntil) {
		d.ValidUntil = budget.ValidUntil
	}
	setPolicyBudgetWitness(&d, budget.DocumentWitness)
	setPolicyPricingWitness(&d, budget.PricingDocumentRequired, budget.PricingDocumentWitness)
	if budget.AccountingEvidence != nil {
		d.AccountingFence = budget.AccountingEvidence.Fence
	}
	d.RuleID = budget.RuleID
	d.Reason = budget.Reason
	return d, nil
}

func setPolicyPricingWitness(d *intervention.PolicyDecision, required bool, witness guard.BudgetDocumentWitness) {
	if d == nil {
		return
	}
	d.PricingDocumentRequired = required
	d.PricingDocumentKnown = witness.Known
	d.PricingDocumentPresent = witness.Present
	d.PricingDocumentSHA256 = witness.SHA256
}

func setPolicyBudgetWitness(d *intervention.PolicyDecision, witness guard.BudgetDocumentWitness) {
	if d == nil {
		return
	}
	d.BudgetDocumentKnown = witness.Known
	d.BudgetDocumentPresent = witness.Present
	d.BudgetDocumentSHA256 = witness.SHA256
}
