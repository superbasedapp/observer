//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudbudget.go is the node half of the evidence budget (managed-SaaS
// ruling R-AI1, docs/cloud-intelligence.md "Plan v5: token budgets"). The
// hosted service refuses an envelope whose estimated evidence tokens exceed
// the account tier's evidence budget (413 evidence_over_budget). The node
// fits instead: the preview and consent build is stepped down with
// cloudevidence.FitToBudget, the fitted settings are what the consent
// receipt freezes, and the send-time rebuild (which uses the receipt's
// settings) therefore reproduces the exact bytes previewed.
//
// The budget is what the last `observer cloud sync` read from GET /v1/usage
// (migration 254, store.LastKnownCloudEvidenceTokenBudget), else the free
// tier's cloudcontract.DefaultEvidenceTokenBudget.

// errCloudEvidenceOverBudget is the floor case: even the ladder's smallest
// envelope is over the budget, so nothing can be sent for this session.
var errCloudEvidenceOverBudget = cloudevidence.ErrEvidenceOverBudget

// cloudEvidenceBudget resolves the evidence budget a build fits to.
func cloudEvidenceBudget(ctx context.Context, st *store.Store) (budget int, known bool, err error) {
	budget, known, err = st.LastKnownCloudEvidenceTokenBudget(ctx)
	if err != nil {
		return 0, false, err
	}
	if !known {
		return cloudcontract.DefaultEvidenceTokenBudget, false, nil
	}
	return budget, true, nil
}

// cloudEnvelopeBuild builds one envelope under the given settings (nil = the
// legacy unconfigured selection). It is buildPlaneEnvelope bound to one
// session, purpose and plane.
type cloudEnvelopeBuild func(*store.CloudEvidenceSettings) (cloudEnvelopeResult, error)

// fitCloudEnvelopeToBudget returns the build of settings when it fits
// budgetTokens, else the first rung of the step-down ladder that fits, built
// whole by the same build path. A floor that does not fit returns an error
// wrapping cloudevidence.ErrEvidenceOverBudget with the copy the CLI prints.
//
// The result's EvidenceSettingsJSON names the settings the returned bytes
// were built with, so the receipt the consent records freezes them. An
// unconfigured (nil) selection that does not fit steps down from the
// default settings, so its receipt then carries explicit settings.
func fitCloudEnvelopeToBudget(purpose cloudcontract.Purpose, settings *store.CloudEvidenceSettings, budgetTokens int, budgetKnown bool, build cloudEnvelopeBuild) (cloudEnvelopeResult, error) {
	first, err := build(settings)
	if err != nil {
		return cloudEnvelopeResult{}, err
	}
	note := cloudBudgetNote{
		BudgetTokens: budgetTokens, BudgetKnown: budgetKnown,
		EstimatedTokens: cloudcontract.EstimateEvidenceTokens(len(first.Bytes)),
	}
	note.UnfittedTokens = note.EstimatedTokens
	if cloudcontract.EvidenceFitsBudget(len(first.Bytes), budgetTokens) {
		first.Budget = &note
		return first, nil
	}

	base := store.DefaultCloudEvidenceSettings()
	if settings != nil {
		base = *settings
	}
	effective, _, err := cloudSettingsForPurpose(&base, purpose)
	if err != nil {
		return cloudEnvelopeResult{}, err
	}
	built := map[cloudcontract.EvidenceSettings]cloudEnvelopeResult{}
	if settings != nil {
		// The unstepped build above IS the base build: never read the session twice for it.
		built[*effective] = first
	}
	fit, err := cloudevidence.FitToBudget(*effective, budgetTokens, func(s cloudcontract.EvidenceSettings) ([]byte, error) {
		if r, ok := built[s]; ok {
			return r.Bytes, nil
		}
		r, berr := build(&s)
		if berr != nil {
			return nil, berr
		}
		built[s] = r
		return r.Bytes, nil
	})
	if errors.Is(err, errCloudEvidenceOverBudget) {
		return cloudEnvelopeResult{}, fmt.Errorf("%w. This session is too large for your plan's evidence budget of %d tokens even with the smallest selection (one short prompt, no tool activity), so it cannot be sent; nothing was recorded", err, budgetTokens)
	}
	if err != nil {
		return cloudEnvelopeResult{}, err
	}
	res, ok := built[fit.Settings]
	if !ok {
		return cloudEnvelopeResult{}, errors.New("cloud evidence budget: the fitted build was not recorded")
	}
	note.EstimatedTokens = fit.EstimatedTokens
	note.SteppedDown = true
	note.Rung = fit.Rung
	if note.Rung == "" {
		note.Rung = "L0"
	}
	res.Budget = &note
	return res, nil
}

// cloudPrintBudgetLine prints the preview / consent summary's budget line, so
// the developer sees that (and why) the bytes above are a smaller selection
// than their settings.
func cloudPrintBudgetLine(w io.Writer, n *cloudBudgetNote) {
	if n == nil {
		return
	}
	source := "your plan's"
	if !n.BudgetKnown {
		source = "the default (no sync has read your plan yet)"
	}
	if n.BudgetTokens <= 0 {
		fmt.Fprintf(w, "evidence budget:         none on your plan (about %d tokens)\n", n.EstimatedTokens)
		return
	}
	fmt.Fprintf(w, "evidence budget:         about %d of %d tokens, %s evidence budget\n", n.EstimatedTokens, n.BudgetTokens, source)
	if n.SteppedDown {
		fmt.Fprintf(w, "                         stepped down to step %s to fit (your settings would send about %d tokens); the evidence settings above are the reduced ones this consent freezes\n",
			n.Rung, n.UnfittedTokens)
	}
}

// cloudApplyUsageTokens copies the token budgets a successful usage read
// reported onto the sync record. u nil (no read this run) leaves them nil,
// which keeps the stored evidence budget and shows the windows as unknown.
func cloudApplyUsageTokens(rec *store.CloudSyncLast, u *cloudgateway.UsageView) {
	if u == nil {
		return
	}
	evidence := u.EvidenceTokenBudget
	rec.EvidenceTokenBudget = &evidence
	rec.BudgetUnit, rec.EnrichmentTier = u.BudgetUnit, u.EnrichmentTier
	if u.BudgetUnit != cloudBudgetUnitTokens {
		return
	}
	session, dUsed, dBudget, mUsed, mBudget := u.SessionTokenBudget, u.DailyTokensUsed, u.DailyTokenBudget, u.MonthlyTokensUsed, u.MonthlyTokenBudget
	rec.SessionTokenBudget, rec.DailyTokensUsed, rec.DailyTokenBudget = &session, &dUsed, &dBudget
	rec.MonthlyTokensUsed, rec.MonthlyTokenBudget = &mUsed, &mBudget
}

// cloudBudgetUnitTokens is the usage view's budget_unit on a token plan.
const cloudBudgetUnitTokens = "tokens"
