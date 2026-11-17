//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/orgintel"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// intelsubmit.go builds and queues NODE-BUILT org-plane evidence (Cloud
// Intelligence parity phase 2, the B1 rail): the same cloudevidence builder as
// the personal plane, for PlaneOrg, at the level orgintel.PlanSubmit allows.
// The org client sends queued rows on its push cycle
// (internal/orgclient/intelsubmit.go). Nothing here talks to the network.

// orgIntelSubmitPerCycle bounds one background cycle. Which sessions qualify
// (quiet, min actions, max age) and whether the sweep runs at all come from
// the org's terms (orgintel.SweepFor, parity phase 4).
const orgIntelSubmitPerCycle = 3

// buildOrgIntelEnvelope builds the org-plane envelope for a session at plan's
// level, with the org's excerpt selection narrowed to that level (nil = the
// builder's defaults). The bytes are deterministic, so a preview and the later
// submission of an unchanged session are byte-identical (the two-digest
// truth).
func buildOrgIntelEnvelope(ctx context.Context, st *store.Store, orgID, sessionID string, plan orgintel.SubmitPlan, settings *cloudcontract.EvidenceSettings, pricer *cost.Engine) (orgIntelBuilt, error) {
	if !plan.OK {
		return orgIntelBuilt{}, fmt.Errorf("org session enrichment is not available on this machine (%s)", plan.Reason)
	}
	classes := make([]string, 0, 1)
	for _, c := range plan.Level.FieldClasses() {
		classes = append(classes, string(c))
	}
	res, err := buildPlaneEnvelope(ctx, st, envelopePlane{plane: cloudcontract.PlaneOrg, orgID: orgID},
		sessionID, plan.Purpose, classes, pricer, settings)
	if err != nil {
		return orgIntelBuilt{}, err
	}
	// The level recorded is what the bytes CARRY (a titles build of a
	// session with no real prompt carries no excerpt): the server's rule.
	level := plan.Level
	if res.Envelope != nil {
		level = cloudcontract.EnvelopeEvidenceLevel(*res.Envelope)
	}
	return orgIntelBuilt{OrgID: orgID, Level: level, Purpose: level.Purpose(), Result: res}, nil
}

// queueOrgIntelSubmission queues a built envelope (inserted=false when the
// same bytes are already queued or sent).
func queueOrgIntelSubmission(ctx context.Context, st *store.Store, b orgIntelBuilt, sessionID, trigger string) (store.OrgIntelSubmission, bool, error) {
	return st.EnqueueOrgIntelSubmission(ctx, store.OrgIntelSubmission{
		OrgID: b.OrgID, SessionID: sessionID, Purpose: string(b.Purpose), EvidenceLevel: string(b.Level),
		Trigger: trigger, EvidenceDigest: b.Result.Digests.EvidenceContent, UploadDigest: b.Result.Digests.Upload,
		Envelope: b.Result.Bytes,
	}, time.Now().UTC())
}

// orgIntelSubmitPlanFor resolves the node's current submission plan.
func orgIntelSubmitPlanFor(ctx context.Context, st *store.Store, configKey bool, railOn bool) (orgIntelSnapshot, orgintel.SubmitPlan, error) {
	snap, err := loadOrgIntelSnapshot(ctx, st, configKey, time.Now().UTC())
	if err != nil {
		return snap, orgintel.SubmitPlan{}, err
	}
	return snap, orgintel.PlanSubmit(snap.Inputs, railOn), nil
}

// orgIntelSubmitSource is the org client's background source: each cycle it
// queues up to orgIntelSubmitPerCycle quiet org-authority sessions this org
// has no submission for, under the current plan and the org's sweep bounds.
// When the org runs enrichment on demand only for this member, the cycle
// queues nothing. A session that cannot be built is skipped (it stays a
// candidate; nothing is queued for it).
func orgIntelSubmitSource(st *store.Store, live *liveOrgEnrichment, railOn func() bool, pricer *cost.Engine) func(ctx context.Context) error {
	return func(ctx context.Context) error {
		snap, plan, err := orgIntelSubmitPlanFor(ctx, st, live.Get(), railOn())
		if err != nil || !plan.OK || snap.Enrolment == nil {
			return err
		}
		sweep := orgintel.SweepFor(snap.Inputs.Requirement)
		if !sweep.On {
			return nil
		}
		settings := orgintel.EvidenceSettingsFor(snap.Inputs.Requirement, plan.Level)
		now := time.Now().UTC()
		// The candidates are only sessions captured under the org enrolled
		// now (sessions.authority_org_key, D-43): a session captured under
		// a previous enrolment (possibly another org) is never offered here.
		since := orgintel.SweepSince(now, sweep.MaxAge)
		cands, err := st.ListOrgIntelSubmitCandidates(ctx, snap.Enrolment.OrgID, since,
			sweep.Quiet, sweep.MinActions, orgIntelSubmitPerCycle, now)
		if err != nil {
			return err
		}
		for _, c := range cands {
			b, berr := buildOrgIntelEnvelope(ctx, st, snap.Enrolment.OrgID, c.SessionID, plan, settings, pricer)
			if berr != nil {
				continue
			}
			if _, _, qerr := queueOrgIntelSubmission(ctx, st, b, c.SessionID, store.OrgIntelTriggerBackground); qerr != nil {
				return qerr
			}
		}
		return nil
	}
}
