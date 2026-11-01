package orgclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// intelsubmit.go is the node half of the B1 rail (Cloud Intelligence parity
// phase 2): sending org_intel_outbox rows over the signed
// POST /api/agent/intel/evidence. The envelopes themselves are built by
// cmd/observer (the cloudevidence builder, PlaneOrg) and queued through the
// store; this file only sends what is queued and records the answer. It rides
// the push cycle: no new timer, host or connection.

// intelSubmitMaxAttempts is how many retryable failures a row may take before
// the node stops trying (it is then refused with the last reason).
const intelSubmitMaxAttempts = 8

// intelSubmitBatch bounds the rows one cycle sends.
const intelSubmitBatch = 5

// intelSubmitBackoff is the wait before retry number n (1-based), table-driven.
var intelSubmitBackoff = []time.Duration{5 * time.Minute, 15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 6 * time.Hour}

func intelSubmitDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > len(intelSubmitBackoff) {
		return intelSubmitBackoff[len(intelSubmitBackoff)-1]
	}
	return intelSubmitBackoff[attempt-1]
}

// SetIntelSubmitSource installs the callback that QUEUES this cycle's
// background submissions (cmd/observer builds the envelopes under the org's
// level and the developer's consent). nil disables background submission;
// rows queued by a developer action are still sent.
func (c *Client) SetIntelSubmitSource(src func(ctx context.Context) error) {
	if c == nil {
		return
	}
	c.intelSubmitSource = src
}

// IntelSubmitResult is one send's interpretation.
type IntelSubmitResult struct {
	Update  store.OrgIntelSubmissionUpdate
	Receipt *orgcontract.IntelEvidenceReceipt
	Refusal *orgcontract.IntelEvidenceRefusal
}

// intelSubmitOutcomeState maps the server's admission outcome onto the row's
// terminal state.
var intelSubmitOutcomeState = map[string]string{
	"admitted":         store.OrgIntelOutboxSubmitted,
	"duplicate":        store.OrgIntelOutboxDuplicate,
	"already_enriched": store.OrgIntelOutboxAlreadyEnriched,
}

// SubmitIntelEvidence sends one queued row and records the answer on it. It
// returns the interpreted result; an error is returned only when the store
// could not record it.
func (c *Client) SubmitIntelEvidence(ctx context.Context, row store.OrgIntelSubmission) (IntelSubmitResult, error) {
	var res IntelSubmitResult
	// Consent is re-checked right before the bytes leave (review C156-20), so
	// a row read before a withdrawal is never sent after it.
	if ok, err := c.intelSendConsented(ctx, row.OrgID); err == nil && !ok {
		res = IntelSubmitResult{Update: store.OrgIntelSubmissionUpdate{State: store.OrgIntelOutboxRefused, Reason: store.OrgIntelOutboxReasonConsentWithdrawn}}
	} else {
		res = c.sendIntelEvidence(ctx, row, time.Now().UTC())
	}
	if err := c.store.MarkOrgIntelSubmission(ctx, row.ID, res.Update, time.Now().UTC()); err != nil {
		return res, err
	}
	return res, nil
}

// intelSendConsented reports whether evidence for orgID may leave now: a
// managed node needs no developer consent (the org decides), including one
// whose org switched it to enterprise (P-205: the org server admits it as
// managed); an
// individual one needs an active accepted consent for this org. A different
// or missing enrolment answers true and leaves the decision to the send
// path's own enrolment_changed / not_enrolled branches.
func (c *Client) intelSendConsented(ctx context.Context, orgID string) (bool, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return false, err
	}
	if enr == nil || enr.OrgID != orgID {
		return true, nil
	}
	if managed, merr := NodeManagedFor(ctx, c.store, enr); merr != nil {
		return false, merr
	} else if managed {
		return true, nil
	}
	_, ok, err := c.store.ActiveOrgIntelConsent(ctx, orgID)
	return ok, err
}

func (c *Client) sendIntelEvidence(ctx context.Context, row store.OrgIntelSubmission, now time.Time) IntelSubmitResult {
	retry := func(reason string) IntelSubmitResult {
		attempt := row.Attempts + 1
		if attempt >= intelSubmitMaxAttempts {
			return IntelSubmitResult{Update: store.OrgIntelSubmissionUpdate{State: store.OrgIntelOutboxRefused, Reason: "gave_up: " + reason}}
		}
		return IntelSubmitResult{Update: store.OrgIntelSubmissionUpdate{
			State: store.OrgIntelOutboxFailedRetryable, Reason: reason, NextAt: now.Add(intelSubmitDelay(attempt)),
		}}
	}
	if len(row.Envelope) == 0 {
		return IntelSubmitResult{Update: store.OrgIntelSubmissionUpdate{State: store.OrgIntelOutboxRefused, Reason: "bytes_missing"}}
	}
	ident, err := c.resolveIntelRailIdentity(ctx)
	if err != nil {
		return retry("not_enrolled")
	}
	if ident.OrgID != row.OrgID {
		// Queued for an org this machine is no longer enrolled with: never sent.
		return IntelSubmitResult{Update: store.OrgIntelSubmissionUpdate{State: store.OrgIntelOutboxRefused, Reason: "enrolment_changed"}}
	}
	body, err := json.Marshal(orgcontract.IntelEvidenceSubmit{
		SessionID: row.SessionID, Purpose: row.Purpose, Trigger: row.Trigger,
		Envelope: string(row.Envelope), EvidenceDigest: row.EvidenceDigest, UploadDigest: row.UploadDigest,
	})
	if err != nil {
		return IntelSubmitResult{Update: store.OrgIntelSubmissionUpdate{State: store.OrgIntelOutboxRefused, Reason: "encode: " + err.Error()}}
	}
	status, raw, err := c.postIntelRail(ctx, ident, orgcontract.IntelEvidencePath, body)
	if err != nil {
		return retry("unreachable")
	}
	switch {
	case status == http.StatusOK:
		var rec orgcontract.IntelEvidenceReceipt
		if err := json.Unmarshal(raw, &rec); err != nil {
			return retry("bad_reply")
		}
		state, ok := intelSubmitOutcomeState[rec.Outcome]
		if !ok {
			return retry("unknown_outcome")
		}
		return IntelSubmitResult{Receipt: &rec, Update: store.OrgIntelSubmissionUpdate{State: state, JobID: rec.JobID}}
	case status == http.StatusNotFound:
		// An older server, or the feature off: never clears, retried slowly.
		r := retry("not_supported")
		if r.Update.State == store.OrgIntelOutboxFailedRetryable {
			r.Update.NextAt = now.Add(intelSubmitBackoff[len(intelSubmitBackoff)-1])
		}
		return r
	}
	// A server error is never a verdict on the evidence: always retried.
	if status >= http.StatusInternalServerError {
		return retry(fmt.Sprintf("http_%d", status))
	}
	var ref orgcontract.IntelEvidenceRefusal
	if json.Unmarshal(raw, &ref) == nil && ref.Error != "" {
		if !ref.Retryable {
			return IntelSubmitResult{Refusal: &ref, Update: store.OrgIntelSubmissionUpdate{State: store.OrgIntelOutboxRefused, Reason: ref.Error}}
		}
		r := retry(ref.Error)
		r.Refusal = &ref
		return r
	}
	return retry(fmt.Sprintf("http_%d", status))
}

// runIntelSubmitCycle queues this cycle's background submissions and sends the
// sendable rows. Fail-open and logged; never affects push health.
func (c *Client) runIntelSubmitCycle(ctx context.Context) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return
	}
	if c.intelSubmitSource != nil {
		if err := c.intelSubmitSource(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.logger.Debug("org intelligence: queueing background submissions failed", "err", err)
		}
	}
	// Review C156-20: an individual node whose consent ended sends nothing,
	// and whatever is still queued is cancelled here too (the withdrawal
	// already cancels in its own transaction; this covers a row queued by a
	// cycle that raced it).
	if ok, cerr := c.intelSendConsented(ctx, enr.OrgID); cerr == nil && !ok {
		if n, err := c.store.CancelPendingOrgIntelSubmissions(ctx, enr.OrgID, store.OrgIntelOutboxReasonConsentWithdrawn, time.Now().UTC()); err != nil {
			c.logger.Warn("org intelligence: cancelling unconsented submissions failed", "err", err)
		} else if n > 0 {
			c.logger.Info("org intelligence: cancelled queued submissions, consent is no longer active", "rows", n)
		}
		return
	}
	rows, err := c.store.SendableOrgIntelSubmissions(ctx, enr.OrgID, time.Now().UTC(), intelSubmitBatch)
	if err != nil {
		c.logger.Warn("org intelligence: reading the submission outbox failed", "err", err)
		return
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return
		}
		res, err := c.SubmitIntelEvidence(ctx, row)
		if err != nil {
			c.logger.Warn("org intelligence: recording a submission failed", "id", row.ID, "err", err)
			continue
		}
		c.logger.Debug("org intelligence: submission sent", "id", row.ID, "state", res.Update.State, "reason", res.Update.Reason)
	}
}
