package orgclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgclient/gen"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// PushResult summarises one push attempt for the CLI / loop.
type PushResult struct {
	Empty        bool  // nothing above the cursor; no network call was made
	RowCount     int   // rows in the batch
	Bytes        int   // gzip wire bytes shipped
	AcceptedRows int64 // server-reported newly-stored rows
	DedupedRows  int64 // server-reported already-present rows
	// More reports that the batch was cut by the byte budget and rows are
	// still waiting (store.PushBatch.Full): the push loop re-kicks.
	More bool
}

// LastPayload returns the JSON of the most recent successfully-pushed envelope
// (the content-free rollup, byte-for-byte as it went on the wire), or nil when
// the agent has never pushed. The dashboard serves it verbatim so a developer
// can audit exactly what was shared.
func (c *Client) LastPayload(ctx context.Context) ([]byte, error) {
	return c.store.LoadLastPushPayload(ctx)
}

// PushOnce ships at most one batch of content-free rows above the local push
// cursor to the org server. An empty batch makes no network call and writes no
// log row. On HTTP 200 it advances + persists the cursor and records an "ok"
// push-log row; on an auth failure it records "failed" and returns
// ErrAuthFailed; on any other failure (network, 5xx, 429, 4xx) it records
// "retry" and returns a (retryable) error.
func (c *Client) PushOnce(ctx context.Context) (PushResult, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w", err)
	}
	if enr == nil {
		c.noteCredential(false, credentialNoRecord)
		return PushResult{}, ErrNotEnrolled
	}
	bearer, err := c.bearers.LoadBearer()
	if errors.Is(err, ErrNoSecret) {
		c.noteCredential(false, credentialNoBearer)
		return PushResult{}, ErrNotEnrolled
	}
	if err != nil {
		c.noteCredential(false, credentialNoBearer+": "+err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: load bearer: %w", err)
	}
	signKey, err := c.bearers.LoadAgentKey()
	if errors.Is(err, ErrNoSecret) {
		c.noteCredential(false, credentialNoKey)
		return PushResult{}, ErrNotEnrolled
	}
	if err != nil {
		c.noteCredential(false, credentialNoKey+": "+err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: load signing key: %w", err)
	}
	c.noteCredential(true, "")

	cur, err := c.store.LoadPushCursor(ctx)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: load cursor: %w", err)
	}
	batch, err := c.selectBatch(ctx, cur, c.maxPushBytes(), enr)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: select: %w", err)
	}
	if batch.Empty() {
		// Nothing to deliver, so every snapshot family composed this tick is
		// as delivered as it can be: commit, or a family that legitimately
		// recomputes to zero rows would re-probe as dirty forever.
		c.store.CommitPushedSnapshots()
		// A cursor can still have moved without a row to ship: the
		// per-session rate-limit wire consumes snapshots that can never ship
		// (no linked session, or out of scope). Persist that progress (same
		// CAS as an accepted push) so an idle node does not re-scan the same
		// unshippable rows every tick, and a long unshippable run cannot pin
		// the wire below a later shippable window. Nothing was delivered, so
		// nothing is acknowledged. Best-effort: a failure only re-scans.
		if batch.Cursor != cur {
			if _, err := c.store.SavePushCursorIfUnchanged(ctx, cur, batch.Cursor); err != nil {
				c.logger.Warn("org push: saving the cursor past unshippable rows failed; they will be re-scanned", "err", err)
			}
		}
		return PushResult{Empty: true}, nil
	}

	env := EnvelopeFromBatch(batch, cur, EnvelopeMeta{
		AgentVersion: c.agentVersion,
		// Managed tenancy only: ManagedMachineIdentity returns "" for an
		// individual/BYO enrolment, an unresolvable machine id, or any load
		// error, and the field is omitempty — so an unmanaged node's envelope
		// stays byte-identical to the pre-feature shape. Reusing the SAME
		// accessor PostPolicyState uses keeps one definition of "this node's
		// machine identity" (the server keys on it across both rails).
		MachineIdentity: c.ManagedMachineIdentity(ctx),
		// Agent Access P4 W4e: the per-DEVICE source key, derived from the
		// agent-access key slot when one is present (sourcenodekey.go);
		// "" (omitempty) on a node without the slot, so its envelope stays
		// byte-identical to the pre-P4 shape.
		SourceNodeKey: c.sourceNodeKey(),
		PushInterval:  c.pushInterval(),
	})
	raw, err := json.Marshal(env)
	if err != nil {
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), 0, "failed", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: marshal: %w", err)
	}
	batch, _, raw, err = c.recomposeToFit(ctx, cur, enr, batch, env, raw)
	if err != nil {
		return PushResult{}, err
	}
	if batch.Empty() {
		// A recompose can only shrink, never empty, an envelope with a cursor
		// row (the first row is always admitted); this guards the impossible.
		return PushResult{Empty: true}, nil
	}
	if err := validatePushBodySize(raw, c.maxPushBytes()); err != nil {
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(raw)), "failed", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w", err)
	}
	wire, err := gzipBytes(raw)
	if err != nil {
		// A marshal/gzip failure is local and not retryable, but recording it
		// keeps the dashboard honest about why nothing shipped.
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), 0, "failed", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: encode: %w", err)
	}

	ts := time.Now().Unix()
	sig := ed25519.Sign(signKey, orgcontract.PushSigningMessage(ts, wire))
	localFP := orgcontract.AgentKeyFingerprint(signKey.Public().(ed25519.PublicKey))

	gc, err := c.genClient(enr.OrgServerURL)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w", err)
	}
	// P2b: report the grant-replacement generation this node has adopted so the
	// server's fleet-ACK gate can converge. 0 (no grant, or no replacement yet)
	// still registers the node in the fleet registry. Best-effort: a read
	// failure just leaves the ACK at 0.
	ackGen := c.currentReplacementGeneration(ctx, enr)
	params := &gen.PushBatchParams{
		XSBOTimestamp:      &ts,
		XSBOAgentSignature: strPtr(base64.RawURLEncoding.EncodeToString(sig)),
	}
	// G1-BREAKGLASS: publish this node's seal key (signed, bound to org+node)
	// and report any redeemed leases the server has not heard about yet.
	bgAcks := c.pendingBreakGlassAcks()
	resp, err := gc.PushBatchWithBodyWithResponse(ctx, params, "application/json", bytes.NewReader(wire),
		bearerEditor(bearer), gzipEncodingEditor, agentKeyFingerprintEditor(localFP),
		grantReplacementAckEditor(ackGen), sealKeyEditor(signKey, enr.OrgID, enr.UserID),
		breakGlassAckEditor(bgAcks))
	if err != nil {
		c.noteRenewal(RenewalPathPush, 0, err)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "retry", err.Error())
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: post: %w", err)
	}
	// The renewal signal (§4.2) is keyed off the PUSH path's own
	// authorization, which is the requirement parent §11.3 states: an org
	// that revokes push permission but leaves the policy poll working must
	// not keep governing the machine indefinitely.
	c.noteRenewal(RenewalPathPush, resp.StatusCode(), nil)

	switch resp.StatusCode() {
	case http.StatusOK:
		// Compare-and-swap against the cursor THIS cycle loaded, never a blind
		// save: an enrolment re-seed or an `observer org backfill` reset that
		// landed while this batch was in flight owns the stored cursor, and
		// overwriting it would either replay the node's whole pre-enrolment
		// history (the 2026-09-07 re-enrol regression) or undo the operator's
		// deliberate reset. The rows this cycle did deliver are absorbed by the
		// server's dedup, so keeping the stored cursor loses nothing.
		saved, err := c.store.SavePushCursorIfUnchanged(ctx, cur, batch.Cursor)
		if err != nil {
			return PushResult{}, fmt.Errorf("orgclient.PushOnce: save cursor: %w", err)
		}
		if !saved {
			c.logger.Info("push cursor moved underneath this cycle (enrol or backfill); keeping the stored cursor")
		}
		// Re-send queue (agent migration 140): the rows this batch carried are
		// now on the org at this batch's NodeRev, so their queued changes (up
		// to that snapshot) are done. Best-effort: a failure only means those
		// rows re-send once more, which the org absorbs (an equal NodeRev is a
		// no-op).
		if err := c.store.AckPushedChanges(ctx, batch.Acks); err != nil {
			c.logger.Warn("org push: acknowledging re-sent rows failed; they will re-send", "err", err)
		}
		// Snapshot families are "delivered" only once the server has ACCEPTED
		// the batch — every other exit path leaves them dirty so the next tick
		// recomposes what this one failed to ship (plan Track R2 constraint 4).
		c.store.CommitPushedSnapshots()
		// Persist the exact rollup that was shared so the dashboard can show it
		// (best-effort: a failure here never fails an accepted push).
		_ = c.store.SaveLastPushPayload(ctx, raw)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "ok", "")
		res := PushResult{RowCount: batch.RowCount(), Bytes: len(wire), More: batch.Full}
		// Server backpressure (P3): the org may advise a minimum gap
		// between this node's pushes; the push scheduler honours it.
		c.notePushMinInterval(resp.HTTPResponse)
		if resp.JSON200 != nil {
			res.AcceptedRows = resp.JSON200.AcceptedRows
			res.DedupedRows = resp.JSON200.DedupedRows
		}
		// P2b grant-replacement delivery (design §5.3, Sol S4). An out-of-band
		// authority change may ride the push response. The generated 200 struct
		// does not carry the field, so decode it from the RAW body and feed the
		// already-built, independently-tested accept path. Best-effort: a
		// delivery or accept failure never fails an otherwise-accepted push.
		c.maybeApplyGrantReplacement(ctx, resp.Body)
		// The re-consent advisory (reconsent.go): recorded for the local
		// dashboard's prompt, never acted on.
		c.noteReconsent(resp.Body)
		// The server has now heard the ACKs this push carried; then redeem any
		// newly delivered leases / drop early-revoked ones (best-effort).
		c.markBreakGlassAcked(bgAcks)
		c.maybeRedeemBreakGlassLeases(ctx, resp.Body, signKey, enr)
		c.maybeKickPolicyResourceFetch(resp.Body)
		// Enterprise Update Management nudge (§3.5). Same raw-body,
		// best-effort shape as the seams above: the response may name a newer
		// published manifest version per channel, and only then does the node
		// fetch the SIGNED manifest with a separate authenticated GET. An org
		// that has published nothing adds ZERO requests to this cycle.
		c.noteUpdateNudge(resp.Body)
		// The org's stated purpose for its Code security views (lane
		// SEC-E3), for the dashboard's affected-worker notice.
		c.noteSecurityPurpose(ctx, resp.Body)
		// A renamed org (T-862): the acknowledgment carries the org's current
		// display name, recorded in place of the enrolment's. Best-effort.
		c.noteOrgName(ctx, resp.JSON200, enr)
		// Whether the org is the developer's own (finding F12): recorded so
		// the daemon picks the owner audience's managed defaults. Best-effort.
		c.noteOwnerManaged(ctx, resp.JSON200, enr)
		// An accepted push proves this node is not below the org's floor, so
		// a previously-recorded 426 refusal is stale the instant we get here.
		c.clearAgentTooOld()
		return res, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		msg := c.reportAuthFailure(resp.Body, resp.StatusCode(), localFP, enr.OrgServerURL)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "failed", msg)
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w: %s", ErrAuthFailed, msg)
	case http.StatusRequestEntityTooLarge:
		msg := serverError(resp.Body, resp.StatusCode())
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "failed", msg)
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w: %s", ErrBatchTooLarge, msg)
	case http.StatusUpgradeRequired:
		// Enterprise update management W5: the org refuses pushes from agents
		// below [server].min_agent_version. Recorded as FAILED (not "retry")
		// with the version-naming message, because this is not a transient
		// condition an operator should wait out — it clears when the node is
		// updated, and the node dashboard's update banner reads exactly this
		// record to say so.
		msg := c.noteAgentTooOld(resp.Body, resp.StatusCode())
		c.logger.Error("org push refused: this node is below the org's minimum agent version", "detail", msg)
		// A refused node is exactly the node that most needs an update, so
		// the update rail is armed HERE rather than only on the 200 path. The
		// server's 426 body carries the same update_versions nudge an
		// accepted push does (an additive, optional field), and the channel
		// is marked pending regardless so a server too old to send it still
		// lifts this node over the floor. Without this the one mechanism that
		// can fix the condition was gated behind the push the condition
		// refuses.
		c.noteUpdateNudge(resp.Body)
		c.markUpdateChannelPendingAfterRefusal(ctx)
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "failed", msg)
		return PushResult{}, fmt.Errorf("orgclient.PushOnce: %w: %s", ErrAgentTooOld, msg)
	default:
		msg := serverError(resp.Body, resp.StatusCode())
		_ = c.store.RecordPush(ctx, int64(batch.RowCount()), int64(len(wire)), "retry", msg)
		// A typed error (not a bare fmt.Errorf string) so normalizeFailureKey
		// can key runLoop's dedup on the status code alone via errors.As —
		// msg is the server's response body, which routinely carries a
		// fresh request id or timestamp that would otherwise re-arm a WARN
		// every single retry.
		//
		// The push cursor is NOT advanced on this path (only the 200 branch
		// saves it), so every row of this batch stays unpushed in the node's
		// store and is re-sent on the next cycle; a 503 log_full / 429 never
		// marks anything pushed (T-823).
		err := &httpStatusError{op: "orgclient.PushOnce", status: resp.StatusCode(), body: msg}
		if resp.HTTPResponse != nil {
			err.retryAfter = parseRetryAfter(resp.HTTPResponse.Header.Get("Retry-After"), time.Now())
		}
		return PushResult{}, err
	}
}

// errIdle signals that a cycle did no work because the agent is not enrolled
// (or the enrolment row could not be read). The loop keeps its normal interval
// cadence rather than backing off — there is nothing failing, only nothing to
// do — so an enrol on a running daemon is picked up within one interval.
var errIdle = errors.New("orgclient: idle cycle")

// pushCycleState is the per-PushLoop failure-dedup state one cycle threads to
// the next: one failureDeduper PER independent failure stream, so a routing
// fetch recovering cannot re-arm the announcement fetch's WARN and vice versa.
// A fresh set per PushLoop invocation (same lifetime as the loop).
type pushCycleState struct {
	enrolRead, routing, announcement, displayPolicy, accessGrants, requestOutbox, agentConfig, messages failureDeduper
}

// cycleKind is what one push-loop cycle does (pushsched.Decision, restated so
// the scheduler's type does not thread through the cycle). The zero value is
// a LIGHT cycle: the upload alone.
type cycleKind struct {
	// rails refreshes the governance rails (the ceiling cycle).
	rails bool
	// railsOnly skips the upload: a ceiling inside the org's push
	// backpressure window still refreshes the rails on time (Sol A5-06).
	// Meaningful only with rails.
	railsOnly bool
}

// pushCycle is ONE push-loop cycle: enrolment read, the budget + pricing rails,
// the push, then the remaining governance rails. It is the loop's body, split
// out so a test can drive exactly one cycle and read the envelope it produced.
// The ORDER is the contract - see the comment above refreshBudgetRails.
func (c *Client) pushCycle(ctx context.Context, state *pushCycleState, kind cycleKind) (PushResult, error) {
	rails := kind.rails
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		warnOnce(c.logger, &state.enrolRead, err, "org push: enrolment read failed")
		return PushResult{}, errIdle
	}
	state.enrolRead.observe("")
	if enr == nil {
		// Not enrolled (yet, or unenrolled while running). The budget sink is
		// still told so (T-718): an `observer unenroll` in ANOTHER process
		// cleared the store, but this daemon's composed budget, and with it a
		// fail-closed B-625, lived on in memory until a restart because the
		// sink only ever heard from a cycle that reached the rails.
		c.railsMu.Lock()
		c.retireBudgetRail()
		c.railsMu.Unlock()
		return PushResult{}, errIdle
	}
	// The budget + pricing rails run BEFORE the push, not after it
	// (demo-estate finding 2026-09-20): the envelope carries the node's
	// budget POSTURE, composed at push time from the LAST fetch outcome,
	// so a cycle that pushed first shipped the previous cycle's state -
	// and on the first cycle after a restart that was the primed
	// `unreachable` posture, one second before the fetch succeeded. The
	// org then read `budget_required` over a node whose proxy was passing
	// requests until the next interval. See refreshBudgetRails.
	//
	// A LIGHT cycle (rails=false, the activity-driven push of P3) skips
	// every rail: it ships rows and nothing else. Its ack still records the
	// rail versions, and any rail it reports moved is queued for the
	// policy-freshness checker (recordRailVersions) because cycleRails is
	// false.
	if rails {
		c.refreshBudgetRails(ctx)
		c.pollManagedPullRails(ctx)
	}
	// A RAIL-ONLY cycle (Sol A5-06) skips the upload: the org asked this
	// node to space its pushes, and the rails below are pulls the hint does
	// not govern. Rows stay pending for the next upload cycle.
	// err is nil here (the enrolment read above returned on failure), so a
	// rail-only cycle reports success: every rail below is fail-open.
	var res PushResult
	if !kind.railsOnly || !rails {
		res, err = c.uploadForCycle(ctx, rails)
		if errors.Is(err, errIdle) {
			return PushResult{}, errIdle
		}
	}
	if !rails {
		// The update nudge is ack-driven and fetches nothing unless the
		// ack named a newer manifest, so it rides light cycles too.
		c.FetchPendingUpdateManifests(ctx)
		// A light push the org accepted proves it is back: a message rail
		// left stalled by the outage retries now instead of waiting for
		// the next rail cycle (T-854). A rail cycle syncs it below anyway.
		if err == nil {
			c.retryStalledOrgMessages(ctx)
		}
		return res, err
	}
	// Best-effort §R19.1 policy sync rides the same cycle: a fetch
	// failure never affects push health (P1 - the policy cache
	// just stays at its last verified version).
	c.railsMu.Lock()
	_, routingOutcome, perr := c.FetchRoutingPolicy(ctx)
	c.railsMu.Unlock()
	// Forward the TOTAL typed outcome (§2.5b) to the P0-6 reporter. A nil
	// outcome is a skip (context.Canceled - a shutdown, not a verdict); a
	// nil sink (the default) is today's exact no-op (R6-1).
	if routingOutcome != nil && c.routingOutcomeSink != nil {
		c.routingOutcomeSink(*routingOutcome)
	}
	switch {
	case perr != nil && !errors.Is(perr, ErrNotEnrolled):
		warnOnce(c.logger, &state.routing, perr,
			"org routing policy fetch failed - if this persists, check the org server, or run `observer unenroll` / set [org_client].enabled = false to stop trying")
	default:
		state.routing.observe("")
	}
	// The org-served Cloud Intelligence RESULT rail (org-served-cloud-
	// intelligence plan §2.4, W3) rides the SAME cycle for the same reason:
	// no new timer, no new host, no new connection. It is a PULL (the org's
	// derived results coming back), gated internally by
	// [intelligence].org_enrichment - a node that has not opted in makes no
	// request at all, so this call is inert on every individual/unopted
	// node. Every failure is FAIL-OPEN: the node keeps its cached results.
	// Cloud Intelligence parity (design section 3.7): the requirement
	// document, the T-155d sweep and the node's consent report ride the same
	// cycle, before the result pull so a swept cache is never re-filled under
	// a consent that no longer covers it.
	c.runIntelConsentCycle(ctx)
	// Parity phase 2: queue and send node-built org-plane evidence (B1).
	// The background source is gated in cmd/observer by the same rail gate
	// and consent as the result pull; developer-queued rows are sent here.
	c.runIntelSubmitCycle(ctx)
	intelOutcome, ierr := c.FetchIntelResults(ctx)
	if ierr != nil && !errors.Is(ierr, ErrNotEnrolled) && !errors.Is(ierr, context.Canceled) {
		c.logRailFetchFailure(intelOutcome.State,
			"org intelligence distribution channel off or not offered",
			"org intelligence results fetch failed", ierr)
	}
	// Rail R3 of the dashboard-announcements plan (§4) rides the
	// SAME cycle for the same reason: no new timer, no new host, no
	// new connection - and a fetch failure never affects push
	// health (P1), it just leaves the banner at its last verified
	// version.
	c.railsMu.Lock()
	_, aerr := c.FetchOrgAnnouncement(ctx)
	c.railsMu.Unlock()
	switch {
	case aerr != nil && !errors.Is(aerr, ErrNotEnrolled):
		warnOnce(c.logger, &state.announcement, aerr,
			"org announcement fetch failed - if this persists, check the org server, or run `observer unenroll` / set [org_client].enabled = false to stop trying")
	default:
		state.announcement.observe("")
	}
	// The developer cost-display rail (operator ruling 2026-10-02) rides the
	// SAME cycle for the same reasons as the announcement above, and fails
	// the same way: a fetch failure never affects push health, it leaves the
	// dashboard on the last verified value (dollars when nothing was ever
	// verified).
	// The policy-freshness checker refreshes it between cycles through the
	// same helper (railFetchers, RailDisplay).
	_, derr := c.refreshDisplayPolicy(ctx)
	switch {
	case derr != nil && !errors.Is(derr, ErrNotEnrolled):
		warnOnce(c.logger, &state.displayPolicy, derr,
			"org display policy fetch failed - developer dashboards keep the last verified cost display; if this persists, check the org server")
	default:
		state.displayPolicy.observe("")
	}
	// The access-grant rail (request-grants design §3.1) rides the SAME cycle
	// for the same reasons, and fails the same way: a fetch failure keeps the
	// last verified grants (each still bounded by its own expiry and the
	// org's offline window) and never affects push health. Requests the
	// developer raised while the org was unreachable go out here too.
	if _, gerr := c.refreshAccessGrants(ctx); gerr != nil && !errors.Is(gerr, ErrNotEnrolled) {
		warnOnce(c.logger, &state.accessGrants, gerr,
			"org access grants fetch failed - the node keeps its last verified grants until they expire or go stale; if this persists, check the org server")
	} else {
		state.accessGrants.observe("")
	}
	if _, oerr := c.FlushAccessRequestOutbox(ctx); oerr != nil {
		warnOnce(c.logger, &state.requestOutbox, oerr, "queued access requests could not be sent yet - they stay queued for the next cycle")
	} else {
		state.requestOutbox.observe("")
	}
	// Admin and developer messaging (T-854) rides the SAME cycle for the
	// same reasons: the outbox (replies, new threads, read and acknowledge
	// receipts) goes first, then the signed per-caller pull, paged until the
	// org says there is no more. A failure never affects push health and
	// never deletes a held message.
	c.syncOrgMessagesInCycle(ctx, &state.messages)
	// The org AI tool policy rail (adapter config P6) rides the SAME cycle
	// and fails the same way: a failure never affects push health and leaves
	// the last verified policy in force. Gated to managed nodes with a live
	// grant (no request at all otherwise). The freshness checker refreshes it
	// between cycles through the same helper (railFetchers,
	// RailAgentConfig).
	_, acerr := c.refreshAgentConfigPolicy(ctx)
	switch {
	case acerr != nil && !errors.Is(acerr, ErrNotEnrolled):
		warnOnce(c.logger, &state.agentConfig, acerr,
			"org AI tool policy fetch failed - the last verified policy stays in force; if this persists, check the org server")
	default:
		state.agentConfig.observe("")
	}
	// Arc 4 P6b managed-integrity probe rides the SAME cycle (plan §9,
	// announce.go discipline: no new timer/host/connection). MANAGED nodes
	// only - an individual node never computes a fingerprint or a signal, so
	// the individual plane is untouched by construction. A report failure
	// never affects push health (P1).
	// Enterprise Update Management (§3.5) rides the SAME cycle, for the
	// same reason as rail R3 above: no new timer, no new host, no new
	// connection. It fetches ONLY the channels the push acknowledgment
	// just said the server is ahead on, so a fleet with nothing published
	// makes no extra request at all. A fetch failure never affects push
	// health - it leaves the update card at its last verified manifest.
	c.FetchPendingUpdateManifests(ctx)
	// Managed nodes only (ReportManagedIntegrity gates itself on
	// IsManagedEnrolment: a managed enrolment, or a node its org switched to
	// enterprise, P-205).
	c.ReportManagedIntegrity(ctx)
	return res, err
}

// uploadForCycle is the upload half of a push cycle: PushOnce plus the
// oversized-batch bookkeeping. A not-enrolled node maps to errIdle.
func (c *Client) uploadForCycle(ctx context.Context, rails bool) (PushResult, error) {
	// A rail cycle refreshes every push-cycle rail itself, so its own ack
	// must not queue them again (policyfreshness.go recordRailVersions).
	c.cycleRails.Store(rails)
	defer c.cycleRails.Store(false)
	res, err := c.PushOnce(ctx)
	if errors.Is(err, ErrNotEnrolled) {
		return PushResult{}, errIdle
	}
	// Oversized-batch circuit bookkeeping lives HERE, not in runLoop's
	// timing switch: runLoop is shared with the policy-poll loops, and a
	// poll succeeding while the push is parked must not close the push
	// circuit. This is the one owner of that state.
	switch {
	case errors.Is(err, ErrBatchTooLarge):
		c.noteOversizedBatch(ctx, err)
	case err == nil:
		if cerr := c.store.ClearPushBreaker(ctx); cerr != nil {
			c.logger.Warn("org push: could not clear the oversized-batch pause record", "err", cerr)
		}
	}
	return res, err
}

// refreshBudgetRails polls the org BUDGET rail and, beside it, the org
// PRICING rail. It is called by every push cycle immediately BEFORE PushOnce,
// and by PushNow, so the posture the envelope carries (composed through the
// store's BudgetPostureProvider at SELECT time) describes the fetch this
// cycle just made rather than the one before it.
//
// The org BUDGET rail (org-budget plan §3.3c) rides the push cycle for the
// same reason as routing: no new timer, no new host, no new connection. It is
// a conditional GET (If-None-Match over the document digest, not the version
// - a team-membership change moves a cap without moving the version), so the
// steady state is a 304. Every failure is FAIL-OPEN: the sink is poked with
// the typed state and the guard keeps the node's own [guard.budget] numbers.
//
// The org PRICING rail (enterprise-pricing plan §3.3) rides the SAME cycle,
// immediately after the budget rail and for the same reasons. It is polled
// BESIDE the budget rather than on its own schedule because the two are one
// governance fact: a cap and the rate it is measured in. A node that
// refreshed one without the other would spend the gap enforcing this
// quarter's cap against last quarter's prices. Ruling R2 gates both on the
// same [guard.budget].from_org switch, and a disabled rail makes no request
// at all.
//
// The pricing SINK is notified by FetchPricingPolicy itself, not here - the
// one place this rail's wiring diverges from the budget rail's, and
// deliberately. The pricing sink must also fire on the COLD-START path
// (LoadPersistedPricing, minutes before the first poll), and a caller that
// owned the notification would leave that path silently un-notified: the
// engine would hold the persisted rates while the posture said nothing had
// been applied.
func (c *Client) refreshBudgetRails(ctx context.Context) {
	c.railsMu.Lock()
	defer c.railsMu.Unlock()
	budgetOutcome, berr := c.FetchBudgetPolicy(ctx)
	// The cadence the push loop is actually ticking at rides with every
	// outcome (bundle BUD-N): the composition boundary derives the
	// cross-machine baseline's staleness window from it, and the client is
	// the one place that resolves it.
	budgetOutcome.PushInterval = c.pushInterval()
	if c.budgetSink != nil && !errors.Is(berr, context.Canceled) {
		c.budgetSink(budgetOutcome)
	}
	if berr != nil && !errors.Is(berr, ErrNotEnrolled) && !errors.Is(berr, context.Canceled) {
		c.logRailFetchFailure(budgetOutcome.State,
			"org budget distribution channel off or not offered",
			"org budget policy fetch failed", berr)
	}
	pricingOutcome, prerr := c.FetchPricingPolicy(ctx)
	if prerr != nil && !errors.Is(prerr, ErrNotEnrolled) && !errors.Is(prerr, context.Canceled) {
		c.logRailFetchFailure(pricingOutcome.State,
			"org pricing distribution channel off or not offered",
			"org pricing policy fetch failed", prerr)
	}
}

// retireBudgetRail tells the budget sink that no enrolment exists, so the
// boundary recomposes onto the node's own numbers and drops every org-derived
// cap, protection and the fail-closed posture (T-718). It also drops this
// client's in-memory copy of the last verified body. Idempotent and cheap: the
// boundary's apply is a no-op when nothing changed.
func (c *Client) retireBudgetRail() {
	c.budget.clear()
	if c.budgetSink == nil {
		return
	}
	c.budgetSink(BudgetFetchOutcome{State: orgcontract.BudgetFetchNotEnrolled, PushInterval: c.pushInterval()})
}

// RetireIdentity is the in-process half of a leave (T-718): after Unenroll ran
// in this process OR another, the daemon calls it so the org budget rail
// recomposes at once rather than at the next push cycle. Safe on an enrolled
// node: it only acts when the store holds no enrolment.
func (c *Client) RetireIdentity(ctx context.Context) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil || enr != nil {
		return
	}
	c.railsMu.Lock()
	defer c.railsMu.Unlock()
	c.retireBudgetRail()
}

// PushNow runs ONE push exactly the way a loop cycle does: the budget and
// pricing rails are refreshed first, then the envelope is built and shipped.
// It is what `observer org push-now` calls, so an operator-triggered push
// carries the node's CURRENT budget posture rather than whatever the process
// last composed - a CLI process, which has made no fetch of its own, would
// otherwise push a posture from its cold cache (demo-estate finding
// 2026-09-20).
//
// It returns ErrNotEnrolled without touching either rail when the node is not
// enrolled, so the sinks never see a not_enrolled outcome the loop would not
// have produced either. PushOnce alone remains the bare envelope push for
// callers that own their own rail cadence.
func (c *Client) PushNow(ctx context.Context) (PushResult, error) {
	enr, err := c.store.LoadEnrolment(ctx)
	if err != nil {
		return PushResult{}, fmt.Errorf("orgclient.PushNow: %w", err)
	}
	if enr == nil {
		return PushResult{}, ErrNotEnrolled
	}
	c.refreshBudgetRails(ctx)
	return c.PushOnce(ctx)
}

// noteOversizedBatch is the ONE owner of the ErrBatchTooLarge circuit state. It
// does the two things a silent park does not: it says out loud, at Error level,
// that org telemetry has STOPPED and for how long, and it persists the pause so
// the dashboard and `observer org push-status` — which run in other processes —
// can show it instead of the operator having to read org_push_log by hand.
//
// Persisting is best-effort: failing to write the record must never escalate a
// parked push into a broken daemon (P1).
func (c *Client) noteOversizedBatch(ctx context.Context, err error) {
	until := time.Now().UTC().Add(oversizedBatchBackoff)
	c.logger.Error("org push PAUSED - the composed rollup is larger than the accepted push limit, "+
		"so NOTHING is reaching the org server until this clears",
		"err", err,
		"paused_for", oversizedBatchBackoff.String(),
		"resumes_at", until.Format(time.RFC3339),
		"what_to_check", "raise [org_client].max_push_bytes, narrow [org_client.scope] to fewer "+
			"projects, or turn off a large [org_client.share] tier - the org server also enforces "+
			"its own body limit, so a node-side raise alone may not be enough")
	if serr := c.store.OpenPushBreaker(ctx, until, err.Error()); serr != nil {
		c.logger.Warn("org push: could not record the oversized-batch pause for the dashboard", "err", serr)
	}
}

// pushRecomposeAttempts bounds how often one push cycle recomposes an
// envelope that serialized over the limit; pushRecomposeMargin is the extra
// headroom each recompose takes below the overshoot.
const (
	pushRecomposeAttempts = 3
	pushRecomposeMargin   = 32 << 10
)

// recomposeToFit returns batch, env and raw unchanged when raw fits the push
// limit. The store's budget is an estimate; the serialized envelope is the
// truth. When it is over the limit, recompose against a budget lowered by
// the overshoot (plus a margin) rather than park the loop on an envelope
// that would be refused again on every cycle. Recomposing is safe: every
// compose starts fresh (snapshot staging, section digests), and nothing
// is committed until an accepted push.
func (c *Client) recomposeToFit(ctx context.Context, cur store.PushCursor, enr *store.Enrolment,
	batch store.PushBatch, env orgcontract.PushEnvelope, raw []byte,
) (store.PushBatch, orgcontract.PushEnvelope, []byte, error) {
	for budget, attempt := c.maxPushBytes(), 0; int64(len(raw)) > c.maxPushBytes() && attempt < pushRecomposeAttempts; attempt++ {
		budget -= int64(len(raw)) - c.maxPushBytes() + pushRecomposeMargin
		if budget < c.maxPushBytes()/4 {
			break
		}
		c.logger.Warn("org push: the composed envelope is over the push limit; recomposing with a smaller budget",
			"serialized_bytes", len(raw), "limit_bytes", c.maxPushBytes(), "budget_bytes", budget)
		next, err := c.selectBatch(ctx, cur, budget, enr)
		if err != nil {
			return batch, env, raw, fmt.Errorf("orgclient.PushOnce: reselect: %w", err)
		}
		nextEnv := EnvelopeFromBatch(next, cur, EnvelopeMeta{
			AgentVersion: c.agentVersion, MachineIdentity: env.MachineIdentity,
			SourceNodeKey: env.SourceNodeKey, PushInterval: c.pushInterval(),
		})
		nextRaw, err := json.Marshal(nextEnv)
		if err != nil {
			_ = c.store.RecordPush(ctx, int64(next.RowCount()), 0, "failed", err.Error())
			return batch, env, raw, fmt.Errorf("orgclient.PushOnce: marshal: %w", err)
		}
		batch, env, raw = next, nextEnv, nextRaw
	}
	return batch, env, raw, nil
}

// selectBatch composes the next push batch from cur within maxBytes, under
// this node's share and scope options.
func (c *Client) selectBatch(ctx context.Context, cur store.PushCursor, maxBytes int64, enr *store.Enrolment) (store.PushBatch, error) {
	return c.store.SelectUnpushedSince(
		ctx, cur, maxBytes, enr.OrgID, enr.UserEmail,
		c.shareOptions(),
		c.scopeOptions(),
	)
}

// maxPushBytes returns the configured uncompressed batch ceiling, defaulted and
// clamped to the contract bounds.
func (c *Client) maxPushBytes() int64 {
	mb := c.cfg.MaxPushBytes
	if mb <= 0 {
		mb = config.DefaultMaxPushBytes
	}
	if mb > config.MaxPushBytesCeiling {
		mb = config.MaxPushBytesCeiling
	}
	return mb
}

func validatePushBodySize(raw []byte, maxBytes int64) error {
	if maxBytes <= 0 {
		return nil
	}
	if int64(len(raw)) > maxBytes {
		return fmt.Errorf("%w: serialized_bytes=%d limit_bytes=%d", ErrBatchTooLarge, len(raw), maxBytes)
	}
	return nil
}
