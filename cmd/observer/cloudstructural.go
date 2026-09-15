package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudstructural.go is the STRUCTURAL-INSIGHTS rail inside `observer cloud
// sync` (divergence-remediation plan rev 4.1 §3 W2 "Node half"): capture the
// completed day windows a standing grant authorizes, then drain them in revision
// order through the consent-gated egress seam.
//
// It composes, and invents nothing: the aggregate SQL is the store's
// (LoadStructuralDayFacts), the snapshot is the pure builder's
// (BuildStructuralSnapshot + SerializeStructural), the persistence is the
// store's atomic revision-allocating enqueue, and every send goes through
// internal/cloudgateway.

const (
	// cloudStructuralSourceWindowRule is the versioned identifier of WHICH
	// activity a standing grant covers, recorded on the receipt so the developer
	// agreed to a stated rule rather than to whatever the code happens to do.
	// v1: completed calendar days in the declared timezone, trailing 30.
	cloudStructuralSourceWindowRule = "completed_utc_days_trailing_30"
	// cloudStructuralSourceWindowDays is the trailing window that rule spans.
	cloudStructuralSourceWindowDays = 30
	// cloudStructuralLateDataNote is printed whenever the rail runs. Capture is
	// ONCE per window in this release; the N+1 late-data revision path has store
	// and contract support already but is exercised by the background service.
	// Saying so is the honest-disabled-copy discipline applied to a limitation.
	cloudStructuralLateDataNote = "  (each window is captured once; revision re-capture on late data arrives with the background service)"
)

// cloudSyncStructural runs the whole rail and reports it. It never returns an
// error: a structural problem is reported and stepped over, because it must not
// cost the developer their session-evidence sync.
func cloudSyncStructural(ctx context.Context, st *store.Store, gw *cloudgateway.Gateway, now time.Time, w io.Writer) {
	grant, err := gw.ResolveStandingGrant(ctx, cloudcontract.PurposeStructuralInsights)
	if err != nil {
		if errors.Is(err, cloudgateway.ErrNoLiveGrant) || errors.Is(err, cloudgateway.ErrNoConsentSource) {
			fmt.Fprintln(w, "Structural: skipped — no standing grant, so no window was captured and nothing was sent.")
			fmt.Fprintln(w, "  Grant one with `observer cloud consent grant --purpose structural_activity_insights`.")
			return
		}
		fmt.Fprintf(w, "Structural: skipped — could not resolve the standing grant: %v\n", err)
		return
	}

	captured, cerr := cloudCaptureStructuralWindows(ctx, st, grant, now)
	if cerr != nil {
		fmt.Fprintf(w, "Structural: capture incomplete: %v\n", cerr)
	}
	if captured == 0 && !cloudGrantHasCompletedDay(grant, now) {
		// The day-one cliff, stated rather than left mysterious: the rule the
		// receipt bound covers COMPLETED days at or after the grant, and a grant
		// made today has none yet.
		fmt.Fprintln(w, "Structural: no window yet — the grant covers completed days from the day it was")
		fmt.Fprintln(w, "  made, and today is still in progress. The first window is captured tomorrow.")
	}
	sent, retryable, failed, derr := cloudDrainStructural(ctx, st, gw, w)
	if derr != nil {
		fmt.Fprintf(w, "Structural: drain incomplete: %v\n", derr)
	}
	fmt.Fprintf(w, "Structural: %d window(s) captured, %d sent, %d retryable, %d failed.\n",
		captured, sent, retryable, failed)
	fmt.Fprintln(w, cloudStructuralLateDataNote)
}

// cloudCaptureStructuralWindows snapshots every capture-eligible window.
//
// ELIGIBILITY (source-window rule v1, exactly what the receipt bound):
//
//   - COMPLETED days only — the current day in the declared timezone is still
//     accumulating, and snapshotting it would produce a window whose content
//     changes after it was digested;
//   - within the trailing 30 completed days;
//   - not before the day the grant was created — a standing grant authorizes
//     future windows, never history the developer had not agreed to share when
//     they granted it;
//   - with no cloud_structural_windows row yet. Each window is captured ONCE in
//     this release (see cloudStructuralLateDataNote).
//
// Day boundaries come from the grant's DECLARED timezone, not the host's: a
// device that travels must not re-bucket its history. The period is stored as
// that day's date string, and the aggregate SQL is handed the corresponding UTC
// instants.
//
// An INACTIVE window (no personal-eligible session started in it) is not
// captured. There is nothing to report, the snapshot would be an all-zero row,
// and skipping it means a first sync on a fresh install sends nothing rather
// than thirty empty uploads. The cost is stated and small: if late data later
// lands in such a day, it is captured then as revision 1.
func cloudCaptureStructuralWindows(ctx context.Context, st *store.Store, grant cloudgateway.Grant, now time.Time) (int, error) {
	loc, err := time.LoadLocation(grant.DeclaredTimezone)
	if err != nil {
		return 0, fmt.Errorf("the grant declares timezone %q, which this host cannot load (%w) — "+
			"re-grant with `observer cloud consent grant --purpose %s --timezone <IANA zone>`",
			grant.DeclaredTimezone, err, cloudcontract.PurposeStructuralInsights)
	}

	today := cloudLocalDay(now, loc)
	last := today.AddDate(0, 0, -1) // the newest COMPLETED day
	first := last.AddDate(0, 0, -(cloudStructuralSourceWindowDays - 1))
	if grantDay := cloudLocalDay(grant.CreatedAt, loc); first.Before(grantDay) {
		first = grantDay
	}
	if last.Before(first) {
		return 0, nil // the grant is younger than one completed day
	}

	captured, err := st.ListCapturedStructuralPeriods(ctx,
		cloudevidence.StructuralPeriodRuleV1, cloudcontract.StructuralSnapshotSchemaVersion)
	if err != nil {
		return 0, err
	}

	var n int
	for day := first; !day.After(last); day = day.AddDate(0, 0, 1) {
		period := day.Format(cloudcontract.StructuralPeriodLayout)
		if _, done := captured[period]; done {
			continue
		}
		dayEnd := day.AddDate(0, 0, 1)
		facts, err := st.LoadStructuralDayFacts(ctx,
			day.UTC().Format(time.RFC3339), dayEnd.UTC().Format(time.RFC3339))
		if err != nil {
			return n, fmt.Errorf("aggregate %s: %w", period, err)
		}
		if facts.SessionCount == 0 {
			continue
		}
		if _, _, err := st.EnqueueStructuralOutbox(ctx, store.StructuralWindowKey{
			Period:            period,
			PeriodRuleVersion: cloudevidence.StructuralPeriodRuleV1,
			SchemaVersion:     cloudcontract.StructuralSnapshotSchemaVersion,
		}, grant.ReceiptID, cloudStructuralPayloadBuild(period, grant.DeclaredTimezone, facts)); err != nil {
			return n, fmt.Errorf("capture %s: %w", period, err)
		}
		n++
	}
	return n, nil
}

// cloudStructuralPayloadBuild returns the store's injected build seam: PURE
// marshal-and-hash, called inside the enqueue transaction once the revision is
// allocated (the revision is part of what is digested, so the bytes cannot be
// built before it is known). It touches no store and does no I/O.
func cloudStructuralPayloadBuild(period, declaredTimezone string, facts store.StructuralDayFacts) store.StructuralPayloadBuild {
	return func(revision int) ([]byte, string, error) {
		snap, err := cloudevidence.BuildStructuralSnapshot(cloudevidence.StructuralDayInput{
			Period:                   period,
			Revision:                 revision,
			SourceWatermark:          cloudStructuralWatermark(facts.SourceWatermark),
			SessionCount:             facts.SessionCount,
			ActionCount:              facts.ActionCount,
			ToolMix:                  cloudStructuralMix(facts.ToolMix),
			ModelFamilyMix:           cloudStructuralMix(facts.ModelFamilyMix),
			TokensIn:                 facts.TokensIn,
			TokensOut:                facts.TokensOut,
			CacheReadTokens:          facts.CacheReadTokens,
			CostUSD:                  facts.CostUSD,
			SessionsWithOutcomes:     facts.SessionsWithOutcomes,
			SessionsWithVerification: facts.SessionsWithVerification,
		}, cloudevidence.StructuralBuildOptions{DeclaredTimezone: declaredTimezone})
		if err != nil {
			return nil, "", err
		}
		return cloudevidence.SerializeStructural(snap)
	}
}

// cloudStructuralMix maps store mix counts to builder inputs. The builder
// normalizes, merges and sorts, so this is a pure shape change.
func cloudStructuralMix(in []store.StructuralMixCount) []cloudevidence.StructuralMixInput {
	if len(in) == 0 {
		return nil
	}
	out := make([]cloudevidence.StructuralMixInput, 0, len(in))
	for _, m := range in {
		out = append(out, cloudevidence.StructuralMixInput{Key: m.Key, Count: m.Count})
	}
	return out
}

// cloudStructuralWatermark renders the max included event time as RFC3339, or ""
// for a window with none (which only an inactive window has, and those are not
// captured).
func cloudStructuralWatermark(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// cloudGrantHasCompletedDay reports whether at least one COMPLETED day exists at
// or after the grant's creation day. It is false only on the grant's own day —
// the one situation in which "0 windows captured" is the rule working rather
// than something being wrong.
func cloudGrantHasCompletedDay(grant cloudgateway.Grant, now time.Time) bool {
	loc, err := time.LoadLocation(grant.DeclaredTimezone)
	if err != nil {
		return true // an unloadable zone is reported by the capture path itself
	}
	lastCompleted := cloudLocalDay(now, loc).AddDate(0, 0, -1)
	return !lastCompleted.Before(cloudLocalDay(grant.CreatedAt, loc))
}

// cloudLocalDay truncates an instant to midnight of its calendar day in loc.
func cloudLocalDay(t time.Time, loc *time.Location) time.Time {
	local := t.In(loc)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
}

// cloudDrainStructural sends the queued snapshots in revision order. Each send
// goes through the gateway's STANDING lane, so a grant revoked between capture
// and drain stops the upload before any request is made; and each item carries a
// PreAttempt re-check, so a grant revoked DURING the drain stops it too.
func cloudDrainStructural(ctx context.Context, st *store.Store, gw *cloudgateway.Gateway, w io.Writer) (sent, retryable, failed int, err error) {
	items, err := st.ListSendableStructuralOutbox(ctx)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("list structural outbox: %w", err)
	}
	for _, it := range items {
		serr := gw.StandingSend(ctx, cloudcontract.PurposeStructuralInsights, func(sess cloudgateway.StructuralSession) error {
			return cloudSendStructuralOne(ctx, st, sess, it, w)
		})
		switch {
		case serr == nil:
			sent++
		case errors.Is(serr, cloudgateway.ErrNoLiveGrant), errors.Is(serr, cloudgateway.ErrGrantRevoked),
			errors.Is(serr, store.ErrCloudStructuralSendUnauthorized):
			fmt.Fprintf(w, "  window %s: NOT SENT — the standing grant is no longer live; nothing left this machine\n", it.ID)
			failed++
		case errors.Is(serr, errCloudStructuralRetryable):
			retryable++
		default:
			failed++
		}
	}
	return sent, retryable, failed, nil
}

// errCloudStructuralRetryable classifies a send whose row was left retryable, so
// the caller can count it apart from a terminal failure.
var errCloudStructuralRetryable = errors.New("structural upload failed retryably")

// cloudSendStructuralOne prepares and uploads ONE snapshot window. Prepare
// replays the STORED bytes — it never re-aggregates — and re-checks the standing
// grant, the grant's terms, its review date, and the endpoint binding inside one
// transaction before releasing them.
//
// It deliberately takes NO resolved Grant. Everything the wire declares about
// consent comes from the lease, i.e. from the receipt THIS item is bound to, read
// under the transaction that authorized it. Reading "the newest grant for the
// purpose" instead would let a snapshot queued under older terms ship claiming
// newer ones the moment two live standing receipts coexisted.
func cloudSendStructuralOne(ctx context.Context, st *store.Store, sess cloudgateway.StructuralSession, it store.CloudOutboxItem, w io.Writer) error {
	payload, lease, err := st.PrepareStructuralSend(ctx, it.ID, sess.StructuralEndpoint())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrCloudEndpointMismatch):
			fmt.Fprintf(w, "  window %s: NEEDS RECONFIRMATION — the sync endpoint is not the one the grant bound\n", it.ID)
		case errors.Is(err, store.ErrCloudGrantGenerationDrift):
			fmt.Fprintf(w, "  window %s: NEEDS RECONFIRMATION — the grant's terms changed after this snapshot was queued\n", it.ID)
		case errors.Is(err, store.ErrCloudGrantExpired):
			fmt.Fprintf(w, "  window %s: NEEDS RECONFIRMATION — the standing grant's review date has passed; re-grant with\n", it.ID)
			fmt.Fprintf(w, "    `observer cloud consent grant --purpose %s`\n", cloudcontract.PurposeStructuralInsights)
		case errors.Is(err, store.ErrCloudReconfirmationRequired), errors.Is(err, store.ErrCloudGrantNotStanding):
			fmt.Fprintf(w, "  window %s: NEEDS RECONFIRMATION — the standing grant no longer authorizes it (%v)\n", it.ID, err)
		}
		return err
	}

	window, ok, werr := st.GetStructuralWindow(ctx, it.ID)
	if werr != nil {
		_ = st.MarkCloudOutboxRetryable(ctx, it.ID, "window_read_error")
		return fmt.Errorf("%w: %w", errCloudStructuralRetryable, werr)
	}
	if !ok {
		_ = st.MarkCloudOutboxTerminal(ctx, it.ID, "window_row_missing")
		return fmt.Errorf("structural item %s has no window row", it.ID)
	}

	// The standing-grant binding the server validates against comes from the
	// LEASE — the receipt PrepareStructuralSend just re-checked inside its
	// transaction (endpoint, grant mode, review date and generation drift all
	// refused above) — so what is declared on the wire is exactly what these
	// exact bytes were validated against.
	resp, upErr := sess.UploadStructural(ctx, cloudgateway.StructuralUploadRequest{
		Payload:              payload,
		Period:               window.Key.Period,
		PeriodRuleVersion:    window.Key.PeriodRuleVersion,
		SchemaVersion:        window.Key.SchemaVersion,
		Revision:             window.Revision,
		Digest:               lease.UploadDigest,
		ConsentGeneration:    lease.ConsentGeneration,
		DataDictionaryDigest: lease.DataDictionaryDigest,
		SourceWindowRule:     lease.SourceWindowRule,
		// The per-item authorization re-check, run immediately before EVERY
		// physical POST and before every retry. Without it a `consent revoke`
		// issued mid-drain — which moves this row out of `sending` — would be
		// invisible to a send already past the gateway's one-shot grant check.
		PreAttempt: func() error { return st.VerifyStructuralSendAuthorization(ctx, lease) },
		// The cross-process dispatch lease (Sol re-review N2), keyed to the
		// exact receipt + generation the lease above was validated against.
		DispatchLease: cloudDispatchLeaseFor(st, lease.ReceiptID, cloudcontract.PurposeStructuralInsights, lease.ConsentGeneration),
	})
	if upErr != nil {
		class := cloudStructuralErrClass(upErr)
		if cloudStructuralTerminal(upErr) {
			_ = st.MarkCloudOutboxTerminal(ctx, it.ID, class)
			fmt.Fprintf(w, "  window %s (%s r%d): FAILED (terminal, %s): %v\n",
				it.ID, window.Key.Period, window.Revision, class, upErr)
			return upErr
		}
		_ = st.MarkCloudOutboxRetryable(ctx, it.ID, class)
		fmt.Fprintf(w, "  window %s (%s r%d): failed (retryable, %s): %v\n",
			it.ID, window.Key.Period, window.Revision, class, upErr)
		return fmt.Errorf("%w: %w", errCloudStructuralRetryable, upErr)
	}
	if err := st.MarkCloudOutboxSent(ctx, it.ID); err != nil {
		return err
	}
	ack := resp.SnapshotID
	if resp.Replay {
		ack += " (replay-ack)"
	}
	fmt.Fprintf(w, "  window %s (%s r%d): sent %s\n", it.ID, window.Key.Period, window.Revision, ack)
	return nil
}

// cloudStructuralTerminal classifies a structural upload failure.
//
// It deliberately differs from cloudUploadTerminal on TWO statuses. The W2
// server route may not exist yet, so a 404 (no such route) or a 501 (not
// implemented) is ROUTE ABSENCE, not a rejection of this snapshot — burning the
// window terminally would silently lose a day of a developer's history for a
// reason that fixes itself when the server ships. A 405 is treated the same way,
// since a partially-deployed route answers method-not-allowed. Everything else
// keeps the ordinary rule: 4xx (except 429) is terminal, transport and 5xx are
// retryable.
func cloudStructuralTerminal(err error) bool {
	if errors.Is(err, cloudgateway.ErrSignInExpired) {
		return false // credential state, not a rejection of the window
	}
	status, ok := cloudgateway.HTTPStatus(err)
	if !ok {
		return false // transport error
	}
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented, http.StatusTooManyRequests:
		return false
	}
	return status >= 400 && status < 500
}

// cloudStructuralErrClass returns the content-free error class recorded on the
// row. Route absence gets its own class so an operator reading `last_error` can
// tell "the server has not shipped this route yet" from "the server rejected my
// snapshot".
func cloudStructuralErrClass(err error) string {
	if errors.Is(err, cloudgateway.ErrSignInExpired) {
		return cloudErrClassSignInExpired
	}
	status, ok := cloudgateway.HTTPStatus(err)
	if !ok {
		return "transport"
	}
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return fmt.Sprintf("route_absent_http_%d", status)
	}
	return fmt.Sprintf("http_%d", status)
}
