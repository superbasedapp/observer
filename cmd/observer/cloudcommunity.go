package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudevidence"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudcommunity.go is the W5 contribution-upload leg of `observer cloud sync`
// (divergence-remediation plan §3 W5). Under a live STANDING
// community_cohort_benchmarking grant it computes the developer's own value for
// each registered metric over the CURRENT, IN-PROGRESS UTC month from local
// session data and uploads it. The value is re-sent on each sync until the
// month closes, after which the server freezes it — so the last value before
// month-end is what the cohort aggregation uses. That is exactly what the
// receipt's source-window rule (cloudcontract.CommunitySourceWindowRule) and
// the grant-time disclosure say (Sol re-review N1, ruled option A).
//
// The metrics reuse the SAME local aggregation the structural rail computes
// (LoadStructuralDayFacts: SessionCount + SessionsWithVerification), so there is
// one owner of "how many sessions / how many verified" and no second definition
// that could drift. Everything is consent-gated: with no live standing grant,
// nothing is computed or sent.

// Community phase-1 contribution identifiers. These are validated SERVER-SIDE
// against the community metric/cohort registry (an unknown id is a 400), which
// is the authority; the node hard-codes the phase-1 set it knows how to compute,
// exactly as the structural rail hard-codes its schema constants.
const (
	communityCohortGlobal         = "global"
	communityMetricSessionsPerDay = "sessions_per_active_day"
	communityMetricVerifCoverage  = "verification_coverage_pct"
	communityMetricVersion        = 1

	// cloudCommunitySourceWindowRule is the versioned identifier of WHICH
	// activity a community standing grant covers — the community counterpart
	// to cloudStructuralSourceWindowRule (cloudstructural.go). It is the
	// contract's constant, not a local literal, because it is a WIRE term the
	// server registers (declared on every upload) and part of the community
	// data dictionary the receipt binds. v1 "in_progress_utc_month_after_grant":
	// the CURRENT in-progress UTC month's running value, re-sent each sync
	// until the month closes and then frozen server-side; the grant's own
	// creation month is never eligible (Sol review F6 — standing grants
	// authorize FUTURE windows, never backfilled history). The retired name
	// "completed_utc_months_after_grant" described egress that never happened
	// (Sol re-review N1); a receipt still carrying it fails
	// cloudCommunityTermsCurrent and needs reconfirmation.
	cloudCommunitySourceWindowRule = cloudcontract.CommunitySourceWindowRule
)

// cloudCommunityTermsCurrent reports whether a resolved community grant was
// recorded under the terms THIS build sends under: the current source-window
// rule, the current data-dictionary digest (which the rule and the UTC-fixed
// timezone are part of), and the UTC declared timezone. A receipt under
// retired terms is a receipt for a disclosure the developer never saw for
// today's egress; it is not sent under, and the remedy is a re-grant, which
// raises the consent generation (the existing terms-changed mechanism).
func cloudCommunityTermsCurrent(grant cloudgateway.Grant) error {
	switch {
	case grant.SourceWindowRule != cloudCommunitySourceWindowRule:
		return fmt.Errorf("the grant binds source window rule %q; this build contributes under %q",
			grant.SourceWindowRule, cloudCommunitySourceWindowRule)
	case grant.DataDictionaryDigest != cloudcontract.CommunityDataDictionaryDigest():
		return fmt.Errorf("the grant binds data-dictionary digest %s; this build serves %s",
			grant.DataDictionaryDigest, cloudcontract.CommunityDataDictionaryDigest())
	case grant.DeclaredTimezone != cloudcontract.CommunityDeclaredTimezone:
		return fmt.Errorf("the grant declares timezone %q; community windows are fixed to %s",
			grant.DeclaredTimezone, cloudcontract.CommunityDeclaredTimezone)
	}
	return nil
}

// cloudCommunityEligibleWindow reports whether now's UTC calendar month is
// eligible for community contribution under a grant created at grantedAt: the
// grant's own creation month is excluded, since sessions on days BEFORE the
// grant existed would otherwise be folded into that month's scalar. The first
// eligible month is the first one that starts strictly after the grant.
func cloudCommunityEligibleWindow(grantedAt, now time.Time) bool {
	g := grantedAt.UTC()
	n := now.UTC()
	return n.Year() > g.Year() || (n.Year() == g.Year() && n.Month() > g.Month())
}

// cloudSyncCommunity computes and uploads the current-month contributions. It is
// reported separately and is never fatal — a community problem must not cost the
// developer their session-evidence or structural sync.
func cloudSyncCommunity(ctx context.Context, st *store.Store, gw *cloudgateway.Gateway, now time.Time, w io.Writer) {
	grant, err := gw.ResolveStandingGrant(ctx, cloudcontract.PurposeCohortBenchmarking)
	if err != nil {
		if errors.Is(err, cloudgateway.ErrNoLiveGrant) || errors.Is(err, cloudgateway.ErrNoConsentSource) {
			fmt.Fprintln(w, "Community: skipped — no standing grant, so nothing was computed or sent.")
			fmt.Fprintln(w, "  Grant one with `observer cloud consent grant --purpose community_cohort_benchmarking`.")
			return
		}
		fmt.Fprintf(w, "Community: skipped — could not resolve the standing grant: %v\n", err)
		return
	}

	if terr := cloudCommunityTermsCurrent(grant); terr != nil {
		// The consent-terms bump (Sol re-review N1): a receipt under the
		// retired rule/dictionary is NOT live for this rail. Nothing is
		// computed or sent; the developer re-grants against the truthful
		// disclosure, which raises the consent generation.
		fmt.Fprintf(w, "Community: NEEDS RECONFIRMATION — the standing grant was recorded under earlier terms (%v).\n", terr)
		fmt.Fprintf(w, "  Nothing was computed or sent. Re-grant with `observer cloud consent grant --purpose %s`\n",
			cloudcontract.PurposeCohortBenchmarking)
		fmt.Fprintln(w, "  to read and confirm the current disclosure.")
		return
	}

	if !cloudCommunityEligibleWindow(grant.CreatedAt, now) {
		// F6: the grant's own creation month is never eligible — contributing it
		// would fold sessions from before consent existed into the scalar. This
		// is not a partial-month feature; it is a hard skip until the calendar
		// rolls over into the first month that starts after the grant.
		fmt.Fprintf(w, "Community: skipped — the grant month (%s) is not eligible; the first eligible month begins after it.\n",
			grant.CreatedAt.UTC().Format("2006-01"))
		return
	}

	window := now.UTC().Format("2006-01")
	values, cerr := cloudComputeCommunityMonth(ctx, st, now)
	if cerr != nil {
		fmt.Fprintf(w, "Community: computation incomplete: %v\n", cerr)
	}
	if len(values) == 0 {
		fmt.Fprintf(w, "Community: no sessions this month (%s) yet — nothing to contribute.\n", window)
		return
	}

	// Contribute each computable metric to the global cohort. The wire terms
	// (digest, endpoint) are sourced from THIS exact grant — the one whose
	// ConsentGeneration/window-eligibility we already checked above — never a
	// freshly re-resolved value that could belong to a DIFFERENT receipt.
	//
	// recheckReceipt is the extra PreAttempt half of Sol review F2's fix: the
	// gateway's own built-in recheck (composed ahead of this by
	// StandingSendCommunity/authorize) only confirms SOME standing grant for
	// this purpose is still live — it does not confirm it is the SAME receipt
	// (grant.ReceiptID, captured above) whose terms were used to build the
	// bytes about to be sent. A `consent grant` re-run between the resolve
	// above and this attempt mints a new receipt with a new digest/endpoint;
	// without this check the upload would go out authorized-in-spirit by the
	// new receipt but carrying the OLD receipt's terms. Run before every
	// physical attempt, including retries (matches FD3).
	receiptID := grant.ReceiptID
	recheckReceipt := func() error {
		cur, rerr := gw.ResolveStandingGrant(ctx, cloudcontract.PurposeCohortBenchmarking)
		if rerr != nil {
			return fmt.Errorf("community: re-checking the standing grant: %w", rerr)
		}
		if cur.ReceiptID != receiptID {
			return fmt.Errorf("community: the standing grant changed since this sync started (was receipt %s, now %s) — its terms are stale, resend on the next sync",
				receiptID, cur.ReceiptID)
		}
		return nil
	}

	metricIDs := []string{communityMetricSessionsPerDay, communityMetricVerifCoverage}
	var sent, failed int
	err = gw.StandingSendCommunity(ctx, cloudcontract.PurposeCohortBenchmarking, func(sess cloudgateway.CommunitySession) error {
		for _, id := range metricIDs {
			v, ok := values[id]
			if !ok {
				continue // metric had no data this month
			}
			contribution, berr := cloudevidence.BuildCommunityContribution(cloudevidence.CommunityInput{
				CohortKey:     communityCohortGlobal,
				MetricID:      id,
				MetricVersion: communityMetricVersion,
				WindowID:      window,
				Value:         v,
			})
			if berr != nil {
				fmt.Fprintf(w, "  %s: not sent — %v\n", id, berr)
				failed++
				continue
			}
			payload, digest, serr := cloudevidence.SerializeCommunity(contribution)
			if serr != nil {
				fmt.Fprintf(w, "  %s: not sent — %v\n", id, serr)
				failed++
				continue
			}
			if _, uerr := sess.UploadCommunity(ctx, cloudgateway.CommunityUploadRequest{
				Payload:              payload,
				Digest:               digest,
				ConsentGeneration:    grant.ConsentGeneration,
				DataDictionaryDigest: grant.DataDictionaryDigest,
				// The standing-grant binding the server registers: the rule and
				// timezone come from THIS receipt too (N1/N5), never from a
				// local constant that could disagree with what was granted.
				SourceWindowRule: grant.SourceWindowRule,
				DeclaredTimezone: grant.DeclaredTimezone,
				Endpoint:         grant.Endpoint,
				PreAttempt:       recheckReceipt,
				// The cross-process dispatch lease (N2): taken under THIS exact
				// receipt + generation immediately before every physical
				// attempt, released after; a revoke/re-grant refuses new leases
				// and waits for held ones.
				DispatchLease: cloudDispatchLeaseFor(st, grant.ReceiptID, cloudcontract.PurposeCohortBenchmarking, grant.ConsentGeneration),
			}); uerr != nil {
				cloudCommunityReportSendError(w, id, window, uerr)
				failed++
				continue
			}
			sent++
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, cloudgateway.ErrNoLiveGrant) || errors.Is(err, cloudgateway.ErrGrantRevoked) {
			fmt.Fprintln(w, "Community: not sent — no live consent grant; nothing left this machine.")
			return
		}
		fmt.Fprintf(w, "Community: send incomplete: %v\n", err)
	}
	fmt.Fprintf(w, "Community: %d contribution(s) sent for %s, %d failed.\n", sent, window, failed)
}

// cloudCommunityReportSendError prints why one contribution was not sent. A
// 409 cross_device_conflict is turned into a RECOVERY ACTION rather than an
// echoed server sentence (Sol re-review F9): first device to sync a window owns
// it for that window, so the developer either syncs from that device or waits
// for the next window. The server's owner_device_hint / next_window body
// fields are used when present and stated as unknown when not.
func cloudCommunityReportSendError(w io.Writer, metricID, window string, err error) {
	detail, ok := cloudgateway.HTTPError(err)
	if !ok || detail.StatusCode != http.StatusConflict || detail.Code != "cross_device_conflict" {
		fmt.Fprintf(w, "  %s: not sent — %v\n", metricID, err)
		return
	}
	owner := detail.Extra["owner_device_hint"]
	if owner == "" {
		owner = "(the server did not name it)"
	}
	next := detail.Extra["next_window"]
	if next == "" {
		next = "the month after " + window
	}
	fmt.Fprintf(w, "  %s: not sent — window %s was already synced from a different device on this account (device %s).\n",
		metricID, window, owner)
	fmt.Fprintf(w, "    The first device to sync a window owns it for that window: sync from that device to update %s,\n", window)
	fmt.Fprintf(w, "    or wait for the next window (%s), which this device can sync first. Nothing was overwritten.\n", next)
}

// cloudComputeCommunityMonth aggregates the developer's local session data over
// the CURRENT UTC month into each computable metric value. It reuses the
// structural window aggregation per UTC day so "active day" (a day with >=1
// session) and the verification numerator share the structural rail's single
// definition. A metric with no data this month is absent from the result, and
// nothing is contributed for it.
func cloudComputeCommunityMonth(ctx context.Context, st *store.Store, now time.Time) (map[string]float64, error) {
	monthStart := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	// Iterate each UTC day from the month start through today (the current day is
	// still accumulating, but the running value is re-upserted every sync until
	// the month finalizes, so including today is correct, not premature).
	var daily []store.StructuralDayFacts
	for day := monthStart; !day.After(now.UTC()); day = day.AddDate(0, 0, 1) {
		dayEnd := day.AddDate(0, 0, 1)
		facts, err := st.LoadStructuralDayFacts(ctx,
			day.Format(time.RFC3339), dayEnd.Format(time.RFC3339))
		if err != nil {
			return nil, fmt.Errorf("aggregate %s: %w", day.Format("2006-01-02"), err)
		}
		daily = append(daily, facts)
	}
	return computeCommunityMonthMetrics(daily), nil
}

// computeCommunityMonthMetrics is the PURE aggregation: a month of per-day
// structural facts into the two community metric values. Kept pure (no store,
// no clock) so the metric math is unit-tested in isolation.
//
//   - sessions_per_active_day = total sessions / number of ACTIVE days (a day
//     with >=1 session), rounded to ONE DECIMAL before serialization — the
//     hosted metric registry's band edges are defined against the rounded
//     value ("rounded to 1 decimal upstream", 0022_community_percentile.sql),
//     so uploading the raw division could land a value like 61/31=1.9677 on
//     the wrong side of an edge from where its rounded 2.0 belongs (Sol
//     review F11). Absent when there were no active days.
//   - verification_coverage_pct = 100 * sessions-with-verification / total
//     sessions. The hosted registry does NOT document this metric as rounded
//     upstream (unlike sessions_per_active_day) and its band edges (10/25/
//     50/75/90) are not sub-integer, so no rounding is applied here — see the
//     F11 note in the migration comment above. Absent when there were no
//     sessions.
func computeCommunityMonthMetrics(daily []store.StructuralDayFacts) map[string]float64 {
	var totalSessions, activeDays, totalVerified int
	for _, f := range daily {
		if f.SessionCount == 0 {
			continue
		}
		activeDays++
		totalSessions += f.SessionCount
		totalVerified += f.SessionsWithVerification
	}
	out := make(map[string]float64, 2)
	if activeDays > 0 {
		out[communityMetricSessionsPerDay] = math.Round(float64(totalSessions)/float64(activeDays)*10) / 10
	}
	if totalSessions > 0 {
		out[communityMetricVerifCoverage] = 100 * float64(totalVerified) / float64(totalSessions)
	}
	return out
}
