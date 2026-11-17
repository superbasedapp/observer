package hostclient

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/hostapi"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// UsageStore keeps the daily usage reports (*store.Store, bound to
// sbci_worker: store.RecordOrgUsageDay over org_usage_days, cloud 0085,
// which merges a day pulled twice so a later partial pull never lowers a
// reported seat).
type UsageStore interface {
	RecordOrgUsageDay(ctx context.Context, orgID, day string, u pc.TenantUsage, reportDigest string) error
}

// UsageStats counts one usage pull.
type UsageStats struct {
	// Hosts is how many hosts were asked.
	Hosts int
	// Reports is how many verified reports came back (one per host and day).
	Reports int
	// Unanswered is how many (host, day) asks got no verified usage answer
	// (a transport failure, an unverified or refused answer, another day).
	// Nothing is stored for them; the next pass asks again.
	Unanswered int
	// Recorded is how many tenant entries were stored.
	Recorded int
	// Dropped counts the entries not stored, by verdict.
	Dropped map[hostapi.UsageVerdict]int
}

// pullUsage asks every host that serves at least one org in placed (org id
// to host id) for its signed report of each receipt day hostapi.UsageDays
// names, and stores each entry the usage rules accept. An unanswered ask is
// counted, not an error (a host that has not built the verb yet answers
// unavailable, and the next pass asks again); a store failure is an error.
func (r *Reconciler) pullUsage(ctx context.Context, placed map[string]string) (UsageStats, error) {
	st := UsageStats{Dropped: map[hostapi.UsageVerdict]int{}}
	byHost := map[string]bool{}
	for _, h := range placed {
		byHost[h] = true
	}
	hostIDs := make([]string, 0, len(byHost))
	for h := range byHost {
		hostIDs = append(hostIDs, h)
	}
	sort.Strings(hostIDs)
	days := hostapi.UsageDays(r.now(), r.usageDays)
	var errs []error
	for _, hostID := range hostIDs {
		h, ok := r.hosts.Host(hostID)
		if !ok {
			continue // the reconciler's own pass reports an unknown host
		}
		st.Hosts++
		for _, day := range days {
			if ctx.Err() != nil {
				return st, nil
			}
			req, err := hostapi.UsageProbe(day)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			rep, ok := hostapi.ReadUsage(r.tr.Send(ctx, h, req), day)
			if !ok {
				st.Unanswered++
				continue
			}
			st.Reports++
			if err := r.storeUsage(ctx, hostID, day, rep, placed, &st); err != nil {
				errs = append(errs, err)
			}
		}
	}
	if len(errs) > 0 {
		return st, fmt.Errorf("hostclient.Reconciler.pullUsage: %w", errors.Join(errs...))
	}
	return st, nil
}

// storeUsage judges and stores the entries of one verified report from
// hostID.
func (r *Reconciler) storeUsage(ctx context.Context, hostID, day string, rep hostapi.UsageReport, placed map[string]string, st *UsageStats) error {
	seen := map[string]bool{}
	var errs []error
	for _, u := range rep.Report.Tenants {
		v := hostapi.JudgeUsage(hostapi.UsageEntry{
			Usage:      u,
			PlacedHere: placed[u.TenantID] == hostID,
			SeenBefore: seen[u.TenantID],
		})
		seen[u.TenantID] = true
		if v != hostapi.UsageRecord {
			st.Dropped[v]++
			continue
		}
		if err := r.usage.RecordOrgUsageDay(ctx, u.TenantID, day, u, rep.Digest); err != nil {
			errs = append(errs, fmt.Errorf("host %s day %s org %s: %w", hostID, day, u.TenantID, err))
			continue
		}
		st.Recorded++
	}
	return errors.Join(errs...)
}
