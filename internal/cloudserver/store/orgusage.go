package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// orgusage.go is the one store seam of org_usage_days (cloud 0085; plan 07
// M7b.2): the daily usage report an org's tenant host answers the host
// API's usage verb with (M6.4 pulls it), kept per (org, receipt day). The
// billing period's seat count is computed from these rows by
// internal/orgserver/usage.PeriodSeats, never by SQL here.
//
// Retention (lead decision W16-D9, L-124 C3.ENTL-usage-retention; cloud
// 0100 and 0101): a day is kept 10 years from its date, after the org is
// deleted too (the foreign key has no cascade), and only
// sbci_expire_org_usage_days may delete one, never inside those 10 years.
// Its member ids are minimised once the day is older than the billing and
// dispute window (13 months by default): MinimiseOrgUsageDays keeps the
// count in seat_count and empties seat_member_ids. A minimised day can no
// longer enter PeriodSeats' union, which only ever reads a current period.

// ErrUsageReport means a report or its day is malformed.
var ErrUsageReport = errors.New("cloudserver/store: malformed usage report")

const maxSeatMembers = 100000

var reportDigestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// The AI gateway refusal reasons a report may carry (cloud 0157): a short
// counter name, at most a handful of them.
var aigwReasonRE = regexp.MustCompile(`^[a-z_]{1,40}$`)

const maxAIGWRefusalReasons = 16

// OrgUsageDay is one stored daily report.
type OrgUsageDay struct {
	// Day is the receipt day (YYYY-MM-DD).
	Day string
	// Usage is the report; TenantID is the org id.
	Usage platformcontract.TenantUsage
	// ReportDigest is the SHA-256 (hex) of the signed report body.
	ReportDigest string
	// SeatCount is the day's distinct seat members: the kept count of a
	// minimised day, else the number of its member ids.
	SeatCount int
	// Minimised is true once the day's member ids were emptied
	// (Usage.ActiveSeatMemberIDs is then empty and SeatCount holds them).
	Minimised bool
	// ReceivedAt is when the row was last written.
	ReceivedAt time.Time
}

func checkUsageReport(orgID, day string, u platformcontract.TenantUsage, digest string) error {
	if _, err := time.Parse(time.DateOnly, day); err != nil {
		return fmt.Errorf("day %q: %w", day, ErrUsageReport)
	}
	if u.TenantID != orgID {
		return fmt.Errorf("report for tenant %q stored under org %q: %w", u.TenantID, orgID, ErrUsageReport)
	}
	if u.MachineIdentities < 0 || u.Sessions < 0 || u.Members < 0 || u.AIGWRequests < 0 {
		return fmt.Errorf("negative count: %w", ErrUsageReport)
	}
	if len(u.AIGWRefusals) > maxAIGWRefusalReasons {
		return fmt.Errorf("%d AI gateway refusal reasons: %w", len(u.AIGWRefusals), ErrUsageReport)
	}
	for reason, n := range u.AIGWRefusals {
		if !aigwReasonRE.MatchString(reason) || n < 0 {
			return fmt.Errorf("AI gateway refusal reason %q = %d: %w", reason, n, ErrUsageReport)
		}
	}
	if len(u.ActiveSeatMemberIDs) > maxSeatMembers {
		return fmt.Errorf("%d seat members: %w", len(u.ActiveSeatMemberIDs), ErrUsageReport)
	}
	for _, m := range u.ActiveSeatMemberIDs {
		if m == "" || len(m) > 128 {
			return fmt.Errorf("seat member id empty or too long: %w", ErrUsageReport)
		}
	}
	if !reportDigestRE.MatchString(digest) {
		return fmt.Errorf("report digest is not hex SHA-256: %w", ErrUsageReport)
	}
	return nil
}

// RecordOrgUsageDay stores one org's report for one receipt day. A day
// already stored merges: the seat members become the union and the counts
// the larger (members takes the newer value: it is a point-in-time count),
// so a later partial pull never lowers a reported seat. A day already
// minimised keeps no member id: a late report raises its kept count to the
// larger of the two and stores none of its ids.
func (s *Store) RecordOrgUsageDay(ctx context.Context, orgID, day string, u platformcontract.TenantUsage, reportDigest string) error {
	if err := checkUsageReport(orgID, day, u, reportDigest); err != nil {
		return fmt.Errorf("cloudserver/store.RecordOrgUsageDay: %w", err)
	}
	seats := u.ActiveSeatMemberIDs
	if seats == nil {
		seats = []string{}
	}
	refusals := u.AIGWRefusals
	if refusals == nil {
		refusals = map[string]int64{}
	}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`INSERT INTO org_usage_days (org_id, day, seat_member_ids, machine_identities, sessions, members, report_digest,
			                             aigw_requests, aigw_refusals)
			 VALUES ($1::uuid, $2::date, $3::text[], $4, $5, $6, $7, $8, $9::jsonb)
			 ON CONFLICT (org_id, day) DO UPDATE SET
			     seat_member_ids = CASE WHEN org_usage_days.minimised_at IS NOT NULL THEN '{}'::text[]
			                            ELSE (SELECT coalesce(array_agg(DISTINCT m ORDER BY m), '{}')
			                                    FROM unnest(org_usage_days.seat_member_ids || EXCLUDED.seat_member_ids) AS m) END,
			     seat_count = CASE WHEN org_usage_days.minimised_at IS NOT NULL
			                       THEN greatest(org_usage_days.seat_count, cardinality(EXCLUDED.seat_member_ids))
			                       ELSE NULL END,
			     machine_identities = greatest(org_usage_days.machine_identities, EXCLUDED.machine_identities),
			     sessions = greatest(org_usage_days.sessions, EXCLUDED.sessions),
			     members = EXCLUDED.members,
			     report_digest = EXCLUDED.report_digest,
			     aigw_requests = greatest(org_usage_days.aigw_requests, EXCLUDED.aigw_requests),
			     aigw_refusals = (SELECT coalesce(jsonb_object_agg(k, greatest(coalesce((org_usage_days.aigw_refusals->>k)::bigint, 0),
			                                                                    coalesce((EXCLUDED.aigw_refusals->>k)::bigint, 0))), '{}'::jsonb)
			                        FROM jsonb_object_keys(org_usage_days.aigw_refusals || EXCLUDED.aigw_refusals) AS k),
			     received_at = now()`,
			orgID, day, seats, u.MachineIdentities, u.Sessions, u.Members, reportDigest, u.AIGWRequests, refusals)
		return err
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.RecordOrgUsageDay: %w", err)
	}
	return nil
}

// OrgUsageDays returns an org's stored reports for the receipt days from
// start up to, not including, end (YYYY-MM-DD), ordered by day.
func (s *Store) OrgUsageDays(ctx context.Context, orgID, start, end string) ([]OrgUsageDay, error) {
	for _, d := range []string{start, end} {
		if _, err := time.Parse(time.DateOnly, d); err != nil {
			return nil, fmt.Errorf("cloudserver/store.OrgUsageDays: day %q: %w", d, ErrUsageReport)
		}
	}
	var out []OrgUsageDay
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT to_char(day, 'YYYY-MM-DD'), seat_member_ids, machine_identities, sessions, members, report_digest, received_at,
			        coalesce(seat_count, cardinality(seat_member_ids)), minimised_at IS NOT NULL,
			        aigw_requests, aigw_refusals
			   FROM org_usage_days
			  WHERE org_id = $1::uuid AND day >= $2::date AND day < $3::date
			  ORDER BY day`, orgID, start, end)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			d := OrgUsageDay{Usage: platformcontract.TenantUsage{TenantID: orgID}}
			var refusals map[string]int64
			if err := rows.Scan(&d.Day, &d.Usage.ActiveSeatMemberIDs, &d.Usage.MachineIdentities, &d.Usage.Sessions,
				&d.Usage.Members, &d.ReportDigest, &d.ReceivedAt, &d.SeatCount, &d.Minimised,
				&d.Usage.AIGWRequests, &refusals); err != nil {
				return err
			}
			if len(refusals) > 0 {
				d.Usage.AIGWRefusals = refusals
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.OrgUsageDays: %w", err)
	}
	return out, nil
}

// maxMinimiseBatch bounds one MinimiseOrgUsageDays statement: a backlog is
// worked off over several passes, never in one long transaction.
const maxMinimiseBatch = 5000

// MinimiseOrgUsageDays minimises up to maxMinimiseBatch days dated strictly
// before before (YYYY-MM-DD) that still hold member ids: each keeps its
// count in seat_count, is stamped minimised_at = now, and loses its ids
// (W16-D9). It returns how many it minimised; a day already minimised is
// never touched again, so a repeated pass changes nothing.
func (s *Store) MinimiseOrgUsageDays(ctx context.Context, before string, now time.Time) (int64, error) {
	if _, err := time.Parse(time.DateOnly, before); err != nil {
		return 0, fmt.Errorf("cloudserver/store.MinimiseOrgUsageDays: day %q: %w", before, ErrUsageReport)
	}
	var n int64
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE org_usage_days u
			    SET seat_count = cardinality(u.seat_member_ids), seat_member_ids = '{}', minimised_at = $2
			  WHERE (u.org_id, u.day) IN (
			        SELECT org_id, day FROM org_usage_days
			         WHERE day < $1::date AND minimised_at IS NULL
			         ORDER BY day, org_id
			         LIMIT $3
			           FOR UPDATE)`,
			before, now.UTC(), maxMinimiseBatch)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.MinimiseOrgUsageDays: %w", err)
	}
	return n, nil
}

// ExpireOrgUsageDays deletes the days dated strictly before before
// (YYYY-MM-DD) through sbci_expire_org_usage_days, the table's only delete
// path, which refuses any day inside the 10-year retention (cloud 0101). It
// returns how many it deleted.
func (s *Store) ExpireOrgUsageDays(ctx context.Context, before string) (int64, error) {
	if _, err := time.Parse(time.DateOnly, before); err != nil {
		return 0, fmt.Errorf("cloudserver/store.ExpireOrgUsageDays: day %q: %w", before, ErrUsageReport)
	}
	var n int64
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT sbci_expire_org_usage_days($1::date)`, before).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.ExpireOrgUsageDays: %w", err)
	}
	return n, nil
}
