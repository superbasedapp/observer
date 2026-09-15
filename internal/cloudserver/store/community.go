package store

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/community"
)

// ErrWindowNotCurrent is returned by the contribution write path when the target
// window is not the server's current, in-progress UTC-month window — either
// because it has already elapsed (allowing a value change would let its published
// aggregate move, a repeated-window differencing signal, Sol F5) or because it
// names a window that has not started yet (an authenticated device pre-seeding a
// future window with an arbitrary value before being revoked, Sol F10).
// Contributions may only be written to the single current, in-progress window.
//
// Renamed from ErrWindowFinalized (Sol re-review N7): "finalized" is wrong for a
// FUTURE window that has not started, and the DB trigger reports both cases the
// same way. The current, in-progress window is the single writable one; anything
// else — past or future — is "not current".
var ErrWindowNotCurrent = errors.New("cloudserver/store: contribution window is not the current, in-progress window; only the in-progress window accepts writes")

// ErrWindowFinalized is a DEPRECATED alias for ErrWindowNotCurrent, kept so any
// out-of-tree caller (and older tests) that did errors.Is(err, ErrWindowFinalized)
// keeps matching. New code should reference ErrWindowNotCurrent.
//
// Deprecated: use ErrWindowNotCurrent.
var ErrWindowFinalized = ErrWindowNotCurrent

// ErrUnknownCohort is returned by UpsertContribution when the cohort key is not a
// registered community cohort (Sol review F7a — the data boundary rejects
// arbitrary cohort keys).
var ErrUnknownCohort = errors.New("cloudserver/store: cohort is not a registered community cohort")

// ErrCrossDeviceConflict is returned by UpsertContribution when a DIFFERENT
// device than the one that wrote the existing (account, cohort, metric,
// version, window) row attempts to write it (Sol review F9 recommendation
// #1). leaderboard_contributions' natural key has no device dimension —
// widening it would double-count the account in the aggregation — so instead
// the second device is refused rather than silently overwriting the first
// device's value. First device to sync a window wins; a same-device rewrite
// remains idempotent.
var ErrCrossDeviceConflict = errors.New("cloudserver/store: this contribution window was already synced from a different device on this account")

// community.go is the SQL owner for the W5 private community-percentile surface
// (divergence remediation plan §3 "W5"; operator ruling R3). Three seams, three
// trust boundaries:
//
//   - CommunityBands   — the ONLY cross-tenant read. Runs as sbci_aggregator via
//     WithAggregator and returns nothing but floored, k-suppressed band cells
//     from the SECURITY DEFINER sbci_community_bands function. It takes no
//     account argument, so it cannot target or difference out an account.
//   - UpsertContribution — the tenant-owned write (WithAccount, RLS+WITH CHECK):
//     an account records its OWN metric value for a finalized window. Idempotent
//     on (cohort, metric, version, window): re-contributing updates in place.
//   - AccountContribution — the tenant-owned read of the account's OWN value,
//     for placing its own percentile (the own-percentile surface builds on this).

// BandCell is one finalized, floored, k-suppressed histogram cell returned by the
// aggregation. It carries a band index and a count — never a raw value, a cohort
// total, or an account id.
type BandCell struct {
	CohortKey     string `json:"cohort_key"`
	MetricID      string `json:"metric_id"`
	MetricVersion int    `json:"metric_version"`
	WindowID      string `json:"window_id"`
	Band          int    `json:"band"`
	BandCount     int64  `json:"band_count"`
}

// CommunityBands returns the floored, k-suppressed band distribution for a
// (cohort, metric, version, window) as computed cross-tenant by the SECURITY
// DEFINER sbci_community_bands function under the aggregator role. It returns an
// empty slice (never an error) when the window is not yet finalized, the metric
// is unregistered, the window_id is malformed, or the displayed-cohort is below
// the ≥30 floor — the function collapses all of those to "no cells", so a caller
// cannot distinguish "too small" from "not yet due" from "unknown metric", which
// is itself a privacy property.
//
// The arguments are FIXED registry identifiers only. There is deliberately no
// account parameter and no free predicate: "this cohort minus account X" is
// unexpressible, so cohort-minus-one differencing is structurally impossible.
func (s *Store) CommunityBands(ctx context.Context, cohortKey, metricID string, metricVersion int, windowID string) ([]BandCell, error) {
	var out []BandCell
	err := s.WithAggregator(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT cohort_key, metric_id, metric_version, window_id, band, band_count
			   FROM sbci_community_bands($1, $2, $3, $4)`,
			cohortKey, metricID, metricVersion, windowID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c BandCell
			if e := rows.Scan(&c.CohortKey, &c.MetricID, &c.MetricVersion, &c.WindowID, &c.Band, &c.BandCount); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.CommunityBands: %w", err)
	}
	return out, nil
}

// CommunityBandSnapshot is one materialized delayed-band cell, as read by the
// api/portal from community_band_snapshots. It carries the cohort size (≥30 by
// construction) alongside the band count — never a raw value or account id.
type CommunityBandSnapshot struct {
	CohortKey     string `json:"cohort_key"`
	MetricID      string `json:"metric_id"`
	MetricVersion int    `json:"metric_version"`
	WindowID      string `json:"window_id"`
	Band          int    `json:"band"`
	BandCount     int64  `json:"band_count"`
	CohortSize    int64  `json:"cohort_size"`
}

// MaterializeCommunityWindow computes the finalized, floored, k-suppressed bands
// and the cohort size for one (cohort, metric, version, window) via the
// aggregator role, then REWRITES that window's rows in community_band_snapshots
// (the delayed-band materialization the api/portal reads). It returns the number
// of cells written. A window that is unfinalized or below the ≥30 floor yields
// zero cells and a zero size, and this clears any stale rows for it.
//
// The read (sbci_community_bands + sbci_community_cohort_size) runs under
// WithAggregator — the only role permitted to EXECUTE them — and the write runs
// under the store's own role (worker in production, app in dev/tests, both
// granted DML on the snapshot table). The two run in separate transactions: the
// materialization is a delayed, idempotent recompute, so it does not need the
// read and write to be atomic; a concurrent re-run simply recomputes the same
// finalized (frozen) window.
func (s *Store) MaterializeCommunityWindow(ctx context.Context, cohortKey, metricID string, metricVersion int, windowID string) (int, error) {
	cells, err := s.CommunityBands(ctx, cohortKey, metricID, metricVersion, windowID)
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.MaterializeCommunityWindow: bands: %w", err)
	}
	var size int64
	if err := s.WithAggregator(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT sbci_community_cohort_size($1, $2, $3, $4)`,
			cohortKey, metricID, metricVersion, windowID).Scan(&size)
	}); err != nil {
		return 0, fmt.Errorf("cloudserver/store.MaterializeCommunityWindow: size: %w", err)
	}

	// A window that did not clear the floor (size 0) must not persist any cells,
	// even if a prior run wrote some — recompute is authoritative.
	if size == 0 {
		cells = nil
	}

	written := 0
	if err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, e := tx.Exec(ctx,
			`DELETE FROM community_band_snapshots
			  WHERE cohort_key=$1 AND metric_id=$2 AND metric_version=$3 AND window_id=$4`,
			cohortKey, metricID, metricVersion, windowID); e != nil {
			return e
		}
		for _, c := range cells {
			if _, e := tx.Exec(ctx,
				`INSERT INTO community_band_snapshots
				     (cohort_key, metric_id, metric_version, window_id, band, band_count, cohort_size, computed_at)
				 VALUES ($1,$2,$3,$4,$5,$6,$7, now())`,
				cohortKey, metricID, metricVersion, windowID, c.Band, c.BandCount, size); e != nil {
				return e
			}
			written++
		}
		return nil
	}); err != nil {
		return 0, fmt.Errorf("cloudserver/store.MaterializeCommunityWindow: write: %w", err)
	}
	return written, nil
}

// ReadCommunityBands returns a materialized window's snapshot cells (the api /
// portal read path — sbci_api holds SELECT on community_band_snapshots but NOT
// EXECUTE on the aggregation, so it can only ever read the delayed snapshot).
// Runs WithSystem (aggregate-only table, no tenant scope). An empty slice means
// the window is not yet materialized, unfinalized, or below the floor.
func (s *Store) ReadCommunityBands(ctx context.Context, cohortKey, metricID string, metricVersion int, windowID string) ([]CommunityBandSnapshot, error) {
	var out []CommunityBandSnapshot
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT cohort_key, metric_id, metric_version, window_id, band, band_count, cohort_size
			   FROM community_band_snapshots
			  WHERE cohort_key=$1 AND metric_id=$2 AND metric_version=$3 AND window_id=$4
			  ORDER BY band`,
			cohortKey, metricID, metricVersion, windowID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var c CommunityBandSnapshot
			if e := rows.Scan(&c.CohortKey, &c.MetricID, &c.MetricVersion, &c.WindowID, &c.Band, &c.BandCount, &c.CohortSize); e != nil {
				return e
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ReadCommunityBands: %w", err)
	}
	return out, nil
}

// CommunityWindowRef identifies one finalized (cohort, metric, version, window)
// aggregate — no account, no value.
type CommunityWindowRef struct {
	CohortKey     string
	MetricID      string
	MetricVersion int
	WindowID      string
}

// ListFinalizedWindowsWithData returns every finalized (cohort, metric, version,
// window) that still has at least one contribution (Sol F7b). The worker
// materializes each so a deletion propagates to old published snapshots within a
// materialization cadence (well under R3's 24h). Runs under the aggregator role
// (the only role that may read cross-tenant contributions).
func (s *Store) ListFinalizedWindowsWithData(ctx context.Context) ([]CommunityWindowRef, error) {
	var out []CommunityWindowRef
	err := s.WithAggregator(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT cohort_key, metric_id, metric_version, window_id FROM sbci_community_windows()`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var r CommunityWindowRef
			if e := rows.Scan(&r.CohortKey, &r.MetricID, &r.MetricVersion, &r.WindowID); e != nil {
				return e
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.ListFinalizedWindowsWithData: %w", err)
	}
	return out, nil
}

// PruneOrphanCommunitySnapshots deletes materialized snapshot rows whose
// (cohort, metric, version, window) is NOT in live — i.e. a window whose
// contributions were all removed (opt-out/deletion). Together with
// ListFinalizedWindowsWithData + MaterializeCommunityWindow, this guarantees a
// deleted account's data leaves the PUBLISHED bands too, not just the raw table
// (Sol F7b). Runs WithSystem (aggregate-only table).
func (s *Store) PruneOrphanCommunitySnapshots(ctx context.Context, live []CommunityWindowRef) (int, error) {
	// Build the live key set for an anti-join. With a tiny fixed cohort×metric
	// registry this list is small; a NOT-IN over a VALUES set is fine.
	liveKeys := make(map[string]bool, len(live))
	for _, r := range live {
		liveKeys[r.CohortKey+"\x00"+r.MetricID+"\x00"+strconv.Itoa(r.MetricVersion)+"\x00"+r.WindowID] = true
	}
	deleted := 0
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `SELECT cohort_key, metric_id, metric_version, window_id FROM community_band_snapshots GROUP BY cohort_key, metric_id, metric_version, window_id`)
		if e != nil {
			return e
		}
		var stale []CommunityWindowRef
		for rows.Next() {
			var r CommunityWindowRef
			if e := rows.Scan(&r.CohortKey, &r.MetricID, &r.MetricVersion, &r.WindowID); e != nil {
				rows.Close()
				return e
			}
			if !liveKeys[r.CohortKey+"\x00"+r.MetricID+"\x00"+strconv.Itoa(r.MetricVersion)+"\x00"+r.WindowID] {
				stale = append(stale, r)
			}
		}
		rows.Close()
		if e := rows.Err(); e != nil {
			return e
		}
		for _, r := range stale {
			ct, e := tx.Exec(ctx,
				`DELETE FROM community_band_snapshots WHERE cohort_key=$1 AND metric_id=$2 AND metric_version=$3 AND window_id=$4`,
				r.CohortKey, r.MetricID, r.MetricVersion, r.WindowID)
			if e != nil {
				return e
			}
			deleted += int(ct.RowsAffected())
		}
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.PruneOrphanCommunitySnapshots: %w", err)
	}
	return deleted, nil
}

// UpsertContribution records (or replaces) the calling account's own metric value
// for a finalized window in a cohort. It runs tenant-scoped (WithAccount), so RLS
// + the table's WITH CHECK guarantee the row is written under this account and no
// other. Idempotent on the natural key FOR THE SAME DEVICE: a repeat contribution
// from the device that wrote the row updates the value in place rather than
// stacking, so the aggregation never double-counts an account. A contribution
// from a DIFFERENT device to an already-written (cohort, metric, version, window)
// is refused (ErrCrossDeviceConflict, Sol F9 recommendation #1) rather than
// silently overwriting the first device's value — deviceID is the caller's
// authenticated principal device, never a client-declared field. The metric must
// be registered in community_metrics (the FK rejects an unknown metric — the SQL
// half of forbidden-metric enforcement).
func (s *Store) UpsertContribution(ctx context.Context, accountID, deviceID, cohortKey, metricID string, metricVersion int, windowID string, value float64) error {
	// Reject an unregistered cohort at the boundary (Sol F7a): the metric FK
	// already rejects an unregistered metric; the cohort has no FK, so validate it
	// against the compiled-in registry here so an arbitrary cohort key can never
	// be stored. An unknown cohort is inert (no reader), but rejecting it keeps
	// the data boundary honest.
	if !community.ValidCohort(cohortKey) {
		return ErrUnknownCohort
	}
	// Freeze anything but the current window (Sol F5 elapsed + F10 future): only
	// the single in-progress UTC-month window accepts writes, so a published
	// aggregate can never move under a later value change AND a device can never
	// pre-seed a not-yet-eligible future window. The DB backstops this with a
	// trigger (migration 0025, tightened in 0027) so a direct SQL path cannot
	// bypass it either.
	//
	// NOTE: this legacy direct-write seam still consults the Go wall clock. The
	// admission path the intake handler now uses is AdmitCommunityContribution,
	// which makes the DB clock authoritative (Sol N4). This function is retained
	// for the store-level tests and for any non-admission direct write.
	if !community.IsCurrentWindow(time.Now(), windowID) {
		return ErrWindowNotCurrent
	}
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		// Re-fence the account status INSIDE this write transaction (Sol F5): a
		// standing grant can be validated and then the account can be deleted
		// before this write lands, or this write can race a concurrent deletion.
		// FOR SHARE serializes against the deletion fence's UPDATE of this same
		// row (mirrors revalidateStructuralAdmissionTx / SubmitJob's FE4 fence)
		// without blocking this account's OTHER concurrent uploads against each
		// other.
		if e := fenceAccountActiveTx(ctx, tx, accountID); e != nil {
			return e
		}
		_, e := upsertContributionTx(ctx, tx, accountID, deviceID, cohortKey, metricID, metricVersion, windowID, value)
		return e
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.UpsertContribution: %w", err)
	}
	return nil
}

// fenceAccountActiveTx takes the account row FOR SHARE and asserts it is still
// active, returning ErrAccountClosed otherwise (Sol F5). FOR SHARE — not FOR
// UPDATE — conflicts with the deletion fence's UPDATE of this row (so the two
// serialize: either this tx commits before the fence, and the deletion's own
// purge removes what it wrote, or this tx reads 'closed'/absent and refuses),
// while still letting the account's OWN concurrent uploads run in parallel.
func fenceAccountActiveTx(ctx context.Context, tx pgx.Tx, accountID string) error {
	var status string
	if e := tx.QueryRow(ctx,
		`SELECT status FROM accounts WHERE account_id = $1::uuid FOR SHARE`,
		accountID).Scan(&status); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return ErrAccountClosed
		}
		return fmt.Errorf("lock account: %w", e)
	}
	if status != "active" {
		return ErrAccountClosed
	}
	return nil
}

// dbCurrentWindowTx reads the DB's authoritative current UTC-month window id
// ("YYYY-MM") from clock_timestamp() (Sol N4). Using the DB clock for the Go-side
// currency decision means the API/store check and the DB trigger evaluate the
// SAME wall clock, so they cannot disagree across a UTC-rollover boundary the way
// three independently sampled clocks (API Go, store Go, DB) could.
func dbCurrentWindowTx(ctx context.Context, tx pgx.Tx) (string, error) {
	var w string
	if e := tx.QueryRow(ctx,
		`SELECT to_char(date_trunc('month', clock_timestamp() AT TIME ZONE 'UTC'), 'YYYY-MM')`).Scan(&w); e != nil {
		return "", fmt.Errorf("read db current window: %w", e)
	}
	return w, nil
}

// isWindowNotCurrentDBError reports whether e is the contribution freeze
// trigger's current-window violation (SQLSTATE 23514, raised by
// sbci_reject_finalized_contribution). It is the DB backstop for the micro-race
// where a request passes the Go-side dbCurrentWindowTx check just before a UTC
// rollover and reaches the INSERT just after it: the trigger rejects it and this
// maps the raw 23514 to the typed ErrWindowNotCurrent so the API returns a
// consistent 409 rather than a generic 500 (Sol N4).
func isWindowNotCurrentDBError(e error) bool {
	var pgErr interface{ SQLState() string }
	return errors.As(e, &pgErr) && pgErr.SQLState() == "23514"
}

// nextWindowAfter returns the UTC-month window id one month after the given
// "YYYY-MM" window — the next window that will accept writes (Sol F9 recovery
// hint). A malformed input yields "" (the caller omits the hint).
func nextWindowAfter(windowID string) string {
	if len(windowID) != 7 || windowID[4] != '-' {
		return ""
	}
	y, err1 := strconv.Atoi(windowID[:4])
	mo, err2 := strconv.Atoi(windowID[5:])
	if err1 != nil || err2 != nil || mo < 1 || mo > 12 {
		return ""
	}
	t := time.Date(y, time.Month(mo), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	return fmt.Sprintf("%04d-%02d", t.Year(), int(t.Month()))
}

// upsertContributionTx is the ONE owner of the leaderboard_contributions write
// SQL — shared by UpsertContribution (legacy direct seam) and
// AdmitCommunityContribution (the admission transaction). It performs the
// device-guarded upsert and returns the OWNING device id on a cross-device
// conflict (for the Sol F9 recovery hint).
//
// Ownership (Sol F9 + N6): the natural key has no device dimension, so a second
// device must not silently overwrite the first's value. The ON CONFLICT arm is
// guarded so it applies only when the existing row is owned by THIS device OR is
// a legacy unowned (”) row — the latter is CLAIMED by the first authenticated
// device that writes it (migration 0029 backfilled populated rows to ”, which
// no real device id can match; treating ” as unowned makes such a row writable
// again, Sol N6). RETURNING tells us whether the upsert applied: an existing row
// owned by a DIFFERENT, non-empty device leaves the guard false, writes nothing,
// yields pgx.ErrNoRows, and maps to ErrCrossDeviceConflict — a single atomic
// statement, so two devices' first writes cannot interleave.
func upsertContributionTx(ctx context.Context, tx pgx.Tx, accountID, deviceID, cohortKey, metricID string, metricVersion int, windowID string, value float64) (conflictOwnerDevice string, err error) {
	var wroteDevice string
	e := tx.QueryRow(ctx,
		`INSERT INTO leaderboard_contributions
		     (account_id, cohort_key, metric_id, metric_version, window_id, device_id, value)
		 VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
		 ON CONFLICT (account_id, cohort_key, metric_id, metric_version, window_id)
		 DO UPDATE SET value = EXCLUDED.value, device_id = EXCLUDED.device_id, updated_at = now()
		 WHERE leaderboard_contributions.device_id IN ('', EXCLUDED.device_id)
		 RETURNING device_id`,
		accountID, cohortKey, metricID, metricVersion, windowID, deviceID, value).
		Scan(&wroteDevice)
	if errors.Is(e, pgx.ErrNoRows) {
		// The guard was false: a different, non-empty device owns this row. Read
		// its owner so the caller can surface an actionable recovery hint. The
		// SELECT runs in the same tx; even though the caller rolls the tx back on
		// this error, the value is already captured in Go.
		var owner string
		if e2 := tx.QueryRow(ctx,
			`SELECT device_id FROM leaderboard_contributions
			  WHERE account_id = $1::uuid AND cohort_key = $2
			    AND metric_id = $3 AND metric_version = $4 AND window_id = $5`,
			accountID, cohortKey, metricID, metricVersion, windowID).Scan(&owner); e2 != nil {
			// Best-effort hint only; the conflict itself is authoritative.
			owner = ""
		}
		return owner, ErrCrossDeviceConflict
	}
	if isWindowNotCurrentDBError(e) {
		return "", ErrWindowNotCurrent
	}
	return "", e
}

// AdmitCommunityContributionInput carries everything one atomic community
// admission needs: the standing-grant binding (validated/registered in the SAME
// transaction as the write) and the contribution itself.
type AdmitCommunityContributionInput struct {
	// Grant binding. Purpose + DeviceID are supplied by the CALLER from the
	// authenticated route/principal, never client fields.
	Purpose              string
	DeviceID             string
	DataDictionaryDigest string
	SchemaVersion        string
	ConsentGeneration    int64
	DeclaredTimezone     string
	// Contribution.
	CohortKey     string
	MetricID      string
	MetricVersion int
	WindowID      string
	Value         float64
	// Now seeds the grant registration's timestamps only. The WINDOW currency
	// decision is DB-clock authoritative (Sol N4), never this value.
	Now time.Time
}

// AdmitCommunityContributionResult reports the admission outcome. GrantAction is
// the registration branch ("created"/"updated"/"unchanged") on success.
// CurrentWindow is the DB-authoritative current window (always set once the fence
// passes). On ErrCrossDeviceConflict, OwnerDeviceID + NextWindow carry the Sol F9
// recovery hint.
type AdmitCommunityContributionResult struct {
	GrantAction   string
	CurrentWindow string
	OwnerDeviceID string
	NextWindow    string
}

// AdmitCommunityContribution is the ONE admission transaction for a community
// contribution (Sol N3 + N4 + F7). In a SINGLE tenant transaction it, in order:
//
//  1. fences the account FOR SHARE (ErrAccountClosed if not active) — taken
//     FIRST so it serializes against account deletion;
//  2. reads the DB-authoritative current window and refuses anything else
//     (ErrWindowNotCurrent) — the DB clock, not the API/store Go clocks;
//  3. takes the (account, device, purpose) advisory lock and validates/registers
//     the standing grant (registerCommunityGrantTx);
//  4. performs the device-guarded contribution upsert (upsertContributionTx).
//
// ANY refusal after step 1 returns an error, which rolls the WHOLE transaction
// back — so a grant is NEVER created or advanced by a request whose contribution
// is then refused (the split-transaction defect Sol N3 flagged: a cross-device
// conflict or a post-authenticate deletion could otherwise leave a live grant
// behind). The success audit belongs to the caller and fires only on nil error.
func (s *Store) AdmitCommunityContribution(ctx context.Context, accountID string, in AdmitCommunityContributionInput) (AdmitCommunityContributionResult, error) {
	if in.Now.IsZero() {
		in.Now = time.Now()
	}
	// Defensive cohort check at the boundary (the API validates too); an unknown
	// cohort can never be stored and never advances a grant.
	if !community.ValidCohort(in.CohortKey) {
		return AdmitCommunityContributionResult{}, ErrUnknownCohort
	}
	var out AdmitCommunityContributionResult
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		// 1) Account fence FIRST (serializes with deletion).
		if e := fenceAccountActiveTx(ctx, tx, accountID); e != nil {
			return e
		}
		// 2) DB-authoritative window currency (Sol N4).
		dbWindow, e := dbCurrentWindowTx(ctx, tx)
		if e != nil {
			return e
		}
		out.CurrentWindow = dbWindow
		out.NextWindow = nextWindowAfter(dbWindow)
		if in.WindowID != dbWindow {
			return ErrWindowNotCurrent
		}
		// 3) Advisory lock + grant validate/register, in THIS transaction. A
		// refusal here rolls back with nothing written.
		_, action, e := registerCommunityGrantTx(ctx, tx, accountID, CommunityGrantInput{
			Purpose:              in.Purpose,
			DeviceID:             in.DeviceID,
			DataDictionaryDigest: in.DataDictionaryDigest,
			SchemaVersion:        in.SchemaVersion,
			ConsentGeneration:    in.ConsentGeneration,
			DeclaredTimezone:     in.DeclaredTimezone,
			Now:                  in.Now,
		})
		if e != nil {
			return e
		}
		out.GrantAction = action
		// 4) The contribution upsert. A cross-device conflict (or the DB trigger's
		// current-window backstop) rolls back the grant mutation from step 3 too.
		owner, e := upsertContributionTx(ctx, tx, accountID, in.DeviceID, in.CohortKey, in.MetricID, in.MetricVersion, in.WindowID, in.Value)
		if errors.Is(e, ErrCrossDeviceConflict) {
			out.OwnerDeviceID = owner
			return e
		}
		return e
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrAccountClosed),
			errors.Is(err, ErrWindowNotCurrent),
			errors.Is(err, ErrUnknownCohort),
			errors.Is(err, ErrCrossDeviceConflict),
			errors.Is(err, ErrCommunityGrantRevoked),
			errors.Is(err, ErrCommunityGenerationStale),
			errors.Is(err, ErrCommunityDictionaryMismatch),
			errors.Is(err, ErrCommunityGrantTermsMismatch),
			errors.Is(err, ErrCommunityBindingIncomplete):
			return out, err
		}
		return out, fmt.Errorf("cloudserver/store.AdmitCommunityContribution: %w", err)
	}
	return out, nil
}

// AccountContribution returns the calling account's OWN contributed value for a
// (cohort, metric, version, window), or ErrNotFound if it never contributed. It
// runs tenant-scoped, so RLS ensures an account can only ever read its own value
// — the raw value is never exposed cross-tenant. The own-percentile surface pairs
// this with CommunityBands to show the account where it sits.
func (s *Store) AccountContribution(ctx context.Context, accountID, cohortKey, metricID string, metricVersion int, windowID string) (float64, error) {
	var value float64
	found := false
	err := s.WithAccount(ctx, accountID, func(ctx context.Context, tx pgx.Tx) error {
		e := tx.QueryRow(ctx,
			`SELECT value FROM leaderboard_contributions
			  WHERE account_id = $1::uuid AND cohort_key = $2
			    AND metric_id = $3 AND metric_version = $4 AND window_id = $5`,
			accountID, cohortKey, metricID, metricVersion, windowID).Scan(&value)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.AccountContribution: %w", err)
	}
	if !found {
		return 0, ErrNotFound
	}
	return value, nil
}
