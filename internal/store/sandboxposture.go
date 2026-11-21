package store

import (
	"context"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// The sandbox posture aggregate (sandbox plan v2 section 8.4, phase P1a).
// This file, not orgpush.go, owns the terminal_run read for it (the privacy
// sentinel forbids that table name in orgpush.go); orgpush.go composes it
// through composeSandboxPosture, the BudgetPosture pattern.
//
// Two halves:
//   - SelectSandboxPostureRows: per (day x isolation_class x capture_level x
//     capture_origin x verification x native_sandbox_state x key_custody)
//     run counts over the G19 columns (migration 179). Content-free: never a
//     run id, a session id, a tool, a path or a hash.
//   - the capability: which floors this node can meet now, a LIVE fact from
//     the sandbox module's probe, so it is a func seam bound by the cmd layer
//     only while the Sandboxes and VMs module is active.
//
// Both ship only under the terminal_detail tier AND only while the
// capability provider is bound: with the module inactive nothing is
// composed. Note (lane sbx-p2, P-017 (i)): an install with no [components]
// block resolves the module ACTIVE (it is on in the developer distro), so
// such a node does push these rows. That is why both stay content-free:
// closed enums, counts and booleans only, pinned field by field by
// tests/invariant/privacy_test.go and clamped again at org ingest.

// sandboxPostureWindowDays bounds the aggregate like the terminal summaries.
const sandboxPostureWindowDays = terminalSummaryWindowDays

// SandboxCapabilityProvider returns this node's current sandbox capability.
// ok=false means nothing to report.
type SandboxCapabilityProvider func() (orgcontract.SandboxCapabilityRow, bool)

// SetSandboxCapabilityProvider wires the capability seam; the cmd layer binds
// it only while the Sandboxes and VMs module is active. nil unbinds it, and
// with it the whole posture aggregate.
func (s *Store) SetSandboxCapabilityProvider(p SandboxCapabilityProvider) { s.sandboxCapability = p }

// SelectSandboxPostureRows aggregates terminal_run's isolation evidence into
// the per-day posture buckets. Runs that recorded no evidence (rows from
// before migration 179) are left out. Each bucket carries its runs split by
// the seccomp state they recorded (migration 232, lane FU4) as counts, not
// as a key, so the bucket is the one it always was.
func (s *Store) SelectSandboxPostureRows(ctx context.Context) ([]orgcontract.SandboxPostureRow, error) {
	since := time.Now().UTC().AddDate(0, 0, -sandboxPostureWindowDays)
	rows, err := s.db.QueryContext(ctx, `
		SELECT substr(launched_at, 1, 10) AS day, isolation_class, capture_level, capture_origin,
		       verification, native_sandbox_state, key_custody, seccomp, COUNT(*)
		FROM terminal_run
		WHERE launched_at >= ? AND (isolation_class != '' OR capture_level != '' OR capture_origin != '')
		GROUP BY day, isolation_class, capture_level, capture_origin, verification, native_sandbox_state, key_custody, seccomp
		ORDER BY day, isolation_class, capture_level, capture_origin, verification, native_sandbox_state, key_custody, seccomp`,
		timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.SelectSandboxPostureRows: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := []orgcontract.SandboxPostureRow{}
	for rows.Next() {
		var r orgcontract.SandboxPostureRow
		var seccomp string
		if err := rows.Scan(&r.Day, &r.IsolationClass, &r.CaptureLevel, &r.CaptureOrigin,
			&r.Verification, &r.NativeSandboxState, &r.KeyCustody, &seccomp, &r.Runs); err != nil {
			return nil, fmt.Errorf("store.SelectSandboxPostureRows: scan: %w", err)
		}
		out = foldSandboxPostureSeccomp(out, r, seccomp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SelectSandboxPostureRows: %w", err)
	}
	return out, nil
}

// foldSandboxPostureSeccomp adds one (bucket, seccomp) count to out: the
// rows arrive ordered by bucket, so a row of the same bucket as the last
// one adds to it. A recorded state goes into the split; "" (not recorded)
// counts only in Runs.
func foldSandboxPostureSeccomp(out []orgcontract.SandboxPostureRow, r orgcontract.SandboxPostureRow, seccomp string) []orgcontract.SandboxPostureRow {
	// Only the closed vocabulary leaves the node; anything else in the
	// column counts as not recorded.
	if !sandboxvocab.SeccompRun(seccomp).Valid() {
		seccomp = ""
	}
	if n := len(out); n > 0 && sameSandboxPostureBucket(out[n-1], r) {
		out[n-1].Runs += r.Runs
		if seccomp != "" {
			if out[n-1].Seccomp == nil {
				out[n-1].Seccomp = map[string]int64{}
			}
			out[n-1].Seccomp[seccomp] += r.Runs
		}
		return out
	}
	if seccomp != "" {
		r.Seccomp = map[string]int64{seccomp: r.Runs}
	}
	return append(out, r)
}

// sameSandboxPostureBucket reports whether two rows share every key field.
func sameSandboxPostureBucket(a, b orgcontract.SandboxPostureRow) bool {
	return a.Day == b.Day && a.IsolationClass == b.IsolationClass && a.CaptureLevel == b.CaptureLevel &&
		a.CaptureOrigin == b.CaptureOrigin && a.Verification == b.Verification &&
		a.NativeSandboxState == b.NativeSandboxState && a.KeyCustody == b.KeyCustody
}

// composeSandboxPosture resolves the capability and, when the posture family
// changed, the day rows for one push envelope. It returns nothing while the
// capability seam is unbound (module inactive) or reports nothing.
func (s *Store) composeSandboxPosture(ctx context.Context, budget *envelopeBudget, orgID, userEmail string) ([]orgcontract.SandboxPostureRow, *orgcontract.SandboxCapabilityRow, error) {
	if s.sandboxCapability == nil {
		return nil, nil, nil
	}
	capRow, ok := s.sandboxCapability()
	if !ok {
		return nil, nil, nil
	}
	var days []orgcontract.SandboxPostureRow
	if s.snapChanged(ctx, snapFamSandboxPosture) {
		rows, err := s.SelectSandboxPostureRows(ctx)
		if err != nil {
			return nil, nil, err
		}
		for i := range rows {
			rows[i].OrgID, rows[i].UserEmail = orgID, userEmail
		}
		days = fitSnapshot(s, budget, snapFamSandboxPosture, rows)
	}
	capRow.OrgID, capRow.UserEmail = orgID, userEmail
	return days, &capRow, nil
}
