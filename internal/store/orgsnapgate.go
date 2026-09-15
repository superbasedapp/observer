// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// orgsnapgate.go is Track R2 of the steady-state CPU remediation
// (docs/plans/observer-steady-state-cpu-remediation-plan-2026-08-26.md), the
// systemic answer to the audit's §6 finding: every SNAPSHOT wire family in
// orgpush.go re-runs its full window/whole-table recompute on EVERY push tick,
// independent of change rate. Track R1 made the three worst recomputes cheap;
// it did not change the invariant that the whole family runs O(window) work per
// tick forever, and grows with each new wire.
//
// The gate is a per-daemon, IN-MEMORY change-detection layer with three levers,
// applied in this order:
//
//  1. Freshness floor (maxSkipAge). A family that has not been recomputed for
//     this long is ALWAYS recomputed, however clean its probe looks. This is
//     what keeps a skipped family's server-side `pushed_at` advancing: two
//     rollup reads (rollup.CodeintelForUser / rollup.DevCodeintel and
//     rollup.AdvisorFleet) window on `pushed_at`, so a family that stops being
//     re-pushed for longer than the dashboard window silently renders as
//     missing even though the server never deleted the row. The floor is
//     deliberately an hour against day-scale dashboard windows.
//  2. Cadence knob (minInterval, [org_client] snapshot_interval_seconds). A
//     family recomputes at most this often EVEN WHEN DIRTY, bounding worst-case
//     CPU on a constantly-changing node where the probe never skips. Owned by
//     the push loop (orgclient sets it via Store.SetOrgSnapshotInterval); the
//     store only applies it.
//  3. Change probe. A cheap per-source-family fingerprint (typically a
//     COALESCE(MAX(id),0) index-endpoint seek) compared against the value
//     recorded at the last SUCCESSFUL push. Equal → skip.
//
// FAIL-OPEN BY CONSTRUCTION (plan constraint 4). Every uncertain path degrades
// to "recompute", which is today's behaviour: a nil gate, an unregistered
// family, a probe error, a never-committed family, and a clock that moved
// backwards all return true. Nothing here can ever degrade to "silently ship
// nothing".
//
// COMMIT-ON-SUCCESS. A recompute records a PENDING fingerprint; only
// Store.CommitPushedSnapshots (called by orgclient.PushOnce after the server
// accepts the batch, and on the empty-batch path where there is nothing to
// deliver) promotes pending → committed. A failed push therefore leaves every
// family dirty and the next tick recomposes it — the batch the server never saw
// is never treated as delivered.
//
// TRUNCATION IS NOT DELIVERY. fitRows may keep only a PREFIX of a family's rows
// when the envelope budget runs out; the dropped tail is re-composed on the next
// tick (that is what makes truncation safe — see fitRows' doc comment). A
// truncated family is therefore marked NOT committable, so the gate keeps it
// dirty and the tail actually ships. Wiring a snapshot wire through
// fitSnapshot rather than bare fitRows is what enforces this.
//
// PRIVACY / MODULE BOUNDARY. This file names NO source table. Each family's
// probe SQL lives in that family's own Select* file — the same one-owner
// discipline orgpush.go follows — and reaches the DB through snapProbeScalar
// below. orgpush.go itself only ever references the snapFamily identifiers, so
// tests/invariant/privacy_test.go's source-level sentinel is untouched.

// snapFamily identifies one snapshot wire family for change detection. The
// values are wire-family names, never table names.
type snapFamily string

const (
	snapFamRoutingSummary     snapFamily = "routing_summary"
	snapFamRoutingDetail      snapFamily = "routing_detail"
	snapFamRoutingDev         snapFamily = "routing_dev"
	snapFamCacheSummary       snapFamily = "cache_summary"
	snapFamSessionCache       snapFamily = "session_cache"
	snapFamSessionCacheEvents snapFamily = "session_cache_events"
	snapFamSessionVerbosity   snapFamily = "session_verbosity"
	snapFamSessionProcess     snapFamily = "session_process"
	snapFamSessionNetwork     snapFamily = "session_network"
	snapFamProcessSummary     snapFamily = "process_summary"
	snapFamProjectPatterns    snapFamily = "project_patterns"
	snapFamBenchmark          snapFamily = "benchmark"
	snapFamCompressionStats   snapFamily = "compression_stats"
	snapFamCodeintelDev       snapFamily = "codeintel_dev"
	snapFamCodeintelSummary   snapFamily = "codeintel_summary"
	snapFamTerminalRuns       snapFamily = "terminal_runs"
	snapFamTerminalCommands   snapFamily = "terminal_commands"
	snapFamRemoteAuditRows    snapFamily = "remote_audit_rows"
	snapFamTerminalSummary    snapFamily = "terminal_summary"
	snapFamRemoteAuditSummary snapFamily = "remote_audit_summary"
	snapFamGuardPins          snapFamily = "guard_pins"
	snapFamGuardApprovals     snapFamily = "guard_approvals"
	snapFamLimitGauge         snapFamily = "limit_gauge"
	// The two Lines-of-Code wire families (docs/plans/
	// lines-of-code-tracking-plan-2026-09-07.md §3.4). They share one probe
	// because they read one source family, exactly like the three
	// router_decisions-backed wires above.
	snapFamSessionLOC snapFamily = "session_loc"
	snapFamLOCDays    snapFamily = "loc_days"
	// The two node session-detail trickle-up families (W2/W3). The task wire
	// is ONE recompute feeding TWO slices (items + transitions), so both share
	// snapFamSessionTasks — the benchmark arrangement, not a second family.
	snapFamSessionTasks       snapFamily = "session_tasks"
	snapFamSessionToolAccount snapFamily = "session_tool_accounts"
)

// snapProbes is the family → probe registry (CLAUDE.md #5: a decision table,
// not a switch ladder). Each probe is a method on *Store declared in the
// family's OWN file, so every source-table name stays with its one owner.
//
// Families sharing a source table share one probe by design — router_decisions
// feeds three wires, cache_events three (the fleet day aggregate, the session
// bucket and the per-event timeline), process_runs/process_events two. They
// stay SEPARATE families with one shared probe rather than one family: each is
// its own independently truncatable slice, and a shared gate entry would let a
// truncation of one keep the others dirty forever.
//
// DELIBERATELY ABSENT: the advisor wire (SelectAdvisorSuggestionRows). It is
// not a SQL recompute at all — it is a snapshot of the injected
// AdvisorOrgProvider, whose inputs span the advisor digest, advisor_state and
// most of the node's substrate. No cheap probe over that surface would be
// honest, and it is one of the two families whose rollup read windows on
// `pushed_at`, so a wrong skip is directly visible on the org dashboard. It
// therefore keeps today's every-tick behaviour. The obs provider tiers are
// absent for the same reason: internal/obs owns those reads.
var snapProbes = map[snapFamily]func(*Store, context.Context) (string, error){
	snapFamRoutingSummary:     (*Store).probeRouterDecisions,
	snapFamRoutingDetail:      (*Store).probeRouterDecisions,
	snapFamRoutingDev:         (*Store).probeRouterDecisions,
	snapFamCacheSummary:       (*Store).probeCacheEvents,
	snapFamSessionCache:       (*Store).probeCacheEvents,
	snapFamSessionCacheEvents: (*Store).probeCacheEvents,
	snapFamSessionVerbosity:   (*Store).probeSessionVerbositySubstrate,
	snapFamSessionProcess:     (*Store).probeProcessRuns,
	snapFamProcessSummary:     (*Store).probeProcessRuns,
	snapFamSessionNetwork:     (*Store).probeNetworkEvents,
	snapFamProjectPatterns:    (*Store).probeProjectPatterns,
	snapFamBenchmark:          (*Store).probeBenchmarks,
	snapFamCompressionStats:   (*Store).probeCompressionEvents,
	snapFamCodeintelDev:       (*Store).probeCodeintel,
	snapFamCodeintelSummary:   (*Store).probeCodeintel,
	snapFamTerminalRuns:       (*Store).probeTerminalActivity,
	snapFamTerminalCommands:   (*Store).probeTerminalActivity,
	snapFamTerminalSummary:    (*Store).probeTerminalActivity,
	snapFamRemoteAuditRows:    (*Store).probeRemoteAudit,
	snapFamRemoteAuditSummary: (*Store).probeRemoteAudit,
	snapFamGuardPins:          (*Store).probeGuardPins,
	snapFamGuardApprovals:     (*Store).probeGuardApprovals,
	snapFamLimitGauge:         (*Store).probeLimitSnapshots,
	snapFamSessionLOC:         (*Store).probeFileChanges,
	snapFamLOCDays:            (*Store).probeFileChanges,
	snapFamSessionTasks:       (*Store).probeTaskFlow,
	snapFamSessionToolAccount: (*Store).probeToolAccounts,
}

// snapGateDefaultMaxSkipAge is the freshness floor: the longest a clean family
// may go without a recompute. An hour is chosen against the org rollups'
// DAY-scale windows (rollup.DefaultWindowDays is 30, and the narrowest
// selectable window is a day), so a skipped family's `pushed_at` can never age
// out of a dashboard window. At the default 120 s push cadence it still means
// ~29 of every 30 ticks skip.
const snapGateDefaultMaxSkipAge = time.Hour

// snapEntry is one family's gate state.
type snapEntry struct {
	// committed is the fingerprint as of the last SUCCESSFUL push, and
	// committedAt when that push was accepted. A zero committedAt means the
	// family has never been delivered, so it always recomputes.
	committed   string
	committedAt time.Time
	// pending is this tick's fingerprint, promoted by commit(). hasPending is
	// false when the probe failed (nothing trustworthy to record); committable
	// is false when the composed wire was TRUNCATED by the envelope budget and
	// therefore still owes the server its tail.
	pending     string
	hasPending  bool
	committable bool
}

// snapGate is the per-daemon, in-memory change-detection state. Losing it on
// restart costs exactly one full recompute on the first tick, which is today's
// every-tick behaviour — that is why it is deliberately not persisted (plan:
// "no new state corruption class").
type snapGate struct {
	mu          sync.Mutex
	minInterval time.Duration
	maxSkipAge  time.Duration
	entries     map[snapFamily]*snapEntry
	skipped     map[snapFamily]int64
	recomputes  map[snapFamily]int64
}

// newSnapGate returns a gate with the freshness floor set and no cadence
// throttle (the push loop installs its own via setMinInterval).
func newSnapGate() *snapGate {
	return &snapGate{
		maxSkipAge: snapGateDefaultMaxSkipAge,
		entries:    map[snapFamily]*snapEntry{},
		skipped:    map[snapFamily]int64{},
		recomputes: map[snapFamily]int64{},
	}
}

// setMinInterval installs the Lever-2 cadence. A non-positive value disables
// the throttle (every dirty family recomputes on every tick).
func (g *snapGate) setMinInterval(d time.Duration) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if d < 0 {
		d = 0
	}
	g.minInterval = d
}

// effectiveMaxSkipAgeLocked is the freshness floor, never shorter than the
// operator's own cadence — an operator who deliberately sets a slower
// snapshot_interval_seconds than the floor gets what they asked for rather than
// a floor that silently re-forces the fast cadence.
func (g *snapGate) effectiveMaxSkipAgeLocked() time.Duration {
	if g.minInterval > g.maxSkipAge {
		return g.minInterval
	}
	return g.maxSkipAge
}

// entryLocked returns fam's state, creating it on first sight.
func (g *snapGate) entryLocked(fam snapFamily) *snapEntry {
	e := g.entries[fam]
	if e == nil {
		e = &snapEntry{}
		g.entries[fam] = e
	}
	return e
}

// changed reports whether fam's snapshot must be recomputed this tick. See the
// file doc comment for the ordered levers; every uncertain answer is true.
func (g *snapGate) changed(ctx context.Context, s *Store, fam snapFamily, now time.Time) bool {
	if g == nil || s == nil {
		return true
	}
	g.mu.Lock()
	e := g.entryLocked(fam)
	first := e.committedAt.IsZero()
	age := now.Sub(e.committedAt)
	committed := e.committed
	minInterval := g.minInterval
	maxSkipAge := g.effectiveMaxSkipAgeLocked()
	g.mu.Unlock()

	// Lever 1 — freshness floor. Also covers a clock that moved backwards
	// (age < 0): rather than trust a negative age, recompute.
	overdue := first || age < 0 || age >= maxSkipAge

	// Lever 2 — cadence knob. Checked before the probe so a throttled tick
	// costs no SQL at all.
	if !overdue && age < minInterval {
		return g.note(fam, false)
	}

	probe := snapProbes[fam]
	if probe == nil {
		// Unregistered family: keep today's behaviour exactly.
		return g.note(fam, true)
	}
	fp, err := probe(s, ctx)
	if err != nil {
		// Fail toward recompute, and record nothing to commit so the family
		// stays dirty until a probe succeeds.
		return g.note(fam, true)
	}
	if !overdue && fp == committed {
		return g.note(fam, false)
	}
	g.mu.Lock()
	e = g.entryLocked(fam)
	e.pending, e.hasPending, e.committable = fp, true, true
	g.mu.Unlock()
	return g.note(fam, true)
}

// note records the decision in the counters and returns it.
func (g *snapGate) note(fam snapFamily, recompute bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if recompute {
		g.recomputes[fam]++
	} else {
		g.skipped[fam]++
	}
	return recompute
}

// recomputed records how a recomputed family actually composed. complete=false
// means the envelope budget truncated it, so the family keeps owing the server
// its tail and must NOT be committed.
func (g *snapGate) recomputed(fam snapFamily, complete bool) {
	if g == nil || complete {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.entryLocked(fam).committable = false
}

// commit promotes every committable pending fingerprint. Called only after the
// server has accepted the batch (or when there was nothing to send).
func (g *snapGate) commit(now time.Time) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range g.entries {
		if e.hasPending && e.committable {
			e.committed, e.committedAt = e.pending, now
		}
		// Clear the pending slot either way: a fingerprint that was not
		// committable this cycle must not be promoted by a later commit.
		e.pending, e.hasPending, e.committable = "", false, false
	}
}

// counters returns copies of the skip / recompute tallies, keyed by family.
func (g *snapGate) counters() (skipped, recomputed map[string]int64) {
	skipped, recomputed = map[string]int64{}, map[string]int64{}
	if g == nil {
		return skipped, recomputed
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for fam, n := range g.skipped {
		skipped[string(fam)] = n
	}
	for fam, n := range g.recomputes {
		recomputed[string(fam)] = n
	}
	return skipped, recomputed
}

// snapChanged is the ONE call orgpush.go makes per snapshot family.
func (s *Store) snapChanged(ctx context.Context, fam snapFamily) bool {
	return s.snap.changed(ctx, s, fam, time.Now().UTC())
}

// SetOrgSnapshotInterval installs the [org_client] snapshot_interval_seconds
// cadence: no snapshot wire family recomputes more often than this, even when
// its source data changed. The CURSOR wires (sessions/actions/api_turns/
// token_usage/guard_events/otel_content) are unaffected and keep every tick.
//
// The push loop owns this value (internal/orgclient computes it from its own
// config, defaulting to a multiple of push_interval_seconds); the store only
// applies it. A non-positive duration disables the throttle.
func (s *Store) SetOrgSnapshotInterval(d time.Duration) { s.snap.setMinInterval(d) }

// CommitPushedSnapshots marks every snapshot family composed by the last
// SelectUnpushedSince as delivered. orgclient calls it once the org server has
// accepted the batch (and on the empty-batch path, where there is nothing to
// deliver); a failed push must NOT call it, so the next tick recomposes.
func (s *Store) CommitPushedSnapshots() { s.snap.commit(time.Now().UTC()) }

// OrgSnapshotGateStats returns the per-family skip / recompute tallies since
// process start, for diagnostics and tests.
func (s *Store) OrgSnapshotGateStats() (skipped, recomputed map[string]int64) {
	return s.snap.counters()
}

// snapProbeScalar runs a probe query that yields exactly ONE text column and
// returns it as the family's fingerprint. Probes build that column with SQL
// string concatenation so this helper needs no reflection and no per-family
// scan shape — see any probe* method for the pattern.
//
// The query text (and therefore every table name) is supplied by the family's
// own file; this helper deliberately holds none.
func (s *Store) snapProbeScalar(ctx context.Context, query string, args ...any) (string, error) {
	var fp sql.NullString
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&fp); err != nil {
		return "", err
	}
	return fp.String, nil
}
