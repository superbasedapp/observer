// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
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
// TRUNCATION IS NOT DELIVERY, AND A TRUNCATED FAMILY PAGES. When a family's
// rows do not all fit the envelope's snapshot budget, fitSnapshot ships the
// undelivered rows that fit and marks the family NOT committable, so the gate
// keeps it dirty. Each composed row is staged for the tick as (natural key,
// digest of its wire JSON); CommitPushedSnapshots records, once the server has
// accepted the batch, the digest the server now holds for each natural key,
// and the family stays OPEN (forced to recompute every tick, past the cadence
// knob and the probe) until a tick composes it completely. The next tick's
// recompute skips every row whose CURRENT digest is the one accepted for its
// key, so the page moves forward instead of re-shipping the same prefix: the defect this replaces cut a deterministic recompute at
// the same row on every push, so the tail never shipped, the family never
// committed, and every push was a full-size envelope (the demo box,
// 2026-10-24, 87 GB of archived 1,127-row session_loc prefixes). Once every row
// of a recompute is delivered the family commits, its delivered set is
// dropped, and it goes quiet until its probe changes or the freshness floor
// starts a new cycle.
//
// Why per natural key and not an offset: the org server applies every snapshot
// family as a per-row upsert by the row's natural key (internal/orgserver/
// ingest; no family is a whole-set replace), so delivering pages in any order
// converges on what one unbounded push would leave. snapNaturalKeys mirrors
// each wire row's server conflict key. A row whose content changed mid-cycle
// has a new digest and ships again; a row that changed A to B and back to A
// ships again too, because the server holds B for that key (a bare digest set
// would have taken A as delivered). A row that only moved within the
// recompute's order (a sliding window) is not skipped by accident, as an
// offset would; and a family that keeps changing still converges as long as
// each tick's changes fit a page. Fields that carry the compose time
// (snapVolatileFields) are left out of the digest, or such a family would look
// changed on every compose and never page.
//
// FAIL-OPEN STILL HOLDS. A tick that composes a family COMPLETELY closes its
// cycle (accepted state dropped) whether or not the probe produced a
// fingerprint to commit, so a family whose probe keeps failing ships on every
// tick, page by page, exactly as it did before paging; it is never silenced. The wire shape is
// unchanged, so an old server sees exactly the prefix-truncated pushes it
// always could.
//
// A row larger than the WHOLE snapshot budget can never ship. It is reported
// once (a warning and OrgSnapshotOversizedRows) and settled for the cycle, so
// it no longer blocks every row behind it or keeps the family open forever.
//
// The paging state lives here, in memory, like the rest of the gate: a restart
// starts a fresh cycle that re-ships the family once, which the server's
// upserts absorb.
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
	// The session quality score wire (BL2-ORG), windowed on scored_at and
	// probed on MAX(scored_at) in sessionqualitysummary.go.
	snapFamSessionQuality snapFamily = "session_quality"
	// Commit ownership (lane F-PROJ), probed in commitownersummary.go over the
	// two source families its fold reads (commits and AI line changes).
	snapFamCommitOwnership snapFamily = "commit_ownership"
	// The two node session-detail trickle-up families (W2/W3). The task wire
	// is ONE recompute feeding TWO slices (items + transitions), so both share
	// snapFamSessionTasks — the benchmark arrangement, not a second family.
	snapFamSessionTasks       snapFamily = "session_tasks"
	snapFamSessionToolAccount snapFamily = "session_tool_accounts"
	// The per-session hook liveness wire (surface-gap DEC-5), probed on
	// MAX(last_at) in hookactivitysummary.go.
	snapFamSessionHookActivity snapFamily = "session_hook_activity"
	// The Agent Access P4 MCP relay activity aggregate (mcprelaysummary.go).
	// The per-record MCPRelayEvents sibling is a CURSOR wire and is not
	// gated.
	snapFamMCPRelayActivity snapFamily = "mcp_relay_activity"
	// The Agent Access P11 (c) shadow-MCP discovery inventory
	// (mcpinventory.go), probed through the host-bound provider seam.
	snapFamMCPInventory snapFamily = "mcp_inventory"
	// The delivery wire (commit to PR to merge, D-689): ONE recompute feeding
	// TWO slices (day counts + raw-gated PR rows), probed in delivery.go.
	snapFamDelivery snapFamily = "delivery"
	// The sandbox posture aggregate (sandbox plan v2 section 8.4,
	// sandboxposture.go): a recompute over terminal_run, so it shares the
	// terminal activity probe with the other terminal wires.
	snapFamSandboxPosture snapFamily = "sandbox_posture"
	// The security pillar wire (security plan 7.4, secorgrows.go): the
	// finding rows and the posture row probe the sec_* tables (the posture
	// also the commit-gate verdicts and the UTC day); the change records
	// (lane SEC-F2A) probe sec_change_records in secchange.go.
	snapFamSecurityFindings      snapFamily = "security_findings"
	snapFamSecurityPosture       snapFamily = "security_posture"
	snapFamSecurityChangeRecords snapFamily = "security_change_records"
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
	snapFamRoutingSummary:        (*Store).probeRouterDecisions,
	snapFamRoutingDetail:         (*Store).probeRouterDecisions,
	snapFamRoutingDev:            (*Store).probeRouterDecisions,
	snapFamCacheSummary:          (*Store).probeCacheEvents,
	snapFamSessionCache:          (*Store).probeCacheEvents,
	snapFamSessionCacheEvents:    (*Store).probeCacheEvents,
	snapFamSessionVerbosity:      (*Store).probeSessionVerbositySubstrate,
	snapFamSessionProcess:        (*Store).probeProcessRuns,
	snapFamProcessSummary:        (*Store).probeProcessRuns,
	snapFamSessionNetwork:        (*Store).probeNetworkEvents,
	snapFamProjectPatterns:       (*Store).probeProjectPatterns,
	snapFamBenchmark:             (*Store).probeBenchmarks,
	snapFamCompressionStats:      (*Store).probeCompressionEvents,
	snapFamCodeintelDev:          (*Store).probeCodeintel,
	snapFamCodeintelSummary:      (*Store).probeCodeintel,
	snapFamTerminalRuns:          (*Store).probeTerminalActivity,
	snapFamTerminalCommands:      (*Store).probeTerminalActivity,
	snapFamTerminalSummary:       (*Store).probeTerminalActivity,
	snapFamRemoteAuditRows:       (*Store).probeRemoteAudit,
	snapFamRemoteAuditSummary:    (*Store).probeRemoteAudit,
	snapFamGuardPins:             (*Store).probeGuardPins,
	snapFamGuardApprovals:        (*Store).probeGuardApprovals,
	snapFamLimitGauge:            (*Store).probeLimitSnapshots,
	snapFamSessionLOC:            (*Store).probeFileChanges,
	snapFamLOCDays:               (*Store).probeFileChanges,
	snapFamSessionQuality:        (*Store).probeSessionQuality,
	snapFamCommitOwnership:       (*Store).probeCommitOwnership,
	snapFamSessionTasks:          (*Store).probeTaskFlow,
	snapFamSessionToolAccount:    (*Store).probeToolAccounts,
	snapFamSessionHookActivity:   (*Store).probeHookActivity,
	snapFamMCPRelayActivity:      (*Store).probeMCPRelayRecords,
	snapFamMCPInventory:          (*Store).probeMCPInventory,
	snapFamDelivery:              (*Store).probeDelivery,
	snapFamSandboxPosture:        (*Store).probeTerminalActivity,
	snapFamSecurityFindings:      (*Store).probeSecFindings,
	snapFamSecurityPosture:       (*Store).probeSecPosture,
	snapFamSecurityChangeRecords: (*Store).probeSecChangeRecords,
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
	// accepted maps each natural key the server has ACCEPTED during the
	// current, not yet closed, delivery cycle to the digest it accepted; open
	// is true while the cycle is open. tick holds what this tick composed (or
	// settled as oversized), promoted into accepted by commit(); seen is this
	// tick's natural keys (a repeat means a key coarser than the server's, and
	// falls back to the digest). ticked/complete record whether this tick
	// recomputed the family and composed every row of it. oversized remembers
	// the rows already reported as larger than the whole budget (bounded).
	accepted  map[string]snapRowKey
	tick      []snapStaged
	seen      map[string]struct{}
	ticked    bool
	complete  bool
	open      bool
	oversized map[snapRowKey]struct{}
	// obs is what the current compose learned about rows larger than the
	// whole budget (met whether or not reported before): kept from the tick's
	// start until the next compose begins, so persistOrgPushOversized can
	// fold it into the persisted report before or after the commit.
	obs snapOversizeObservation
}

// snapTickOversize is one tick's oversized-row observation for a family.
type snapTickOversize struct {
	rows, largest, budget int64
}

// snapRowKey is a digest of one composed row: its wire type and its wire JSON
// (less snapVolatileFields).
type snapRowKey [16]byte

// snapStaged is one row a tick composed: its natural key and digest.
type snapStaged struct {
	id string
	d  snapRowKey
}

// snapOversizedRemembered bounds each family's memory of reported oversized
// rows; past it a row may be reported again, never looped on.
const snapOversizedRemembered = 1024

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
	oversized   map[snapFamily]int64
}

// newSnapGate returns a gate with the freshness floor set and no cadence
// throttle (the push loop installs its own via setMinInterval).
func newSnapGate() *snapGate {
	return &snapGate{
		maxSkipAge: snapGateDefaultMaxSkipAge,
		entries:    map[snapFamily]*snapEntry{},
		skipped:    map[snapFamily]int64{},
		recomputes: map[snapFamily]int64{},
		oversized:  map[snapFamily]int64{},
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
	open := e.open
	minInterval := g.minInterval
	maxSkipAge := g.effectiveMaxSkipAgeLocked()
	g.mu.Unlock()

	// Lever 1 — freshness floor. Also covers a clock that moved backwards
	// (age < 0): rather than trust a negative age, recompute. An OPEN family
	// (part of its rows accepted, the rest still owed) is treated the same:
	// its next page is due now, whatever the cadence or the probe says.
	overdue := first || open || age < 0 || age >= maxSkipAge

	// Lever 2 — cadence knob. Checked before the probe so a throttled tick
	// costs no SQL at all.
	if !overdue && age < minInterval {
		return g.note(fam, false)
	}
	// Every path below recomputes: this tick's page starts empty, and the
	// family counts as composed completely until fitSnapshot says otherwise.
	g.mu.Lock()
	e = g.entryLocked(fam)
	e.tick, e.seen, e.ticked, e.complete = nil, nil, true, true
	e.obs = snapOversizeObservation{ticked: true, complete: true}
	g.mu.Unlock()

	probe := snapProbes[fam]
	if probe == nil {
		// Unregistered family: keep today's behaviour exactly.
		return g.note(fam, true)
	}
	fp, err := probe(s, ctx)
	if err != nil {
		// Fail toward recompute, and record nothing to commit so the family
		// stays dirty until a probe succeeds. A complete compose still closes
		// the paging cycle (commit), so the next tick ships the family again.
		return g.note(fam, true)
	}
	if !overdue && fp == committed {
		// Not recomputed after all: this compose learned nothing about the
		// family, so it must not count as a (complete) look at its rows.
		g.mu.Lock()
		e = g.entryLocked(fam)
		e.ticked, e.complete, e.obs = false, false, snapOversizeObservation{}
		g.mu.Unlock()
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
	e := g.entryLocked(fam)
	e.committable, e.complete, e.obs.complete = false, false, false
}

// commit promotes every committable pending fingerprint. Called only after the
// server has accepted the batch (or when there was nothing to send).
//
// A family that composed COMPLETELY closes its cycle and drops its accepted
// state, and commits its fingerprint when the probe produced one (a failing
// probe closes the cycle without a commit, so the family recomputes and ships
// again next tick: fail-open). One that did not records what this tick shipped
// as accepted and stays open, so the next tick ships the next page.
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
		switch {
		case e.ticked && e.complete:
			e.accepted, e.open = nil, false
		case len(e.tick) > 0:
			if e.accepted == nil {
				e.accepted = make(map[string]snapRowKey, len(e.tick))
			}
			for _, r := range e.tick {
				e.accepted[r.id] = r.d
			}
			e.open = true
		}
		// Clear the per-tick state either way: a fingerprint that was not
		// committable this cycle must not be promoted by a later commit. The
		// oversize observation (obs) stays until the next compose starts, so
		// the report can be persisted before or after the commit.
		e.pending, e.hasPending, e.committable = "", false, false
		e.tick, e.seen, e.ticked, e.complete = nil, nil, false, false
	}
}

// beginCompose discards every family's per-tick state at the start of a
// compose, so a tick whose push failed (no commit) can never have its staged
// rows or fingerprint promoted by a LATER push that did not carry them.
func (g *snapGate) beginCompose() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range g.entries {
		e.pending, e.hasPending, e.committable = "", false, false
		e.tick, e.seen, e.ticked, e.complete = nil, nil, false, false
		e.obs = snapOversizeObservation{}
	}
}

// resolve returns the row's paging identity for this tick and whether the
// server already holds exactly this digest for it. A natural key seen twice
// in one tick is coarser than the server's (two server rows): with mark, the
// repeat falls back to key plus digest, which can only cost a re-send, never a
// skip. Without mark (a scan's pre-check) it only looks.
func (g *snapGate) resolve(fam snapFamily, id string, d snapRowKey, mark bool) (string, bool) {
	if g == nil {
		return id, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entryLocked(fam)
	if mark {
		if e.seen == nil {
			e.seen = map[string]struct{}{}
		}
		if _, dup := e.seen[id]; dup {
			id += "\x00#" + hex.EncodeToString(d[:])
		}
		e.seen[id] = struct{}{}
	}
	got, ok := e.accepted[id]
	return id, ok && got == d
}

// stage records a row this tick composed for fam.
func (g *snapGate) stage(fam snapFamily, id string, d snapRowKey) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	e := g.entryLocked(fam)
	e.tick = append(e.tick, snapStaged{id: id, d: d})
}

// oversize settles a row that is larger than the whole snapshot budget (it can
// never ship; stage is false when the row is already settled in the open
// cycle), records it in this tick's observation (every time it is met, which
// is what keeps the persisted report for org status and doctor current), and
// warns the first time this process sees it.
func (g *snapGate) oversize(fam snapFamily, id string, k snapRowKey, rowBytes, limit int64, stage bool) {
	report := true
	if g != nil {
		g.mu.Lock()
		e := g.entryLocked(fam)
		if stage {
			e.tick = append(e.tick, snapStaged{id: id, d: k})
		}
		e.obs.rows++
		e.obs.largest = max(e.obs.largest, rowBytes)
		e.obs.budget = limit
		if _, seen := e.oversized[k]; seen {
			report = false
		} else {
			if e.oversized == nil || len(e.oversized) >= snapOversizedRemembered {
				e.oversized = map[snapRowKey]struct{}{}
			}
			e.oversized[k] = struct{}{}
			g.oversized[fam]++
		}
		g.mu.Unlock()
	}
	if report {
		slog.Default().Warn("org push: a snapshot row is larger than the whole snapshot budget and cannot ship; skipped",
			"family", string(fam), "row_bytes", rowBytes, "snapshot_budget_bytes", limit,
			"hint", "raise [org_client] max_push_bytes to ship it")
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

// oversizedCounts returns a copy of the per-family oversized-row tallies.
func (g *snapGate) oversizedCounts() map[string]int64 {
	out := map[string]int64{}
	if g == nil {
		return out
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for fam, n := range g.oversized {
		out[string(fam)] = n
	}
	return out
}

// snapOversizeObservation is what one compose learned about a family's
// oversized rows: whether it recomputed the family at all, whether it looked
// at every row (complete), and what it met.
type snapOversizeObservation struct {
	ticked, complete bool
	snapTickOversize
}

// oversizeObservations returns this compose's per-family observations.
func (g *snapGate) oversizeObservations() map[snapFamily]snapOversizeObservation {
	out := map[snapFamily]snapOversizeObservation{}
	if g == nil {
		return out
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	for fam, e := range g.entries {
		out[fam] = e.obs
	}
	return out
}

// snapRowState is one composed row as paging sees it.
type snapRowState struct {
	// id is the row's natural key (snapNaturalKeys), or its digest for a type
	// without one.
	id    string
	key   snapRowKey
	bytes int64
	// ok is false when the row could not be marshalled; such a row is never
	// staged or skipped (jsonSize's historical zero-cost treatment).
	ok bool
}

// snapRow marshals one row once for its budget size, and derives its paging
// digest and natural key.
func snapRow[T any](row T) snapRowState { return snapRowValue(reflect.ValueOf(row)) }

// snapRowValue is snapRow over a reflected row value.
func snapRowValue(rv reflect.Value) snapRowState {
	raw, err := json.Marshal(rv.Interface())
	if err != nil {
		return snapRowState{}
	}
	t := rv.Type()
	tag := t.String()
	digestOf := raw
	if volatile := snapVolatileFields[t]; len(volatile) > 0 && rv.Kind() == reflect.Struct {
		cp := reflect.New(t).Elem()
		cp.Set(rv)
		for _, f := range volatile {
			cp.FieldByName(f).SetZero()
		}
		if digestOf, err = json.Marshal(cp.Interface()); err != nil {
			return snapRowState{}
		}
	}
	h := sha256.New()
	_, _ = h.Write([]byte(tag))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(digestOf)
	var k snapRowKey
	copy(k[:], h.Sum(nil))
	id := tag + "\x00#" + hex.EncodeToString(k[:])
	if fields := snapNaturalKeys[t]; len(fields) > 0 && rv.Kind() == reflect.Struct {
		var b strings.Builder
		b.WriteString(tag)
		for _, f := range fields {
			b.WriteByte(0)
			b.WriteString(snapKeyPart(rv.FieldByName(f)))
		}
		id = b.String()
	}
	return snapRowState{id: id, key: k, bytes: int64(len(raw)), ok: true}
}

// snapKeyPart renders one natural-key field. Key fields are strings, integers
// and booleans; anything else falls back to its JSON.
func snapKeyPart(v reflect.Value) string {
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	default:
		raw, _ := json.Marshal(v.Interface())
		return string(raw)
	}
}

// fitSnapshot is fitRows plus the Track R2 gate bookkeeping and snapshot
// PAGING (see the file comment): it skips rows the server already accepted in
// this family's open cycle, settles (and reports) rows that can never fit,
// ships the next undelivered rows that fit the remaining snapshot budget,
// stages them for commit, and records whether the family composed COMPLETELY
// so a truncated one stays dirty. Every gated snapshot wire goes through this
// instead of bare fitRows; the ungated ones (the advisor and obs provider
// tiers) keep using fitRows directly.
//
// Rows are still taken in the owning SELECT's order and the page stops at the
// first owed row that does not fit, so the priority each wire's ORDER BY
// expresses (most-recent-first for the windowed wires) is unchanged.
func fitSnapshot[T any](s *Store, b *envelopeBudget, fam snapFamily, rows []T) []T {
	var kept []T
	complete, skipped := true, false
	for i := range rows {
		st := snapRow(rows[i])
		if !st.ok {
			kept = append(kept, rows[i])
			continue
		}
		id, settled := s.snap.resolve(fam, st.id, st.key, true)
		if st.bytes > b.snapshotLimit {
			// Observed on every compose that meets it, settled or not.
			s.snap.oversize(fam, id, st.key, st.bytes, b.snapshotLimit, !settled)
			skipped = true
			continue
		}
		if settled {
			skipped = true
			continue
		}
		if b.est+st.bytes > b.snapshotLimit {
			complete = false
			break
		}
		b.est += st.bytes
		kept = append(kept, rows[i])
		s.snap.stage(fam, id, st.key)
	}
	s.snap.recomputed(fam, complete)
	if complete && !skipped {
		// The common case keeps the caller's slice exactly as before.
		return rows
	}
	return kept
}

// snapSkipRow is fitSnapshot's per-row skip rule for a selector that bounds
// its own scan (the network events wire): true when the row is already
// delivered in fam's open cycle, or can never fit and has just been settled
// and reported. Such a row must not count against the scan's byte ceiling, or
// the scan would stop at the same place on every tick.
//
// It only looks (no tick bookkeeping), so fitSnapshot's own pass over the rows
// the scan kept resolves each of them exactly once.
func snapSkipRow[T any](s *Store, b *envelopeBudget, fam snapFamily, row T) bool {
	st := snapRow(row)
	if !st.ok {
		return false
	}
	id, settled := s.snap.resolve(fam, st.id, st.key, false)
	if st.bytes > b.snapshotLimit {
		s.snap.oversize(fam, id, st.key, st.bytes, b.snapshotLimit, !settled)
		return true
	}
	return settled
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
//
// The AgentConfigState change digest (agentconfigorg.go) follows the same
// commit-on-success rule and is promoted here too, as is the AI tool
// configuration inventory digest (agentconfiginventory.go).
func (s *Store) CommitPushedSnapshots() {
	s.snap.commit(time.Now().UTC())
	s.commitAgentConfigDigest()
	s.commitComponentPostureDigest()
	s.commitAgentConfigInventory()
}

// OrgSnapshotGateStats returns the per-family skip / recompute tallies since
// process start, for diagnostics and tests.
func (s *Store) OrgSnapshotGateStats() (skipped, recomputed map[string]int64) {
	return s.snap.counters()
}

// OrgSnapshotOversizedRows returns, per snapshot family, how many distinct
// rows since process start were larger than the whole snapshot budget
// ([org_client] max_push_bytes minus the envelope reserve) and so could not
// ship. Each is also logged once as a warning.
func (s *Store) OrgSnapshotOversizedRows() map[string]int64 {
	return s.snap.oversizedCounts()
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
