// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

// This file pins Track R2 — the org-push snapshot change-detection gate
// (internal/store/orgsnapgate.go). Two layers:
//
//   - Unit tests drive snapGate directly through a stub probe, so the ordered
//     levers (freshness floor → cadence knob → change probe), the fail-open
//     paths, and commit-on-success/truncation semantics are each isolated.
//   - Integration tests drive the real SelectUnpushedSince over the same
//     fixture the composed-envelope sentinel uses, proving that a push with no
//     source changes recomposes NOTHING while a dirty family still does.

// snapFamTest is a probe key used only by this file's unit tests. Registering
// it in snapProbes is safe because no wire references it.
const snapFamTest snapFamily = "test_only_family"

// installStubProbe registers a probe for snapFamTest that returns whatever fp
// currently holds (or err), and removes it again at test end. Tests using it
// must NOT be parallel — snapProbes is package state.
func installStubProbe(t *testing.T, fp *string, err *error) {
	t.Helper()
	snapProbes[snapFamTest] = func(*Store, context.Context) (string, error) {
		if *err != nil {
			return "", *err
		}
		return *fp, nil
	}
	t.Cleanup(func() { delete(snapProbes, snapFamTest) })
}

// gatedWireFamilies maps each PushBatch slice field that Track R2 gates to the
// snapFamily guarding it. It is a FIXED expected set, in the style of the
// privacy sentinel's expected-table sets: adding a gated wire means adding a
// row here, and TestSnapGateCoversEveryGatedWire fails by name otherwise.
var gatedWireFamilies = map[string]snapFamily{
	"RoutingSummaries":          snapFamRoutingSummary,
	"CacheSummaries":            snapFamCacheSummary,
	"CodeintelSummaries":        snapFamCodeintelSummary,
	"ProcessSummaries":          snapFamProcessSummary,
	"TerminalSummaries":         snapFamTerminalSummary,
	"RemoteAuditSummaries":      snapFamRemoteAuditSummary,
	"RoutingDetails":            snapFamRoutingDetail,
	"LimitGauges":               snapFamLimitGauge,
	"SessionVerbositySummaries": snapFamSessionVerbosity,
	"SessionCacheSummaries":     snapFamSessionCache,
	// The per-event timeline shares probeCacheEvents with the two aggregates
	// but keeps its OWN family: they are independently truncatable slices, and
	// one shared gate entry would let a truncation of one keep the others
	// permanently dirty.
	"SessionCacheEvents":   snapFamSessionCacheEvents,
	"SessionProcesses":     snapFamSessionProcess,
	"SessionNetworkEvents": snapFamSessionNetwork,
	"ProjectPatterns":      snapFamProjectPatterns,
	"BenchmarkRuns":        snapFamBenchmark,
	"BenchmarkAttempts":    snapFamBenchmark,
	"CompressionStats":     snapFamCompressionStats,
	"RoutingDevRows":       snapFamRoutingDev,
	"CodeintelDevRows":     snapFamCodeintelDev,
	"TerminalRuns":         snapFamTerminalRuns,
	"TerminalCommands":     snapFamTerminalCommands,
	"RemoteAudit":          snapFamRemoteAuditRows,
	"GuardPins":            snapFamGuardPins,
	"GuardApprovals":       snapFamGuardApprovals,
	// Lines-of-Code (W5). Both families share one probe over the single
	// source table, the same arrangement the three router_decisions-backed
	// wires use.
	"SessionLOC": snapFamSessionLOC,
	"LOCDays":    snapFamLOCDays,
	// Node session-detail trickle-up W2/W3. The two task wires share ONE
	// probe over their single source family, the benchmark arrangement.
	"SessionTaskItems":       snapFamSessionTasks,
	"SessionTaskTransitions": snapFamSessionTasks,
	"SessionToolAccounts":    snapFamSessionToolAccount,
}

// ungatedWireFamilies names the wire families that DELIBERATELY keep the
// pre-Track-R2 every-tick behaviour, with the reason. A family may only be
// absent from gatedWireFamilies if it is named here.
var ungatedWireFamilies = map[string]string{
	"AdvisorSuggestions": "snapshot of the injected advisor provider, not a SQL recompute: no honest cheap probe exists over its inputs, and rollup.AdvisorFleet windows on pushed_at",
	// The obs tiers are owned by internal/obs and reached through the provider
	// seam; internal/store cannot probe their tables without breaking the
	// module boundary.
	"ObsSummaries":         "obs provider seam (T1)",
	"ObsTraces":            "obs provider seam (T2)",
	"ObsSpans":             "obs provider seam (T2)",
	"ObsSpanEvents":        "obs provider seam (T2)",
	"ObsContent":           "obs provider seam (T3)",
	"ObsEvalRuns":          "obs provider seam (T4)",
	"ObsEndUserSpend":      "obs provider seam (T5)",
	"ObsAdmissionEvents":   "obs provider seam (T6)",
	"ObsAdmissionPolicies": "obs provider seam (T6)",
	"ObsEvalItems":         "obs provider seam (T7)",
	"ObsEgressDecisions":   "obs provider seam (T8)",
	// Cursor wires are bounded by the fits() guard and read only rows above a
	// persisted watermark — they are already O(new) and must never be gated.
	"Sessions":    "cursor wire",
	"Actions":     "cursor wire",
	"APITurns":    "cursor wire",
	"TokenUsage":  "cursor wire",
	"GuardEvents": "cursor wire",
	"OTelContent": "cursor wire",
}

// TestSnapGateCoversEveryGatedWire is the structural sentinel: every slice
// field of PushBatch must be classified as gated or explicitly ungated, and
// every gated family must have a probe registered. A new snapshot wire that
// silently reintroduces an every-tick recompute fails here BY NAME.
func TestSnapGateCoversEveryGatedWire(t *testing.T) {
	t.Parallel()
	bt := reflect.TypeOf(PushBatch{})
	for i := 0; i < bt.NumField(); i++ {
		f := bt.Field(i)
		if f.Type.Kind() != reflect.Slice {
			continue
		}
		fam, gated := gatedWireFamilies[f.Name]
		_, ungated := ungatedWireFamilies[f.Name]
		switch {
		case gated && ungated:
			t.Errorf("PushBatch.%s is listed as BOTH gated and ungated — pick one", f.Name)
		case !gated && !ungated:
			t.Errorf("PushBatch.%s is a wire family with no Track R2 classification.\n"+
				"Either guard it with s.snapChanged(ctx, <family>) + fitSnapshot in "+
				"internal/store/orgpush.go and register it in gatedWireFamilies here, or record "+
				"WHY it must recompute on every push tick in ungatedWireFamilies. An unclassified "+
				"snapshot wire is the audit §6 defect: O(window) work per tick forever, "+
				"independent of change rate.", f.Name)
		case gated:
			if _, ok := snapProbes[fam]; !ok {
				t.Errorf("PushBatch.%s is gated on family %q but snapProbes has no probe for it — "+
					"the gate would fail open and recompute every tick", f.Name, fam)
			}
		}
	}
	for name := range gatedWireFamilies {
		if _, ok := bt.FieldByName(name); !ok {
			t.Errorf("gatedWireFamilies names %q but PushBatch has no such field", name)
		}
	}
}

// TestSnapGateEveryProbeIsReachable pins the other direction: a probe
// registered for a family no wire uses is dead weight.
func TestSnapGateEveryProbeIsReachable(t *testing.T) {
	t.Parallel()
	used := map[snapFamily]bool{}
	for _, fam := range gatedWireFamilies {
		used[fam] = true
	}
	for fam := range snapProbes {
		if !used[fam] {
			t.Errorf("snapProbes registers family %q that no wire family gates on — "+
				"remove the stale probe or wire the family", fam)
		}
	}
}

func TestSnapGate_FirstSightAlwaysRecomputes(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	s := &Store{}
	now := time.Now().UTC()
	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("a never-committed family must recompute")
	}
}

func TestSnapGate_SkipsWhenFingerprintUnchanged(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	s := &Store{}
	now := time.Now().UTC()

	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("first sight must recompute")
	}
	g.commit(now)
	if g.changed(context.Background(), s, snapFamTest, now.Add(time.Minute)) {
		t.Fatal("an unchanged fingerprint after a committed push must SKIP")
	}
	fp = "v2"
	if !g.changed(context.Background(), s, snapFamTest, now.Add(2*time.Minute)) {
		t.Fatal("a changed fingerprint must recompute")
	}
}

func TestSnapGate_ProbeErrorFailsTowardRecompute(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	s := &Store{}
	now := time.Now().UTC()
	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("first sight must recompute")
	}
	g.commit(now)

	perr = errors.New("probe blew up")
	for i := 1; i <= 3; i++ {
		if !g.changed(context.Background(), s, snapFamTest, now.Add(time.Duration(i)*time.Minute)) {
			t.Fatalf("probe error #%d must recompute (fail toward today's behaviour), not skip", i)
		}
		// A failed probe must record nothing committable, so a commit in the
		// same cycle cannot mark the family clean.
		g.commit(now.Add(time.Duration(i) * time.Minute))
	}
}

func TestSnapGate_UnregisteredFamilyRecomputes(t *testing.T) {
	t.Parallel()
	g := newSnapGate()
	s := &Store{}
	now := time.Now().UTC()
	const unknown snapFamily = "no_probe_registered"
	if !g.changed(context.Background(), s, unknown, now) {
		t.Fatal("a family with no registered probe must keep the pre-R2 every-tick behaviour")
	}
	g.commit(now)
	if !g.changed(context.Background(), s, unknown, now.Add(time.Hour)) {
		t.Fatal("a family with no registered probe must never start skipping")
	}
}

func TestSnapGate_NilGateAlwaysRecomputes(t *testing.T) {
	t.Parallel()
	var g *snapGate
	if !g.changed(context.Background(), &Store{}, snapFamCacheSummary, time.Now()) {
		t.Fatal("a nil gate must degrade to recompute, never to skip")
	}
	g.commit(time.Now()) // must not panic
	g.recomputed(snapFamTest, false)
	g.setMinInterval(time.Second)
	if skipped, recomputed := g.counters(); len(skipped) != 0 || len(recomputed) != 0 {
		t.Fatal("a nil gate must report empty counters")
	}
}

func TestSnapGate_FailedPushLeavesFamilyDirty(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	s := &Store{}
	now := time.Now().UTC()

	// Compose, but never commit — the push failed.
	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("first sight must recompute")
	}
	if !g.changed(context.Background(), s, snapFamTest, now.Add(time.Minute)) {
		t.Fatal("a family the server never accepted must recompute, not be treated as delivered")
	}
}

func TestSnapGate_TruncatedFamilyStaysDirty(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	s := &Store{}
	now := time.Now().UTC()

	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("first sight must recompute")
	}
	// The envelope budget cut this family's tail.
	g.recomputed(snapFamTest, false)
	g.commit(now)
	if !g.changed(context.Background(), s, snapFamTest, now.Add(time.Minute)) {
		t.Fatal("a TRUNCATED family still owes the server its tail — it must not be committed as clean")
	}
	// A complete compose on the next cycle does settle it.
	g.recomputed(snapFamTest, true)
	g.commit(now.Add(time.Minute))
	if g.changed(context.Background(), s, snapFamTest, now.Add(2*time.Minute)) {
		t.Fatal("a complete, accepted compose must settle the family")
	}
}

func TestSnapGate_CadenceKnobThrottlesDirtyFamily(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	g.setMinInterval(10 * time.Minute)
	s := &Store{}
	now := time.Now().UTC()

	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("first sight must recompute regardless of cadence")
	}
	g.commit(now)

	// DIRTY, but inside the cadence window: still skipped. The probe must not
	// even be consulted, which is the point of checking cadence first.
	fp = "v2"
	probed := false
	snapProbes[snapFamTest] = func(*Store, context.Context) (string, error) {
		probed = true
		return fp, nil
	}
	if g.changed(context.Background(), s, snapFamTest, now.Add(time.Minute)) {
		t.Fatal("a dirty family inside snapshot_interval_seconds must be throttled")
	}
	if probed {
		t.Error("the cadence throttle must short-circuit BEFORE the probe query runs")
	}
	// Past the cadence window it recomputes.
	if !g.changed(context.Background(), s, snapFamTest, now.Add(11*time.Minute)) {
		t.Fatal("a dirty family past snapshot_interval_seconds must recompute")
	}
}

func TestSnapGate_FreshnessFloorForcesRecomputeWhenClean(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	s := &Store{}
	now := time.Now().UTC()

	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("first sight must recompute")
	}
	g.commit(now)
	if g.changed(context.Background(), s, snapFamTest, now.Add(snapGateDefaultMaxSkipAge/2)) {
		t.Fatal("a clean family inside the freshness floor must skip")
	}
	// Past the floor a CLEAN family recomputes anyway: two org rollups window
	// on the server-side pushed_at, so a family that stops being re-pushed
	// silently disappears from the dashboard even though nothing was deleted.
	if !g.changed(context.Background(), s, snapFamTest, now.Add(snapGateDefaultMaxSkipAge+time.Second)) {
		t.Fatal("a clean family older than the freshness floor must recompute so pushed_at keeps advancing")
	}
}

func TestSnapGate_FreshnessFloorNeverShorterThanCadence(t *testing.T) {
	t.Parallel()
	g := newSnapGate()
	g.setMinInterval(6 * time.Hour)
	g.mu.Lock()
	got := g.effectiveMaxSkipAgeLocked()
	g.mu.Unlock()
	if got != 6*time.Hour {
		t.Fatalf("effective floor = %v, want the operator's own 6h cadence — a floor shorter than "+
			"the configured cadence would silently re-force the fast tick", got)
	}
}

func TestSnapGate_BackwardsClockRecomputes(t *testing.T) {
	fp, perr := "v1", error(nil)
	installStubProbe(t, &fp, &perr)
	g := newSnapGate()
	g.setMinInterval(10 * time.Minute)
	s := &Store{}
	now := time.Now().UTC()
	if !g.changed(context.Background(), s, snapFamTest, now) {
		t.Fatal("first sight must recompute")
	}
	g.commit(now)
	if !g.changed(context.Background(), s, snapFamTest, now.Add(-time.Hour)) {
		t.Fatal("a clock that moved backwards must fail toward recompute, not into an unbounded skip")
	}
}

// --- integration: the real compose path -----------------------------------

// snapshotSections reports each GATED wire family's row count in a batch.
func snapshotSections(t *testing.T, b PushBatch) map[string]int {
	t.Helper()
	v := reflect.ValueOf(b)
	out := map[string]int{}
	for name := range gatedWireFamilies {
		f := v.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("PushBatch has no field %q", name)
		}
		out[name] = f.Len()
	}
	return out
}

// TestSelectUnpushedSince_UnchangedPushRecomputesNoSnapshotFamily is the
// headline Track R2 assertion: after a successful push, a second push with NO
// source changes composes NOTHING from the snapshot family — every gated
// section is empty and every gated family recorded a SKIP (i.e. its recompute
// SQL never ran).
func TestSelectUnpushedSince_UnchangedPushRecomputesNoSnapshotFamily(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()
	const wide = 64 << 20

	first, err := s.SelectUnpushedSince(ctx, PushCursor{}, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (first): %v", err)
	}
	for name, n := range snapshotSections(t, first) {
		if n == 0 {
			t.Fatalf("fixture did not populate gated family %s — the skip assertion below would be vacuous", name)
		}
	}
	// The server accepted it.
	s.CommitPushedSnapshots()

	beforeSkips, _ := s.OrgSnapshotGateStats()
	second, err := s.SelectUnpushedSince(ctx, first.Cursor, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (second): %v", err)
	}
	afterSkips, _ := s.OrgSnapshotGateStats()

	for name, n := range snapshotSections(t, second) {
		if n != 0 {
			t.Errorf("wire family %s composed %d rows on a push with NO source changes — "+
				"the Track R2 gate did not skip its recompute", name, n)
		}
	}
	for name, fam := range gatedWireFamilies {
		if afterSkips[string(fam)] <= beforeSkips[string(fam)] {
			t.Errorf("family %q (wire %s) recorded no new skip on an unchanged push", fam, name)
		}
	}
	// The cursor wires drained on the first batch, so nothing is left above the
	// cursor. (RowCount is NOT the assertion here: it also counts the obs
	// provider tiers, which are deliberately ungated and recompose every tick.)
	cursorRows := len(second.Sessions) + len(second.Actions) + len(second.APITurns) +
		len(second.TokenUsage) + len(second.GuardEvents) + len(second.OTelContent)
	if cursorRows != 0 {
		t.Errorf("cursor wires shipped %d rows past the first batch's cursor, want 0", cursorRows)
	}
}

// TestSelectUnpushedSince_DirtyFamilyRecomputesWhileOthersSkip pins the
// per-family granularity: touching ONE source table must recompute exactly the
// wires fed by it and leave every other family skipped.
func TestSelectUnpushedSince_DirtyFamilyRecomputesWhileOthersSkip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()
	const wide = 64 << 20

	first, err := s.SelectUnpushedSince(ctx, PushCursor{}, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (first): %v", err)
	}
	s.CommitPushedSnapshots()

	// Dirty exactly one substrate: the cache event log, which feeds the
	// cache_summary, session_cache and session_cache_events wires and nothing
	// else. All three share probeCacheEvents while keeping their own families,
	// so all three must recompute together — that is what "per SOURCE family"
	// means here, not "per wire".
	if _, err := s.InsertCacheEvents(ctx, []CacheEventRow{{
		SessionID: "s1", Tier: "proxy", Timestamp: time.Now().UTC(),
		Model: "claude-opus-4-7-new", Kind: "hit", Cause: "suffix_growth", TokensRead: 4321,
	}}); err != nil {
		t.Fatalf("dirty cache_events: %v", err)
	}

	second, err := s.SelectUnpushedSince(ctx, first.Cursor, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (second): %v", err)
	}
	sections := snapshotSections(t, second)
	cacheFed := map[string]bool{"CacheSummaries": true, "SessionCacheSummaries": true, "SessionCacheEvents": true}
	for name := range cacheFed {
		if sections[name] == 0 {
			t.Errorf("wire family %s did not recompute after its source table changed", name)
		}
	}
	for name, n := range sections {
		if cacheFed[name] {
			continue
		}
		if n != 0 {
			t.Errorf("wire family %s recomputed (%d rows) although only cache_events changed — "+
				"the gate must be per source family, not all-or-nothing", name, n)
		}
	}
}

// TestSelectUnpushedSince_SnapshotCadenceThrottlesDirtyFamilies is the Lever-2
// assertion at the compose seam: with a cadence installed, a family whose
// source data genuinely changed still waits.
func TestSelectUnpushedSince_SnapshotCadenceThrottlesDirtyFamilies(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()
	const wide = 64 << 20

	s.SetOrgSnapshotInterval(time.Hour)

	first, err := s.SelectUnpushedSince(ctx, PushCursor{}, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (first): %v", err)
	}
	if snapshotSections(t, first)["CacheSummaries"] == 0 {
		t.Fatal("the first compose must not be throttled — a never-delivered family always recomputes")
	}
	s.CommitPushedSnapshots()

	if _, err := s.InsertCacheEvents(ctx, []CacheEventRow{{
		SessionID: "s1", Tier: "proxy", Timestamp: time.Now().UTC(),
		Model: "claude-opus-4-7-throttled", Kind: "hit", Cause: "suffix_growth", TokensRead: 11,
	}}); err != nil {
		t.Fatalf("dirty cache_events: %v", err)
	}

	second, err := s.SelectUnpushedSince(ctx, first.Cursor, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (second): %v", err)
	}
	if n := snapshotSections(t, second)["CacheSummaries"]; n != 0 {
		t.Errorf("CacheSummaries composed %d rows inside a 1h snapshot_interval_seconds window — "+
			"the cadence knob must throttle even a DIRTY family", n)
	}

	// Disabling the throttle lets the same dirty family through immediately.
	s.SetOrgSnapshotInterval(0)
	third, err := s.SelectUnpushedSince(ctx, first.Cursor, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (third): %v", err)
	}
	if n := snapshotSections(t, third)["CacheSummaries"]; n == 0 {
		t.Error("with the cadence throttle disabled, a dirty family must recompute on the next tick")
	}
}

// TestSelectUnpushedSince_UncommittedPushRecomposesEverything proves the
// commit-on-success contract end to end: without a CommitPushedSnapshots (i.e.
// the server rejected the batch), the very next compose ships the whole
// snapshot family again.
func TestSelectUnpushedSince_UncommittedPushRecomposesEverything(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()
	const wide = 64 << 20

	first, err := s.SelectUnpushedSince(ctx, PushCursor{}, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (first): %v", err)
	}
	// No CommitPushedSnapshots: the push failed.
	second, err := s.SelectUnpushedSince(ctx, first.Cursor, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (second): %v", err)
	}
	firstSections, secondSections := snapshotSections(t, first), snapshotSections(t, second)
	for name, n := range firstSections {
		if n > 0 && secondSections[name] == 0 {
			t.Errorf("wire family %s was dropped after a FAILED push — a batch the server never "+
				"accepted must never be treated as delivered", name)
		}
	}
}

// TestSnapGateProbesAllSucceedOnSeededStore runs every registered probe against
// a fully-seeded store: a probe whose SQL names a column or table that does not
// exist would otherwise fail open silently, quietly restoring the every-tick
// recompute this arc removes.
func TestSnapGateProbesAllSucceedOnSeededStore(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	seedEveryWireFamily(t, s)
	ctx := context.Background()
	for fam, probe := range snapProbes {
		fp, err := probe(s, ctx)
		if err != nil {
			t.Errorf("probe for family %q failed: %v — a failing probe fails OPEN, so the family "+
				"would silently keep recomputing every tick", fam, err)
			continue
		}
		if fp == "" {
			t.Errorf("probe for family %q returned an empty fingerprint; an empty value cannot be "+
				"distinguished from 'never committed'", fam)
		}
	}
}
