package policystate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// guardFacts / routerFacts / localFacts are compact builders for the org-rail
// and local points so each test states only the fields it exercises.
func guardFacts(f PointFacts) PointFacts {
	f.HasOrgRail = true
	if f.EnforceMode == "" {
		f.EnforceMode = "enforce"
	}
	return f
}

func routerFacts(f PointFacts) PointFacts {
	f.HasOrgRail = true
	return f
}

// TestResolve_DeliveredUnacceptedFromLatestFetch — row 1 reads the reject facts
// from the in-memory last-fetch, never the cache (R2-B1/B5). The row still
// carries the running LKG version and the REJECTED version as desired.
func TestResolve_DeliveredUnacceptedFromLatestFetch(t *testing.T) {
	f := guardFacts(PointFacts{
		CachedAcceptedVersion: 5,
		RunningVersion:        5,
		EffectiveHash:         hex64,
		LatestFetchRejected:   true,
		RejectedVersion:       6,
		RejectCode:            orgcontract.ReasonSigInvalid,
	})
	row := Resolve(PointGuard, FamilyGuardCoding, f)
	if row.Status != orgcontract.StatusDeliveredUnaccepted {
		t.Fatalf("status = %q, want delivered_unaccepted", row.Status)
	}
	if row.Reason != orgcontract.ReasonSigInvalid {
		t.Fatalf("reason = %q, want sig_invalid", row.Reason)
	}
	if row.DesiredVersion != 6 {
		t.Fatalf("desired = %d, want the REJECTED version 6", row.DesiredVersion)
	}
	if row.RunningVersion != 5 {
		t.Fatalf("running = %d, want the LKG 5", row.RunningVersion)
	}
}

// TestResolve_AcceptedButBehindIsPendingRestart — row 3.
func TestResolve_AcceptedButBehindIsPendingRestart(t *testing.T) {
	row := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 4,
		RunningVersion:        3,
		EffectiveHash:         hex64,
	}))
	if row.Status != orgcontract.StatusPendingRestart || row.Reason != orgcontract.ReasonRestartRequired {
		t.Fatalf("got %q/%q, want pending_restart/restart_required", row.Status, row.Reason)
	}
	if !row.RestartRequired {
		t.Fatal("restart_required must be true")
	}
}

// TestResolve_RouterObserveIsAcceptedInert — row 4 (router, mode != enforce).
func TestResolve_RouterObserveIsAcceptedInert(t *testing.T) {
	row := Resolve(PointRouter, FamilyRoutingOptimization, routerFacts(PointFacts{
		CachedAcceptedVersion: 2,
		RunningVersion:        2,
		EffectiveHash:         hex16,
		EnforceMode:           "observe",
	}))
	if row.Status != orgcontract.StatusAcceptedInert || row.Reason != orgcontract.ReasonModeObserve {
		t.Fatalf("got %q/%q, want accepted_inert/mode_observe", row.Status, row.Reason)
	}
	if row.Mode != "observe" {
		t.Fatalf("mode = %q, want observe", row.Mode)
	}
}

// TestResolve_StaleLKGFromTransportUnreachableOnly — row 2 fires ONLY on a
// transport Unreachable; AuthFailed/Indeterminate (which never set
// PointFacts.Unreachable) must not fabricate stale_lkg (R3-B5).
func TestResolve_StaleLKGFromTransportUnreachableOnly(t *testing.T) {
	row := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 3, RunningVersion: 3, EffectiveHash: hex64, Unreachable: true,
	}))
	if row.Status != orgcontract.StatusStaleLKG || row.Reason != orgcontract.ReasonControlPlaneUnreachable {
		t.Fatalf("got %q/%q, want stale_lkg/control_plane_unreachable", row.Status, row.Reason)
	}
	// Not unreachable → must NOT be stale_lkg (this is what proves mapping
	// AuthFailed/Indeterminate onto Unreachable would break).
	ok := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 3, RunningVersion: 3, EffectiveHash: hex64, Unreachable: false,
	}))
	if ok.Status == orgcontract.StatusStaleLKG {
		t.Fatal("a reachable point must never resolve to stale_lkg")
	}
}

// TestResolve_EffectiveRequiresEquality — row 5 uses == (R2-B6): running one
// behind the cache is NOT effective.
func TestResolve_EffectiveRequiresEquality(t *testing.T) {
	eq := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 7, RunningVersion: 7, EffectiveHash: hex64,
	}))
	if eq.Status != orgcontract.StatusEffective || eq.Reason != orgcontract.ReasonOK {
		t.Fatalf("got %q/%q, want effective/ok", eq.Status, eq.Reason)
	}
	behind := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 7, RunningVersion: 6, EffectiveHash: hex64,
	}))
	if behind.Status == orgcontract.StatusEffective {
		t.Fatal("running < cached must not be effective (>= would be the bug)")
	}
}

// TestResolve_RunningAheadIsInconsistent — row 6 (R2-B6): running ahead of the
// cache surfaces as none/inconsistent_observation WITH its versions intact.
func TestResolve_RunningAheadIsInconsistent(t *testing.T) {
	row := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 4, RunningVersion: 5, EffectiveHash: hex64,
	}))
	if row.Status != orgcontract.StatusNone || row.Reason != orgcontract.ReasonInconsistentObservation {
		t.Fatalf("got %q/%q, want none/inconsistent_observation", row.Status, row.Reason)
	}
	if row.RunningVersion != 5 || row.DesiredVersion != 4 {
		t.Fatalf("versions = %d/%d, want running 5 desired 4 intact", row.RunningVersion, row.DesiredVersion)
	}
}

// TestResolve_FirstInstallEmptyHashZeroRunning — row 3 first install: accepted
// into cache, org layer not-yet-loaded → running 0 + EMPTY hash (R3-B2).
func TestResolve_FirstInstallEmptyHashZeroRunning(t *testing.T) {
	row := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 2, RunningVersion: 0, EffectiveHash: "",
	}))
	if row.Status != orgcontract.StatusPendingRestart {
		t.Fatalf("status = %q, want pending_restart", row.Status)
	}
	if row.RunningVersion != 0 {
		t.Fatalf("running = %d, want 0", row.RunningVersion)
	}
	if row.EffectiveHash != "" {
		t.Fatalf("hash = %q, want empty at running 0 (org rail)", row.EffectiveHash)
	}
	// Even if a reader wrongly supplied a hash at running 0, Resolve strips it.
	stripped := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 2, RunningVersion: 0, EffectiveHash: hex64,
	}))
	if stripped.EffectiveHash != "" {
		t.Fatalf("org-rail hash at running 0 must be stripped, got %q", stripped.EffectiveHash)
	}
}

// TestResolve_RestartRequiredHoldsUnderInertAndStale — RestartRequired is
// structural and holds under accepted_inert and stale_lkg (§3.2).
func TestResolve_RestartRequiredHoldsUnderInertAndStale(t *testing.T) {
	inert := Resolve(PointRouter, FamilyRoutingOptimization, routerFacts(PointFacts{
		CachedAcceptedVersion: 5, RunningVersion: 4, EffectiveHash: hex16, EnforceMode: "observe",
	}))
	if inert.Status != orgcontract.StatusAcceptedInert || !inert.RestartRequired {
		t.Fatalf("inert: got %q restart=%v, want accepted_inert restart=true", inert.Status, inert.RestartRequired)
	}
	stale := Resolve(PointGuard, FamilyGuardCoding, guardFacts(PointFacts{
		CachedAcceptedVersion: 5, RunningVersion: 4, EffectiveHash: hex64, Unreachable: true,
	}))
	if stale.Status != orgcontract.StatusStaleLKG || !stale.RestartRequired {
		t.Fatalf("stale: got %q restart=%v, want stale_lkg restart=true", stale.Status, stale.RestartRequired)
	}
}

// TestResolve_LocalPointEmitsLocalEffectiveWithHash — row 7 (R4-B1): a local
// point (HasOrgRail=false) with a live hash → none/local_effective, zero
// versions, hash CARRIED.
func TestResolve_LocalPointEmitsLocalEffectiveWithHash(t *testing.T) {
	row := Resolve(PointProxyAdmitter, FamilyAdmissionInput, PointFacts{
		HasOrgRail: false, EffectiveHash: hex64, EnforceMode: "off",
	})
	if row.Status != orgcontract.StatusNone || row.Reason != orgcontract.ReasonLocalEffective {
		t.Fatalf("got %q/%q, want none/local_effective", row.Status, row.Reason)
	}
	if row.DesiredVersion != 0 || row.RunningVersion != 0 {
		t.Fatalf("versions = %d/%d, want 0/0", row.DesiredVersion, row.RunningVersion)
	}
	if row.EffectiveHash != hex64 {
		t.Fatalf("hash = %q, want the live 64-hex carried", row.EffectiveHash)
	}
}

// TestResolve_LocalPointNoPolicyIsNoPolicy — row 8 (R4-B1): local point, empty
// hash → none/no_policy.
func TestResolve_LocalPointNoPolicyIsNoPolicy(t *testing.T) {
	row := Resolve(PointProxyEgress, FamilyEgressGuardrail, PointFacts{
		HasOrgRail: false, EffectiveHash: "", EnforceMode: "off",
	})
	if row.Status != orgcontract.StatusNone || row.Reason != orgcontract.ReasonNoPolicy {
		t.Fatalf("got %q/%q, want none/no_policy", row.Status, row.Reason)
	}
	if row.EffectiveHash != "" {
		t.Fatalf("hash = %q, want empty", row.EffectiveHash)
	}
}

// TestResolve_NeverEmitsDeferredCodes — a table over every reachable resolver
// output must never emit a still-deferred status/reason (break_glass /
// break_glass_active). Plane-A P0-5 §7.2 ENABLED not_preauthorized /
// capability_mismatch / version_replay for the admission/egress org rail,
// so those are no longer in this deferred set (covered by dedicated
// resolve tests below).
func TestResolve_NeverEmitsDeferredCodes(t *testing.T) {
	deferredStatus := map[string]bool{orgcontract.StatusBreakGlass: true}
	deferredReason := map[string]bool{
		orgcontract.ReasonBreakGlassActive: true,
	}
	cases := []struct {
		point string
		fam   string
		f     PointFacts
	}{
		{PointGuard, FamilyGuardCoding, guardFacts(PointFacts{LatestFetchRejected: true, RejectCode: orgcontract.ReasonLintFailed, RejectedVersion: 2})},
		{PointGuard, FamilyGuardCoding, guardFacts(PointFacts{CachedAcceptedVersion: 3, RunningVersion: 3, EffectiveHash: hex64, Unreachable: true})},
		{PointGuard, FamilyGuardCoding, guardFacts(PointFacts{CachedAcceptedVersion: 3, RunningVersion: 2, EffectiveHash: hex64})},
		{PointRouter, FamilyRoutingOptimization, routerFacts(PointFacts{CachedAcceptedVersion: 3, RunningVersion: 3, EffectiveHash: hex16, EnforceMode: "observe"})},
		{PointGuard, FamilyGuardCoding, guardFacts(PointFacts{CachedAcceptedVersion: 3, RunningVersion: 3, EffectiveHash: hex64})},
		{PointGuard, FamilyGuardCoding, guardFacts(PointFacts{CachedAcceptedVersion: 3, RunningVersion: 4, EffectiveHash: hex64})},
		{PointProxyAdmitter, FamilyAdmissionInput, PointFacts{EffectiveHash: hex64}},
		{PointProxyEgress, FamilyEgressGuardrail, PointFacts{}},
	}
	for i, tc := range cases {
		row := Resolve(tc.point, tc.fam, tc.f)
		if deferredStatus[row.Status] {
			t.Errorf("case %d: emitted deferred status %q", i, row.Status)
		}
		if deferredReason[row.Reason] {
			t.Errorf("case %d: emitted deferred reason %q", i, row.Reason)
		}
	}
}

// TestResolve_AdmitterOrgInertNotPreauthorized is P0-5 §7.1 row 4: an
// installed Org layer gated inert by preauthorization reports
// accepted_inert/not_preauthorized (never none/no_policy, never effective).
func TestResolve_AdmitterOrgInertNotPreauthorized(t *testing.T) {
	row := Resolve(PointProxyAdmitter, FamilyAdmissionInput, PointFacts{
		HasOrgRail: true, CachedAcceptedVersion: 3, RunningVersion: 3,
		EffectiveHash: hex64, EnforceMode: "observe",
		InertReason: orgcontract.ReasonNotPreauthorized,
	})
	if row.Status != orgcontract.StatusAcceptedInert || row.Reason != orgcontract.ReasonNotPreauthorized {
		t.Fatalf("got %q/%q, want accepted_inert/not_preauthorized", row.Status, row.Reason)
	}
	if row.EffectiveHash != hex64 {
		t.Fatalf("hash = %q, want BodyHash-shaped EffectiveHash carried through", row.EffectiveHash)
	}
}

// TestResolve_AdmitterOrgEffectiveUsesBodyHash is P0-5 §4.3/§7.1 row 6: an
// authorized Org layer reports effective/ok with EffectiveHash = BodyHash
// (the facts carry BodyHash into EffectiveHash at the reader boundary).
func TestResolve_AdmitterOrgEffectiveUsesBodyHash(t *testing.T) {
	row := Resolve(PointProxyAdmitter, FamilyAdmissionInput, PointFacts{
		HasOrgRail: true, CachedAcceptedVersion: 2, RunningVersion: 2,
		EffectiveHash: hex64, EnforceMode: "enforce",
	})
	if row.Status != orgcontract.StatusEffective || row.Reason != orgcontract.ReasonOK {
		t.Fatalf("got %q/%q, want effective/ok", row.Status, row.Reason)
	}
	if row.EffectiveHash != hex64 {
		t.Fatalf("hash = %q, want the org BodyHash", row.EffectiveHash)
	}
}

// TestResolve_AdmitterOrgObserveStillEffective — authorized Org with Spec
// mode=observe (not a preauth inert) is still effective under §7.1 row 6.
func TestResolve_AdmitterOrgObserveStillEffective(t *testing.T) {
	row := Resolve(PointProxyAdmitter, FamilyAdmissionInput, PointFacts{
		HasOrgRail: true, CachedAcceptedVersion: 1, RunningVersion: 1,
		EffectiveHash: hex64, EnforceMode: "observe",
	})
	if row.Status != orgcontract.StatusEffective {
		t.Fatalf("status = %q, want effective (authorized observe Org is not inert)", row.Status)
	}
}

// TestResolve_ModeAdviseNormalizedToObserve — S3.
func TestResolve_ModeAdviseNormalizedToObserve(t *testing.T) {
	row := Resolve(PointRouter, FamilyRoutingOptimization, routerFacts(PointFacts{
		CachedAcceptedVersion: 1, RunningVersion: 1, EffectiveHash: hex16, EnforceMode: "advise",
	}))
	if row.Mode != "observe" {
		t.Fatalf("mode = %q, want observe (advise normalized)", row.Mode)
	}
	// advise → observe → NOT enforceIntent → router runs inert, not effective.
	if row.Status != orgcontract.StatusAcceptedInert {
		t.Fatalf("status = %q, want accepted_inert (advise is not enforce)", row.Status)
	}
}

// TestAssemble_OmitsFailedPointNotNone — a reader error omits that point's row
// (never synthesizes none); healthy rows still emit; the joined error returns.
func TestAssemble_OmitsFailedPointNotNone(t *testing.T) {
	boom := errors.New("reader boom")
	readers := map[string]PointReader{
		PointGuard: func(context.Context) (PointFacts, error) {
			return guardFacts(PointFacts{CachedAcceptedVersion: 1, RunningVersion: 1, EffectiveHash: hex64}), nil
		},
		PointRouter: func(context.Context) (PointFacts, error) { return PointFacts{}, boom },
	}
	rows, err := Assemble(context.Background(), readers)
	if err == nil || !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the joined reader error", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 healthy (failed point OMITTED, not synthesized)", len(rows))
	}
	if rows[0].EnforcementPoint != PointGuard {
		t.Fatalf("emitted %q, want the healthy guard row", rows[0].EnforcementPoint)
	}
}

// TestResolve_LastSeenIsRFC3339 confirms the liveness timestamp serializes as
// RFC3339 (the wire contract + server value-guard requirement).
func TestResolve_LastSeenIsRFC3339(t *testing.T) {
	ts := time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)
	row := Resolve(PointProxyEgress, FamilyEgressGuardrail, PointFacts{LastSeen: ts})
	if _, err := time.Parse(time.RFC3339, row.LastSeen); err != nil {
		t.Fatalf("last_seen %q not RFC3339: %v", row.LastSeen, err)
	}
}

const (
	hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	hex16 = "0123456789abcdef"
)

// TestResolve_SelectorMismatchIsDeliveredUnaccepted pins the P0-10 Phase B
// reject code onto row 1 for the two ORG-RAIL points that can report it
// (admitter/egress — the router's delivered_unaccepted set stays
// key-pin/sig only). A selector mismatch keeps the prior LKG running, so
// the row must report the still-running version alongside the rejected one:
// that pairing is what lets the org see "this node refused the targeted
// version and is still on the old one" rather than "this node has nothing".
func TestResolve_SelectorMismatchIsDeliveredUnaccepted(t *testing.T) {
	for _, point := range []string{PointProxyAdmitter, PointProxyEgress} {
		t.Run(point, func(t *testing.T) {
			row := Resolve(point, pointFamily[point], PointFacts{
				HasOrgRail:            true,
				EnforceMode:           "observe",
				CachedAcceptedVersion: 2,
				RunningVersion:        2,
				EffectiveHash:         hex64,
				LatestFetchRejected:   true,
				RejectedVersion:       3,
				RejectCode:            orgcontract.ReasonSelectorMismatch,
			})
			if row.Status != orgcontract.StatusDeliveredUnaccepted {
				t.Fatalf("status = %q, want delivered_unaccepted", row.Status)
			}
			if row.Reason != orgcontract.ReasonSelectorMismatch {
				t.Fatalf("reason = %q, want selector_mismatch", row.Reason)
			}
			if row.DesiredVersion != 3 || row.RunningVersion != 2 {
				t.Fatalf("versions = desired %d / running %d, want 3 / 2 (prior LKG retained)", row.DesiredVersion, row.RunningVersion)
			}
			if row.EffectiveHash != hex64 {
				t.Fatalf("effective_hash = %q, want the still-running org-rail hash", row.EffectiveHash)
			}
		})
	}
}

// --- v2: the gateway.providers point ---------------------------------------
//
// docs/plans/policy-state-v2-gateway-providers-spec-2026-08-15.md §2.1.

// TestAssemble_MapsGatewayPointToItsFamily — Assemble resolves the family
// from the §2.4 mapping, so a new point is one map row, not a new branch.
func TestAssemble_MapsGatewayPointToItsFamily(t *testing.T) {
	readers := map[string]PointReader{
		PointProxyGateway: func(context.Context) (PointFacts, error) {
			return PointFacts{EffectiveHash: hex64, EnforceMode: "enforce"}, nil
		},
	}
	rows, err := Assemble(context.Background(), readers)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Family != FamilyGatewayProviders {
		t.Fatalf("family = %q, want %q", rows[0].Family, FamilyGatewayProviders)
	}
	if rows[0].EnforcementPoint != PointProxyGateway {
		t.Fatalf("point = %q, want %q", rows[0].EnforcementPoint, PointProxyGateway)
	}
}

// TestAssemble_MapsNodeFeaturesPointToItsFamily is TestAssemble_MapsGatewayPointToItsFamily's
// sibling for the org-parity W5.1 point (docs/plans/org-parity-full-depth-plan-2026-08-24.md
// §4): PointNodeFeatures resolves to FamilyNodeFeatures — the mapping the
// node.features ACK, and the Fleet-state "Feature gates" column, depend on.
func TestAssemble_MapsNodeFeaturesPointToItsFamily(t *testing.T) {
	readers := map[string]PointReader{
		PointNodeFeatures: func(context.Context) (PointFacts, error) {
			return PointFacts{EffectiveHash: hex64, EnforceMode: "enforce"}, nil
		},
	}
	rows, err := Assemble(context.Background(), readers)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Family != FamilyNodeFeatures {
		t.Fatalf("family = %q, want %q", rows[0].Family, FamilyNodeFeatures)
	}
	if rows[0].EnforcementPoint != PointNodeFeatures {
		t.Fatalf("point = %q, want %q", rows[0].EnforcementPoint, PointNodeFeatures)
	}
}

// TestOptionalPoints_IncludesNodeFeaturesNotCore pins node-features as the
// third OptionalPoints member (alongside proxy-gateway/node-dashboard) —
// see collector.go's "ORDER IS THE CONTRACT" comment on OptionalPoints. A
// v1-server downgrade must drop it exactly like the other two, never treat
// it as one of the required four.
func TestOptionalPoints_IncludesNodeFeaturesNotCore(t *testing.T) {
	found := false
	for _, p := range OptionalPoints {
		if p == PointNodeFeatures {
			found = true
		}
	}
	if !found {
		t.Fatalf("OptionalPoints = %v, want it to include %q", OptionalPoints, PointNodeFeatures)
	}
	if IsCorePoint(PointNodeFeatures) {
		t.Fatalf("IsCorePoint(%q) = true, want false — it is optional, not one of the v1 four", PointNodeFeatures)
	}
	if _, ok := pointFamily[PointNodeFeatures]; !ok {
		t.Errorf("node-features point has no family mapping — Assemble would silently drop it")
	}
}

// TestCorePoints_IsTheV1FourAndExcludesGateway pins the core/optional split
// the reporter's pre-v2 downgrade depends on (spec §3.2). If the gateway
// point ever leaks into CorePoints, the downgrade posts a five-row snapshot
// to a v1 server and loses every report.
func TestCorePoints_IsTheV1FourAndExcludesGateway(t *testing.T) {
	if len(CorePoints) != 4 {
		t.Fatalf("CorePoints = %v, want exactly the four v1 points", CorePoints)
	}
	for _, p := range []string{PointGuard, PointRouter, PointProxyAdmitter, PointProxyEgress} {
		if !IsCorePoint(p) {
			t.Errorf("IsCorePoint(%q) = false, want true", p)
		}
	}
	if IsCorePoint(PointProxyGateway) {
		t.Fatalf("IsCorePoint(%q) = true, want false — it is the OPTIONAL v2 row", PointProxyGateway)
	}
	// Every core point must still resolve to a family, or Assemble would
	// silently drop it.
	for _, p := range CorePoints {
		if _, ok := pointFamily[p]; !ok {
			t.Errorf("core point %q has no family mapping", p)
		}
	}
}

// TestResolve_GatewayLocalEffective — the node's own lane table (no org rail,
// a live hash) resolves through the UNCHANGED table row 8.
func TestResolve_GatewayLocalEffective(t *testing.T) {
	row := Resolve(PointProxyGateway, FamilyGatewayProviders, PointFacts{
		EffectiveHash: hex64, EnforceMode: "enforce",
	})
	if row.Status != orgcontract.StatusNone || row.Reason != orgcontract.ReasonLocalEffective {
		t.Fatalf("status/reason = %s/%s, want none/local_effective", row.Status, row.Reason)
	}
	if row.EffectiveHash != hex64 {
		t.Errorf("effective_hash = %q, want the live local hash", row.EffectiveHash)
	}
	if row.RestartRequired {
		t.Error("restart_required = true, want false for a local row")
	}
}

// TestResolve_Gen2FieldsGatedToNodeDashboardOnly is the P4-2 gate: the
// server 400s a report that populates AcceptedAuthority/ExtractionEffective/
// DroppedClasses on any row other than node.governance's, so Resolve must
// copy them onto the wire row ONLY for PointNodeDashboard — even when a
// (misbehaving) reader supplies them for another point. This is the
// collector-side half of the P4-2 gate the wire-shape doc comment on
// PointFacts describes; cmd/observer/nodegov_wire.go's reader is the only
// one that ever actually populates these three fields, but Resolve must not
// rely on that.
func TestResolve_Gen2FieldsGatedToNodeDashboardOnly(t *testing.T) {
	gen2 := PointFacts{
		EffectiveHash:       hex64,
		EnforceMode:         "enforce",
		AcceptedAuthority:   []string{"extract.cache"},
		ExtractionEffective: []string{"extract.cache"},
		DroppedClasses:      map[string]string{"pinned": orgcontract.ReasonNotPreauthorized},
	}

	nodeRow := Resolve(PointNodeDashboard, FamilyNodeGovernance, gen2)
	if len(nodeRow.AcceptedAuthority) != 1 || nodeRow.AcceptedAuthority[0] != "extract.cache" {
		t.Fatalf("node-dashboard AcceptedAuthority = %v, want [extract.cache]", nodeRow.AcceptedAuthority)
	}
	if len(nodeRow.ExtractionEffective) != 1 || nodeRow.ExtractionEffective[0] != "extract.cache" {
		t.Fatalf("node-dashboard ExtractionEffective = %v, want [extract.cache]", nodeRow.ExtractionEffective)
	}
	if nodeRow.DroppedClasses["pinned"] != orgcontract.ReasonNotPreauthorized {
		t.Fatalf("node-dashboard DroppedClasses = %v, want pinned->%s", nodeRow.DroppedClasses, orgcontract.ReasonNotPreauthorized)
	}

	others := []struct {
		point  string
		family string
	}{
		{PointGuard, FamilyGuardCoding},
		{PointRouter, FamilyRoutingOptimization},
		{PointProxyAdmitter, FamilyAdmissionInput},
		{PointProxyEgress, FamilyEgressGuardrail},
		{PointProxyGateway, FamilyGatewayProviders},
	}
	for _, o := range others {
		row := Resolve(o.point, o.family, gen2)
		if row.AcceptedAuthority != nil {
			t.Errorf("%s: AcceptedAuthority = %v, want nil (gen2 fields must never leak off node-dashboard)", o.point, row.AcceptedAuthority)
		}
		if row.ExtractionEffective != nil {
			t.Errorf("%s: ExtractionEffective = %v, want nil", o.point, row.ExtractionEffective)
		}
		if row.DroppedClasses != nil {
			t.Errorf("%s: DroppedClasses = %v, want nil", o.point, row.DroppedClasses)
		}
	}
}

// TestAssemble_MapsNodeMCPRelayPointToItsFamily pins the Agent Access P4
// effective-state row (doc3 §12.8): the node-mcp-relay point resolves to
// the tools.mcp_access family through the SAME ordered decision table as
// every other point, and the three statuses the plan names for it —
// effective, accepted_inert (not_preauthorized) and none — all fit the
// closed enum with no new value.
func TestAssemble_MapsNodeMCPRelayPointToItsFamily(t *testing.T) {
	cases := []struct {
		name       string
		facts      PointFacts
		wantStatus string
		wantReason string
		wantMode   string
	}{
		{"effective", PointFacts{HasOrgRail: true, CachedAcceptedVersion: 7, RunningVersion: 7, EffectiveHash: hex64, EnforceMode: "enforce"}, "effective", "ok", "enforce"},
		{"accepted_inert not_preauthorized", PointFacts{HasOrgRail: true, CachedAcceptedVersion: 7, RunningVersion: 7, EffectiveHash: hex64, EnforceMode: "observe", InertReason: "not_preauthorized"}, "accepted_inert", "not_preauthorized", "observe"},
		{"none no_policy (relay disabled / no table)", PointFacts{EnforceMode: "off"}, "none", "no_policy", "off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.facts
			readers := map[string]PointReader{
				PointNodeMCPRelay: func(context.Context) (PointFacts, error) { return f, nil },
			}
			rows, err := Assemble(context.Background(), readers)
			if err != nil {
				t.Fatalf("Assemble: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("rows = %d, want 1", len(rows))
			}
			r := rows[0]
			if r.Family != FamilyToolsMCPAccess || r.EnforcementPoint != PointNodeMCPRelay {
				t.Fatalf("row = %+v, want family %q point %q", r, FamilyToolsMCPAccess, PointNodeMCPRelay)
			}
			if r.Status != tc.wantStatus || r.Reason != tc.wantReason || r.Mode != tc.wantMode {
				t.Errorf("status/reason/mode = %s/%s/%s, want %s/%s/%s", r.Status, r.Reason, r.Mode, tc.wantStatus, tc.wantReason, tc.wantMode)
			}
			// Enum-only: the node-dashboard-only extension fields never ride
			// this row (the server 400s them on any other point).
			if r.AcceptedAuthority != nil || r.ExtractionEffective != nil || r.DroppedClasses != nil || r.EffectivePins != nil {
				t.Errorf("node-mcp-relay row carries node-dashboard-only fields: %+v", r)
			}
		})
	}
}

// TestOptionalPoints_NodeMCPRelayIsNewestNotCore pins node-mcp-relay as the
// FOURTH (newest) OptionalPoints member: the ladder drops it first when a
// pre-v5 server refuses the snapshot, and it is never one of the core four.
func TestOptionalPoints_NodeMCPRelayIsNewestNotCore(t *testing.T) {
	if len(OptionalPoints) == 0 || OptionalPoints[len(OptionalPoints)-1] != PointNodeMCPRelay {
		t.Fatalf("OptionalPoints = %v, want node-mcp-relay LAST (ORDER IS THE CONTRACT)", OptionalPoints)
	}
	if IsCorePoint(PointNodeMCPRelay) || !IsOptionalPoint(PointNodeMCPRelay) {
		t.Fatal("node-mcp-relay must be optional, not core")
	}
}
