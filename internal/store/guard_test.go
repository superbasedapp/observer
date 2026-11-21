package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// t0Guard anchors all timestamps in guard store tests so retention and
// chain math is deterministic.
var t0Guard = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

// guardEventFixture returns a minimal valid guard event row. Callers
// override fields per case.
func guardEventFixture(sessionID, ruleID string, ts time.Time) GuardEventRow {
	return GuardEventRow{
		TS:            ts,
		SessionID:     sessionID,
		Tool:          "claude-code",
		EventKind:     "shell_exec",
		RuleID:        ruleID,
		Category:      "destructive",
		Severity:      "critical",
		Decision:      "flag",
		Source:        "builtin",
		Reason:        "rm -rf targeting the home directory",
		TargetHash:    "deadbeef",
		TargetExcerpt: "rm -rf ~/projects",
	}
}

// TestInsertGuardEvents_ChainContinuity is the §10.4 chain-continuity
// unit test the G2 kickoff requires: events inserted across SEPARATE
// batches still form one unbroken chain (genesis anchor "" → each
// chain_prev equals the prior chain_hash), and VerifyGuardChain walks
// it clean.
func TestInsertGuardEvents_ChainContinuity(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	batch1 := []GuardEventRow{
		guardEventFixture("sA", "R-101", t0Guard),
		guardEventFixture("sA", "R-152", t0Guard.Add(time.Second)),
	}
	if n, err := s.InsertGuardEvents(ctx, batch1); err != nil || n != 2 {
		t.Fatalf("InsertGuardEvents batch1 = (%d, %v), want (2, nil)", n, err)
	}
	batch2 := []GuardEventRow{
		guardEventFixture("sB", "R-110", t0Guard.Add(2*time.Second)),
	}
	if n, err := s.InsertGuardEvents(ctx, batch2); err != nil || n != 1 {
		t.Fatalf("InsertGuardEvents batch2 = (%d, %v), want (1, nil)", n, err)
	}

	// Stamped-back chain fields: genesis anchor, then per-row linkage
	// ACROSS the batch boundary.
	if batch1[0].ChainPrev != "" {
		t.Errorf("genesis chain_prev = %q, want empty", batch1[0].ChainPrev)
	}
	if batch1[1].ChainPrev != batch1[0].ChainHash {
		t.Errorf("row2 chain_prev = %q, want row1 chain_hash %q", batch1[1].ChainPrev, batch1[0].ChainHash)
	}
	if batch2[0].ChainPrev != batch1[1].ChainHash {
		t.Errorf("cross-batch chain_prev = %q, want prior batch tail %q", batch2[0].ChainPrev, batch1[1].ChainHash)
	}
	for i, ev := range append(batch1, batch2...) {
		if len(ev.ChainHash) != 64 {
			t.Errorf("row %d chain_hash = %q, want 64-char sha256 hex", i, ev.ChainHash)
		}
	}

	report, err := s.VerifyGuardChain(ctx)
	if err != nil {
		t.Fatalf("VerifyGuardChain: %v", err)
	}
	if !report.OK || report.Checked != 3 || report.FirstDivergenceID != 0 {
		t.Errorf("VerifyGuardChain = %+v, want OK across 3 rows", report)
	}
}

// TestVerifyGuardChain_DetectsTamper pins the tamper-evidence property:
// a direct UPDATE to a persisted row (bypassing the one-owner helpers,
// as an attacker or a bug would) is reported at that row's id, for both
// failure classes — rewritten content and a broken link (mid-chain
// deletion).
func TestVerifyGuardChain_DetectsTamper(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		tamper string // SQL executed against the seeded 3-row chain
		wantID int64
		detail string // substring expected in report.Detail
	}{
		{
			name:   "rewritten row content",
			tamper: `UPDATE guard_events SET reason = 'innocuous edit' WHERE id = 2`,
			wantID: 2,
			detail: "rewritten row",
		},
		{
			name:   "mid-chain deletion breaks the link",
			tamper: `DELETE FROM guard_events WHERE id = 2`,
			wantID: 3,
			detail: "broken link",
		},
		{
			name:   "decision flip detected",
			tamper: `UPDATE guard_events SET decision = 'allow', enforced = 0 WHERE id = 3`,
			wantID: 3,
			detail: "rewritten row",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, database := newTestStore(t)
			ctx := context.Background()
			events := []GuardEventRow{
				guardEventFixture("sA", "R-101", t0Guard),
				guardEventFixture("sA", "R-110", t0Guard.Add(time.Second)),
				guardEventFixture("sA", "R-152", t0Guard.Add(2*time.Second)),
			}
			if _, err := s.InsertGuardEvents(ctx, events); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if _, err := database.ExecContext(ctx, tc.tamper); err != nil {
				t.Fatalf("tamper: %v", err)
			}
			report, err := s.VerifyGuardChain(ctx)
			if err != nil {
				t.Fatalf("VerifyGuardChain: %v", err)
			}
			if report.OK {
				t.Fatal("VerifyGuardChain reported OK on a tampered chain")
			}
			if report.FirstDivergenceID != tc.wantID {
				t.Errorf("FirstDivergenceID = %d, want %d (detail: %s)", report.FirstDivergenceID, tc.wantID, report.Detail)
			}
			if !strings.Contains(report.Detail, tc.detail) {
				t.Errorf("Detail = %q, want substring %q", report.Detail, tc.detail)
			}
		})
	}
}

// TestInsertGuardEvents_BoundsContent pins the one-owner content
// bounds: Reason and TargetExcerpt are rune-safe truncated at the
// store seam BEFORE the chain hash is computed, so the stored bytes
// and the chain preimage agree (verify stays green on a truncated
// row).
func TestInsertGuardEvents_BoundsContent(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	ev := guardEventFixture("sA", "R-101", t0Guard)
	ev.Reason = strings.Repeat("я", guardMaxReasonRunes+50)        // multibyte: rune-safe cut required
	ev.TargetExcerpt = strings.Repeat("x", guardMaxExcerptRunes*2) // ASCII overlong
	batch := []GuardEventRow{ev}
	if _, err := s.InsertGuardEvents(ctx, batch); err != nil {
		t.Fatalf("InsertGuardEvents: %v", err)
	}

	got, err := s.LoadGuardEventsForSession(ctx, "sA")
	if err != nil {
		t.Fatalf("LoadGuardEventsForSession: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows = %d, want 1", len(got))
	}
	wantReason := strings.Repeat("я", guardMaxReasonRunes) + "…"
	if got[0].Reason != wantReason {
		t.Errorf("Reason not rune-safe bounded: len=%d", len(got[0].Reason))
	}
	wantExcerpt := strings.Repeat("x", guardMaxExcerptRunes) + "…"
	if got[0].TargetExcerpt != wantExcerpt {
		t.Errorf("TargetExcerpt not bounded: len=%d", len(got[0].TargetExcerpt))
	}
	// The chain must verify against the TRUNCATED content.
	report, err := s.VerifyGuardChain(ctx)
	if err != nil || !report.OK {
		t.Errorf("VerifyGuardChain after truncation = (%+v, %v), want OK", report, err)
	}
}

// TestLoadGuardEvents_RoundTrip covers the load helpers: per-session
// ordering, recent-window filtering + limit, anchor NULL handling and
// field round-trip fidelity.
func TestLoadGuardEvents_RoundTrip(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	// Anchored rows must reference real rows (FOREIGN KEY enforced) —
	// seed an api_turn for the anchor; ActionID stays nil here (the
	// hook-path shape) since seeding a full actions row needs Ingest.
	turnID, err := s.InsertAPITurn(ctx, modelsAPITurnFixture("sA", "claude-opus-4-8", t0Guard))
	if err != nil {
		t.Fatalf("InsertAPITurn: %v", err)
	}
	withAnchor := guardEventFixture("sA", "R-104", t0Guard.Add(time.Minute))
	withAnchor.APITurnID = &turnID
	withAnchor.DegradedFrom = "ask"
	withAnchor.Enforced = true
	withAnchor.TaintOrigin = "web_fetch:example.com"
	events := []GuardEventRow{
		guardEventFixture("sA", "R-101", t0Guard),
		withAnchor,
		guardEventFixture("sB", "R-110", t0Guard.Add(2*time.Minute)),
	}
	if _, err := s.InsertGuardEvents(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}

	sA, err := s.LoadGuardEventsForSession(ctx, "sA")
	if err != nil {
		t.Fatalf("LoadGuardEventsForSession: %v", err)
	}
	if len(sA) != 2 || sA[0].RuleID != "R-101" || sA[1].RuleID != "R-104" {
		t.Fatalf("session rows = %+v, want R-101 then R-104", sA)
	}
	if sA[1].APITurnID == nil || *sA[1].APITurnID != turnID {
		t.Errorf("APITurnID round-trip failed: %v", sA[1].APITurnID)
	}
	if sA[0].ActionID != nil || sA[0].APITurnID != nil {
		t.Errorf("nil anchors round-tripped non-nil: %+v", sA[0])
	}
	if !sA[1].Enforced || sA[1].DegradedFrom != "ask" || sA[1].TaintOrigin != "web_fetch:example.com" {
		t.Errorf("field fidelity: %+v", sA[1])
	}
	if !sA[0].TS.Equal(t0Guard) {
		t.Errorf("TS round-trip = %v, want %v", sA[0].TS, t0Guard)
	}

	recent, err := s.LoadRecentGuardEvents(ctx, t0Guard.Add(30*time.Second), 10)
	if err != nil {
		t.Fatalf("LoadRecentGuardEvents: %v", err)
	}
	if len(recent) != 2 || recent[0].RuleID != "R-110" {
		t.Errorf("recent = %d rows (first %s), want 2 newest-first", len(recent), recent[0].RuleID)
	}
	limited, err := s.LoadRecentGuardEvents(ctx, time.Time{}, 1)
	if err != nil || len(limited) != 1 {
		t.Errorf("limit: rows = %d (%v), want 1", len(limited), err)
	}
}

// TestPruneGuardRows_CheckpointKeepsChainVerifiable is the §10.3
// chain-integrity-across-pruning case: prune removes the old prefix,
// writes the checkpoint, the surviving suffix verifies, and the NEXT
// insert anchors correctly (both after partial and full prunes).
func TestPruneGuardRows_CheckpointKeepsChainVerifiable(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	fresh := time.Now().UTC().Add(-time.Hour)
	events := []GuardEventRow{
		guardEventFixture("sOld", "R-101", old),
		guardEventFixture("sOld", "R-110", old.Add(time.Minute)),
		guardEventFixture("sNew", "R-152", fresh),
	}
	if _, err := s.InsertGuardEvents(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}

	removed, err := s.PruneGuardRows(ctx, 30, 0)
	if err != nil {
		t.Fatalf("PruneGuardRows: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 (the old prefix)", removed)
	}

	// The surviving suffix anchors on the checkpoint and verifies.
	report, err := s.VerifyGuardChain(ctx)
	if err != nil {
		t.Fatalf("VerifyGuardChain post-prune: %v", err)
	}
	if !report.OK || report.Checked != 1 {
		t.Fatalf("post-prune chain = %+v, want OK across 1 row", report)
	}

	// New inserts continue the chain from the surviving tail.
	next := []GuardEventRow{guardEventFixture("sNew", "R-104", time.Now().UTC())}
	if _, err := s.InsertGuardEvents(ctx, next); err != nil {
		t.Fatalf("post-prune insert: %v", err)
	}
	if next[0].ChainPrev != events[2].ChainHash {
		t.Errorf("post-prune chain_prev = %q, want surviving tail %q", next[0].ChainPrev, events[2].ChainHash)
	}

	// retentionDays <= 0 is a clean no-op (config pass-through).
	removed, err = s.PruneGuardRows(ctx, 0, 0)
	if err != nil || removed != 0 {
		t.Fatalf("retention<=0 = (%d, %v), want (0, nil) no-op", removed, err)
	}

	// FULL prune (separate store, all rows old): the table empties,
	// the checkpoint becomes the anchor for both verification and the
	// next insert.
	s2, _ := newTestStore(t)
	oldOnly := []GuardEventRow{
		guardEventFixture("s1", "R-101", old),
		guardEventFixture("s1", "R-110", old.Add(time.Second)),
	}
	if _, err := s2.InsertGuardEvents(ctx, oldOnly); err != nil {
		t.Fatalf("s2 seed: %v", err)
	}
	if n, err := s2.PruneGuardRows(ctx, 30, 0); err != nil || n != 2 {
		t.Fatalf("s2 full prune = (%d, %v), want (2, nil)", n, err)
	}
	report, err = s2.VerifyGuardChain(ctx)
	if err != nil || !report.OK || report.Checked != 0 {
		t.Fatalf("s2 empty-after-prune chain = (%+v, %v), want OK/0", report, err)
	}
	postFull := []GuardEventRow{guardEventFixture("s1", "R-152", time.Now().UTC())}
	if _, err := s2.InsertGuardEvents(ctx, postFull); err != nil {
		t.Fatalf("s2 post-full-prune insert: %v", err)
	}
	if postFull[0].ChainPrev != oldOnly[1].ChainHash {
		t.Errorf("post-full-prune anchor = %q, want checkpoint %q", postFull[0].ChainPrev, oldOnly[1].ChainHash)
	}
	if rep, err := s2.VerifyGuardChain(ctx); err != nil || !rep.OK || rep.Checked != 1 {
		t.Errorf("s2 post-insert chain = (%+v, %v), want OK/1", rep, err)
	}
}

// TestPruneGuardRows_SkewedRowRetained pins the prefix-prune
// approximation: an old-stamped row that lands AFTER a newer row
// (clock skew) is retained — pruning never punches a hole in the
// chain.
func TestPruneGuardRows_SkewedRowRetained(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	old := time.Now().UTC().Add(-100 * 24 * time.Hour)
	fresh := time.Now().UTC().Add(-time.Hour)
	events := []GuardEventRow{
		guardEventFixture("s1", "R-101", old),   // prunable prefix
		guardEventFixture("s1", "R-110", fresh), // kept
		guardEventFixture("s1", "R-152", old),   // old ts but AFTER a kept row → retained
	}
	if _, err := s.InsertGuardEvents(ctx, events); err != nil {
		t.Fatalf("seed: %v", err)
	}
	removed, err := s.PruneGuardRows(ctx, 30, 0)
	if err != nil {
		t.Fatalf("PruneGuardRows: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed = %d, want 1 (only the prefix; the skewed row is retained)", removed)
	}
	report, err := s.VerifyGuardChain(ctx)
	if err != nil || !report.OK || report.Checked != 2 {
		t.Errorf("chain = (%+v, %v), want OK across 2 surviving rows", report, err)
	}
}

// TestSummarizeGuardEvents covers the status aggregation: window
// filtering, per-enum grouping, the enforced count, and the empty
// table.
func TestSummarizeGuardEvents(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	empty, err := s.SummarizeGuardEvents(ctx, time.Time{})
	if err != nil || empty.Total != 0 {
		t.Fatalf("empty summary = (%+v, %v)", empty, err)
	}

	old := guardEventFixture("s1", "R-101", t0Guard.Add(-48*time.Hour))
	recent1 := guardEventFixture("s1", "R-110", t0Guard)
	recent1.Decision = "deny"
	recent1.Enforced = true
	recent2 := guardEventFixture("s1", "T-504", t0Guard.Add(time.Minute))
	recent2.Category = "taint"
	recent2.Severity = "critical"
	if _, err := s.InsertGuardEvents(ctx, []GuardEventRow{old, recent1, recent2}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	sum, err := s.SummarizeGuardEvents(ctx, t0Guard.Add(-time.Hour))
	if err != nil {
		t.Fatalf("SummarizeGuardEvents: %v", err)
	}
	if sum.Total != 2 {
		t.Errorf("Total = %d, want 2 (window excludes the old row)", sum.Total)
	}
	if sum.ByDecision["deny"] != 1 || sum.ByDecision["flag"] != 1 {
		t.Errorf("ByDecision = %v", sum.ByDecision)
	}
	if sum.ByCategory["taint"] != 1 || sum.ByCategory["destructive"] != 1 {
		t.Errorf("ByCategory = %v", sum.ByCategory)
	}
	if sum.Enforced != 1 {
		t.Errorf("Enforced = %d, want 1", sum.Enforced)
	}
	all, err := s.SummarizeGuardEvents(ctx, time.Time{})
	if err != nil || all.Total != 3 {
		t.Errorf("zero-since summary = (%+v, %v), want all 3 rows", all, err)
	}
}

// TestUpsertGuardPin covers the (kind, name, client) natural-identity
// upsert: first sight inserts with first_seen; re-pin updates the
// observed fields but PRESERVES first_seen.
func TestUpsertGuardPin(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	first := GuardPinRow{
		Kind: "mcp_server", Name: "github-mcp", Client: "claude-code",
		PinHash: "aaa", FirstSeen: t0Guard, LastVerified: t0Guard,
	}
	if err := s.UpsertGuardPin(ctx, first); err != nil {
		t.Fatalf("UpsertGuardPin: %v", err)
	}
	repin := first
	repin.PinHash = "bbb"
	repin.FirstSeen = t0Guard.Add(time.Hour) // must be ignored on conflict
	repin.LastVerified = t0Guard.Add(time.Hour)
	repin.Status = "drifted"
	if err := s.UpsertGuardPin(ctx, repin); err != nil {
		t.Fatalf("UpsertGuardPin re-pin: %v", err)
	}

	pins, err := s.LoadGuardPins(ctx, "mcp_server")
	if err != nil {
		t.Fatalf("LoadGuardPins: %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("pins = %d, want 1 (upsert, not duplicate)", len(pins))
	}
	p := pins[0]
	if p.PinHash != "bbb" || p.Status != "drifted" {
		t.Errorf("observed fields not updated: %+v", p)
	}
	if !p.FirstSeen.Equal(t0Guard) {
		t.Errorf("first_seen mutated on re-pin: %v, want %v", p.FirstSeen, t0Guard)
	}
	if !p.LastVerified.Equal(t0Guard.Add(time.Hour)) {
		t.Errorf("last_verified not updated: %v", p.LastVerified)
	}

	// Validation: kind and name are required.
	if err := s.UpsertGuardPin(ctx, GuardPinRow{Kind: "", Name: "x"}); err == nil {
		t.Error("UpsertGuardPin accepted empty kind")
	}
	// Same name under a different client is a distinct pin.
	other := first
	other.Client = "cursor"
	if err := s.UpsertGuardPin(ctx, other); err != nil {
		t.Fatalf("UpsertGuardPin other client: %v", err)
	}
	if pins, _ := s.LoadGuardPins(ctx, ""); len(pins) != 2 {
		t.Errorf("all pins = %d, want 2 (per-client identity)", len(pins))
	}
}

// TestUpdateGuardPinStatus covers the approve surface: status flips
// per (kind, name) across clients or scoped to one, last_verified
// stamps, hashes untouched, and a missing pin reports 0 rows.
func TestUpdateGuardPinStatus(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	for _, client := range []string{"claude-code", "cursor"} {
		if err := s.UpsertGuardPin(ctx, GuardPinRow{
			Kind: "mcp_server", Name: "github", Client: client,
			PinHash: "hh", FirstSeen: t0Guard, LastVerified: t0Guard, Status: "pinned",
		}); err != nil {
			t.Fatalf("UpsertGuardPin: %v", err)
		}
	}
	later := t0Guard.Add(2 * time.Hour)

	n, err := s.UpdateGuardPinStatus(ctx, "mcp_server", "github", "cursor", "approved", later)
	if err != nil || n != 1 {
		t.Fatalf("scoped update = %d, %v; want 1 row", n, err)
	}
	n, err = s.UpdateGuardPinStatus(ctx, "mcp_server", "github", "", "approved", later)
	if err != nil || n != 2 {
		t.Fatalf("all-clients update = %d, %v; want 2 rows", n, err)
	}
	pins, err := s.LoadGuardPins(ctx, "mcp_server")
	if err != nil {
		t.Fatalf("LoadGuardPins: %v", err)
	}
	for _, p := range pins {
		if p.Status != "approved" || p.PinHash != "hh" || !p.LastVerified.Equal(later) {
			t.Errorf("pin after approve = %+v", p)
		}
	}
	if n, err := s.UpdateGuardPinStatus(ctx, "mcp_server", "nope", "", "approved", later); err != nil || n != 0 {
		t.Errorf("missing pin update = %d, %v; want 0 rows, nil", n, err)
	}
	if _, err := s.UpdateGuardPinStatus(ctx, "", "github", "", "approved", later); err == nil {
		t.Error("UpdateGuardPinStatus accepted empty kind")
	}
}

// TestGuardMCPServerApproved pins the taint-lookup semantics: true
// only when ≥1 approved row AND zero drifted rows exist for the name.
func TestGuardMCPServerApproved(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pin := func(client, status string) {
		t.Helper()
		if err := s.UpsertGuardPin(ctx, GuardPinRow{
			Kind: "mcp_server", Name: "github", Client: client,
			PinHash: "hh", FirstSeen: t0Guard, LastVerified: t0Guard, Status: status,
		}); err != nil {
			t.Fatalf("UpsertGuardPin: %v", err)
		}
	}

	if ok, err := s.GuardMCPServerApproved(ctx, "github"); err != nil || ok {
		t.Fatalf("no pins = %v, %v; want false", ok, err)
	}
	pin("claude-code", "pinned")
	if ok, _ := s.GuardMCPServerApproved(ctx, "github"); ok {
		t.Fatal("pinned-unapproved reported approved")
	}
	pin("claude-code", "approved")
	if ok, _ := s.GuardMCPServerApproved(ctx, "github"); !ok {
		t.Fatal("approved pin not reported")
	}
	// A drifted row under ANY client suspends trust until re-approval.
	pin("cursor", "drifted")
	if ok, _ := s.GuardMCPServerApproved(ctx, "github"); ok {
		t.Fatal("drifted row did not suspend approval")
	}
	if ok, err := s.GuardMCPServerApproved(ctx, ""); err != nil || ok {
		t.Errorf("empty name = %v, %v; want false, nil", ok, err)
	}
}

// TestRecordGuardPolicyState covers the append-if-changed version log:
// identical reloads are silent; content changes append; latest-per-
// (layer, path) reads back the effective set.
func TestRecordGuardPolicyState(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	row := GuardPolicyStateRow{
		Layer: "user", Path: "~/.observer/guard-policy.toml",
		Version: "", ContentHash: "h1", LoadedAt: t0Guard,
	}
	appended, err := s.RecordGuardPolicyState(ctx, row)
	if err != nil || !appended {
		t.Fatalf("first record = (%v, %v), want (true, nil)", appended, err)
	}
	// Unchanged reload (daemon restart): silent.
	row.LoadedAt = t0Guard.Add(time.Hour)
	appended, err = s.RecordGuardPolicyState(ctx, row)
	if err != nil || appended {
		t.Fatalf("unchanged reload = (%v, %v), want (false, nil)", appended, err)
	}
	// Content change: appends a new version row.
	row.ContentHash = "h2"
	appended, err = s.RecordGuardPolicyState(ctx, row)
	if err != nil || !appended {
		t.Fatalf("changed record = (%v, %v), want (true, nil)", appended, err)
	}
	// A second source on another layer.
	org := GuardPolicyStateRow{
		Layer: "org", Path: "https://org.example/policy-bundle",
		Version: "7", ContentHash: "h9", Signature: "sig-bytes", LoadedAt: t0Guard,
	}
	if _, err := s.RecordGuardPolicyState(ctx, org); err != nil {
		t.Fatalf("org record: %v", err)
	}

	latest, err := s.LatestGuardPolicyStates(ctx)
	if err != nil {
		t.Fatalf("LatestGuardPolicyStates: %v", err)
	}
	if len(latest) != 2 {
		t.Fatalf("latest = %d rows, want 2 (one per layer+path)", len(latest))
	}
	// Ordered by layer: org first, then user.
	if latest[0].Layer != "org" || latest[0].Signature != "sig-bytes" || latest[0].Version != "7" {
		t.Errorf("org latest = %+v", latest[0])
	}
	if latest[1].Layer != "user" || latest[1].ContentHash != "h2" {
		t.Errorf("user latest = %+v (want the h2 version)", latest[1])
	}

	// Validation: layer and path required.
	if _, err := s.RecordGuardPolicyState(ctx, GuardPolicyStateRow{Layer: "", Path: "p"}); err == nil {
		t.Error("RecordGuardPolicyState accepted empty layer")
	}
}

// TestGuardApprovals covers the exception register: insert, expiry
// filtering against now, the non-expiring ” sentinel, rule filtering,
// and prune semantics (only expired AND old rows age out).
func TestGuardApprovals(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	grants := []GuardApprovalRow{
		{
			TS: now.Add(-100 * 24 * time.Hour), RuleID: "R-110", Scope: "project",
			ProjectRootHash: "ph1", GrantedBy: "operator", ExpiresAt: now.Add(-99 * 24 * time.Hour),
		}, // expired + old → prunable
		{
			TS: now.Add(-time.Hour), RuleID: "R-110", Scope: "session",
			SessionID: "sA", GrantedBy: "operator", ExpiresAt: now.Add(time.Hour),
		}, // live
		{
			TS: now.Add(-100 * 24 * time.Hour), RuleID: "R-152", Scope: "global",
			GrantedBy: "operator",
		}, // non-expiring → never prunable, always active
		{
			TS: now.Add(-time.Minute), RuleID: "R-152", Scope: "once",
			SessionID: "sB", GrantedBy: "operator", ExpiresAt: now.Add(-time.Second),
		}, // expired but recent → kept, inactive
	}
	for i, g := range grants {
		if _, err := s.InsertGuardApproval(ctx, g); err != nil {
			t.Fatalf("InsertGuardApproval[%d]: %v", i, err)
		}
	}
	if _, err := s.InsertGuardApproval(ctx, GuardApprovalRow{RuleID: "", Scope: "global"}); err == nil {
		t.Error("InsertGuardApproval accepted empty rule_id")
	}

	active, err := s.ActiveGuardApprovals(ctx, "", now)
	if err != nil {
		t.Fatalf("ActiveGuardApprovals: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("active = %d, want 2 (live session grant + non-expiring global)", len(active))
	}
	byRule, err := s.ActiveGuardApprovals(ctx, "R-152", now)
	if err != nil || len(byRule) != 1 || byRule[0].Scope != "global" {
		t.Errorf("rule filter = %+v (%v), want the one global R-152 grant", byRule, err)
	}
	if byRule[0].ExpiresAt != (time.Time{}) {
		t.Errorf("non-expiring grant ExpiresAt = %v, want zero", byRule[0].ExpiresAt)
	}

	removed, err := s.PruneGuardRows(ctx, 30, 0)
	if err != nil {
		t.Fatalf("PruneGuardRows: %v", err)
	}
	// The total also counts guard_events: since P-232 every grant writes an
	// audit event at its grant time, and the two 100-day-old ones age out
	// under the same retention. The register itself loses exactly one row.
	var approvalsLeft int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM guard_approvals`).Scan(&approvalsLeft); err != nil {
		t.Fatal(err)
	}
	if approvalsLeft != 3 || removed < 1 {
		t.Errorf("pruned = %d, approvals left = %d, want the one expired+old grant gone (3 left)", removed, approvalsLeft)
	}
	remaining, err := s.ActiveGuardApprovals(ctx, "", now.Add(-2*time.Hour))
	if err != nil {
		t.Fatalf("ActiveGuardApprovals post-prune: %v", err)
	}
	// At now-2h, the recent expired grant was still live; the pruned
	// one is gone — 4 seeded - 1 pruned = 3 rows remain, all of which
	// were unexpired at that reference time.
	if len(remaining) != 3 {
		t.Errorf("post-prune rows visible at -2h = %d, want 3", len(remaining))
	}
}
