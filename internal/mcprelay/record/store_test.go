// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package record

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "node.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

func newStore(t *testing.T) *SQLStore {
	t.Helper()
	return NewSQLStore(openDB(t), "node-key-1")
}

func decision(ts int64, callID string) Record {
	return Record{
		Kind: KindDecision, TS: ts, VServer: "vs-github", ServerRefHMAC: "h-server", ToolRefHMAC: "h-tool",
		CallID: callID, CorrConfidence: CorrExact, Method: "tools/call", EventKind: EventCall,
		Decision: DecisionAllow, ClientAttestation: AttestProcess, CredentialAssurance: "node_enrolled",
		CaptureLevel: CaptureL0,
	}
}

func completion(ts int64, callID string, decisionSeq int64) Record {
	return Record{
		Kind: KindCompletion, TS: ts, CallID: callID, DecisionSeq: Int(decisionSeq),
		CaptureLevel: CaptureL0, ResultStatus: "ok", ResultSizeBytes: Int(120), LatencyMS: Int(35),
	}
}

func gap(ts, from, to, lost int64) Record {
	return Record{Kind: KindGap, TS: ts, GapFrom: Int(from), GapTo: Int(to), LostCount: Int(lost), GapReason: "local_append_failed"}
}

func resolution(ts, resolves, from, to int64, how Resolution) Record {
	return Record{Kind: KindGapResolution, TS: ts, ResolvesSeq: Int(resolves), ResolvedRangeStart: Int(from), ResolvedRangeEnd: Int(to), Resolution: how}
}

// TestMigration131CreatesRelayTables pins the three node-local tables.
func TestMigration131CreatesRelayTables(t *testing.T) {
	d := openDB(t)
	for _, table := range []string{"mcp_relay_state", "mcp_relay_launch_spec", "mcp_relay_record"} {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Errorf("table %s: n=%d err=%v", table, n, err)
		}
	}
}

// rawInsert bypasses Validate and drives the row straight at the DDL's
// CHECKs, so the matrix below proves Validate MIRRORS the schema rather than
// merely agreeing with itself.
func rawInsert(t *testing.T, d *sql.DB, rec Record) error {
	t.Helper()
	ctx := context.Background()
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if rec.Family == "" {
		rec.Family = DefaultFamily
	}
	head := Head{Seq: 0, Hash: Genesis("x")}
	_ = tx.QueryRowContext(ctx, `SELECT seq, chain_hash FROM mcp_relay_record ORDER BY seq DESC LIMIT 1`).Scan(&head.Seq, &head.Hash)
	if _, err := insertChainedTx(ctx, tx, rec, &head); err != nil {
		return err
	}
	return tx.Commit()
}

// TestValidateMirrorsDDLCheckMatrix is the CHECK matrix: every row is run
// through Validate AND through a raw insert, and the two verdicts must agree.
func TestValidateMirrorsDDLCheckMatrix(t *testing.T) {
	d := openDB(t)
	// Parents for the completion / resolution rows (raw, valid).
	if err := rawInsert(t, d, decision(1000, "c-parent")); err != nil {
		t.Fatalf("seed decision: %v", err)
	}
	if err := rawInsert(t, d, gap(1001, 900, 950, 2)); err != nil {
		t.Fatalf("seed gap: %v", err)
	}
	mut := func(base Record, f func(*Record)) Record { f(&base); return base }
	cases := []struct {
		name string
		rec  Record
		ok   bool
	}{
		{"decision L0", decision(1002, "c1"), true},
		{"decision L1 excerpt", mut(decision(1002, "c1"), func(r *Record) { r.CaptureLevel = CaptureL1; r.ArgsExcerpt = `{"a":1}` }), true},
		{"decision L2 args_full", mut(decision(1002, "c1"), func(r *Record) {
			r.CaptureLevel = CaptureL2
			r.Server = "github"
			r.Tool = "create_issue"
			r.ArgsFull = `{"title":"x"}`
			r.ArgsScrubStatus = ScrubStructured
		}), true},
		{"decision missing call_id", mut(decision(1002, "c1"), func(r *Record) { r.CallID = "" }), false},
		{"decision missing corr_confidence", mut(decision(1002, "c1"), func(r *Record) { r.CorrConfidence = "" }), false},
		{"decision missing capture_level", mut(decision(1002, "c1"), func(r *Record) { r.CaptureLevel = "" }), false},
		{"decision missing event_kind", mut(decision(1002, "c1"), func(r *Record) { r.EventKind = "" }), false},
		{"decision missing decision", mut(decision(1002, "c1"), func(r *Record) { r.Decision = "" }), false},
		{"decision bad decision enum", mut(decision(1002, "c1"), func(r *Record) { r.Decision = "maybe" }), false},
		{"decision bad event enum", mut(decision(1002, "c1"), func(r *Record) { r.EventKind = "mcp_other" }), false},
		{"decision bad attestation enum", mut(decision(1002, "c1"), func(r *Record) { r.ClientAttestation = "sworn" }), false},
		{"decision bad corr enum", mut(decision(1002, "c1"), func(r *Record) { r.CorrConfidence = "guess" }), false},
		{"decision L0 with excerpt", mut(decision(1002, "c1"), func(r *Record) { r.ArgsExcerpt = "x" }), false},
		{"decision L1 with args_full", mut(decision(1002, "c1"), func(r *Record) { r.CaptureLevel = CaptureL1; r.ArgsFull = "x" }), false},
		{"decision L2 bad scrub status", mut(decision(1002, "c1"), func(r *Record) { r.CaptureLevel = CaptureL2; r.ArgsFull = "x"; r.ArgsScrubStatus = "partial" }), false},
		{"decision carrying result_full", mut(decision(1002, "c1"), func(r *Record) { r.CaptureLevel = CaptureL2; r.ResultFull = "x" }), false},
		{"decision carrying result_status", mut(decision(1002, "c1"), func(r *Record) { r.ResultStatus = "ok" }), false},
		{"decision carrying latency", mut(decision(1002, "c1"), func(r *Record) { r.LatencyMS = Int(1) }), false},
		{"decision carrying decision_seq", mut(decision(1002, "c1"), func(r *Record) { r.DecisionSeq = Int(1) }), false},
		{"decision carrying gap range", mut(decision(1002, "c1"), func(r *Record) { r.GapFrom = Int(1) }), false},
		{"decision carrying resolution", mut(decision(1002, "c1"), func(r *Record) { r.Resolution = ResolutionLateArrival }), false},

		{"completion L0", completion(1003, "c-parent", 1), true},
		{"completion L2 result_full", mut(completion(1003, "c-parent", 1), func(r *Record) {
			r.CaptureLevel = CaptureL2
			r.ResultFull = `{"ok":true}`
			r.ResultScrubStatus = ScrubStructured
			r.ErrorFull = `{"code":1}`
			r.ErrorScrubStatus = ScrubRedacted
			r.ElicitationFull = `{}`
			r.ElicitationScrubStatus = ScrubTruncated
		}), true},
		{"completion missing result_status", mut(completion(1003, "c-parent", 1), func(r *Record) { r.ResultStatus = "" }), false},
		{"completion missing decision_seq", mut(completion(1003, "c-parent", 1), func(r *Record) { r.DecisionSeq = nil }), false},
		{"completion missing call_id", mut(completion(1003, "c-parent", 1), func(r *Record) { r.CallID = "" }), false},
		{"completion missing capture_level", mut(completion(1003, "c-parent", 1), func(r *Record) { r.CaptureLevel = "" }), false},
		{"completion carrying a decision", mut(completion(1003, "c-parent", 1), func(r *Record) { r.Decision = DecisionAllow }), false},
		{"completion carrying corr_confidence", mut(completion(1003, "c-parent", 1), func(r *Record) { r.CorrConfidence = CorrExact }), false},
		{"completion carrying tool", mut(completion(1003, "c-parent", 1), func(r *Record) { r.Tool = "t" }), false},
		{"completion carrying args_full", mut(completion(1003, "c-parent", 1), func(r *Record) { r.CaptureLevel = CaptureL2; r.ArgsFull = "x" }), false},
		{"completion L1 with result_full", mut(completion(1003, "c-parent", 1), func(r *Record) { r.CaptureLevel = CaptureL1; r.ResultFull = "x" }), false},
		{"completion L0 with error_full", mut(completion(1003, "c-parent", 1), func(r *Record) { r.ErrorFull = "x" }), false},
		{"completion carrying attestation", mut(completion(1003, "c-parent", 1), func(r *Record) { r.ClientAttestation = AttestClaimed }), false},
		{"completion carrying gap range", mut(completion(1003, "c-parent", 1), func(r *Record) { r.GapTo = Int(1) }), false},

		{"gap", gap(1004, 900, 950, 2), true},
		{"gap missing lost_count", mut(gap(1004, 900, 950, 2), func(r *Record) { r.LostCount = nil }), false},
		{"gap missing reason", mut(gap(1004, 900, 950, 2), func(r *Record) { r.GapReason = "" }), false},
		{"gap missing gap_to", mut(gap(1004, 900, 950, 2), func(r *Record) { r.GapTo = nil }), false},
		{"gap carrying call_id", mut(gap(1004, 900, 950, 2), func(r *Record) { r.CallID = "c" }), false},
		{"gap carrying capture_level", mut(gap(1004, 900, 950, 2), func(r *Record) { r.CaptureLevel = CaptureL0 }), false},
		{"gap carrying corr_confidence", mut(gap(1004, 900, 950, 2), func(r *Record) { r.CorrConfidence = CorrNone }), false},
		{"gap carrying resolution", mut(gap(1004, 900, 950, 2), func(r *Record) { r.Resolution = ResolutionConfirmedLoss }), false},
		{"gap carrying result_size", mut(gap(1004, 900, 950, 2), func(r *Record) { r.ResultSizeBytes = Int(1) }), false},
		{"gap carrying trace_id", mut(gap(1004, 900, 950, 2), func(r *Record) { r.TraceID = "t" }), false},

		{"gap_resolution", resolution(1005, 2, 900, 920, ResolutionLateArrival), true},
		{"gap_resolution reversed range", resolution(1005, 2, 920, 900, ResolutionLateArrival), false},
		{"gap_resolution missing resolution", mut(resolution(1005, 2, 900, 920, ResolutionLateArrival), func(r *Record) { r.Resolution = "" }), false},
		{"gap_resolution bad resolution enum", mut(resolution(1005, 2, 900, 920, ResolutionLateArrival), func(r *Record) { r.Resolution = "shrug" }), false},
		{"gap_resolution missing resolves_seq", mut(resolution(1005, 2, 900, 920, ResolutionLateArrival), func(r *Record) { r.ResolvesSeq = nil }), false},
		{"gap_resolution carrying gap range", mut(resolution(1005, 2, 900, 920, ResolutionLateArrival), func(r *Record) { r.GapFrom = Int(1) }), false},
		{"gap_resolution carrying capture_level", mut(resolution(1005, 2, 900, 920, ResolutionLateArrival), func(r *Record) { r.CaptureLevel = CaptureL2 }), false},
		{"gap_resolution carrying decision", mut(resolution(1005, 2, 900, 920, ResolutionLateArrival), func(r *Record) { r.Decision = DecisionDeny }), false},
		{"gap_resolution carrying args_excerpt", mut(resolution(1005, 2, 900, 920, ResolutionLateArrival), func(r *Record) { r.ArgsExcerpt = "x" }), false},

		{"unknown kind", Record{Kind: "note", TS: 1}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verr := tc.rec.Validate()
			ierr := rawInsert(t, d, tc.rec)
			if (verr == nil) != tc.ok {
				t.Errorf("Validate: err=%v, want ok=%v", verr, tc.ok)
			}
			if (ierr == nil) != tc.ok {
				t.Errorf("DDL CHECK: err=%v, want ok=%v", ierr, tc.ok)
			}
			if verr != nil && !errors.Is(verr, ErrInvalid) {
				t.Errorf("Validate error %v does not wrap ErrInvalid", verr)
			}
		})
	}
}

// TestAppendChainsAndVerifies: append, read back byte-identically, verify from
// genesis, then tamper in three ways and see each caught at the right seq.
func TestAppendChainsAndVerifies(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	head, err := s.Head(ctx)
	if err != nil || head.Seq != 0 || !bytes.Equal(head.Hash, Genesis("node-key-1")) {
		t.Fatalf("empty head = %+v err=%v, want seq 0 + genesis", head, err)
	}
	r1, err := s.Append(ctx, decision(1000, "c1"))
	if err != nil {
		t.Fatalf("append decision: %v", err)
	}
	if r1.Gap != nil || r1.Record.Seq != 1 || !bytes.Equal(r1.Record.ChainPrev, Genesis("node-key-1")) {
		t.Fatalf("first append = %+v", r1)
	}
	r2, err := s.Append(ctx, completion(1001, "c1", 1))
	if err != nil {
		t.Fatalf("append completion: %v", err)
	}
	if r2.Record.Seq != 2 || !bytes.Equal(r2.Record.ChainPrev, r1.Record.ChainHash) {
		t.Fatalf("second append did not link: %+v", r2.Record)
	}
	got, err := s.Get(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(Canonical(got), Canonical(r2.Record)) {
		t.Fatalf("round-trip changed the canonical bytes:\n%s\n%s", Canonical(got), Canonical(r2.Record))
	}
	if *got.ResultSizeBytes != 120 || *got.LatencyMS != 35 || *got.DecisionSeq != 1 {
		t.Fatalf("nullable ints lost: %+v", got)
	}
	res, err := s.Verify(ctx)
	if err != nil || !res.OK() || res.Records != 2 || res.HeadSeq != 2 {
		t.Fatalf("verify = %+v err=%v", res, err)
	}

	// Tamper 1: rewrite a hashed column.
	if _, err := s.db.Exec(`UPDATE mcp_relay_record SET result_status = 'forged' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	res, _ = s.Verify(ctx)
	if res.OK() || res.Fault.Seq != 2 || !errors.Is(res.Fault, ErrTamper) {
		t.Fatalf("rewritten row not caught: %+v", res)
	}
	if _, err := s.db.Exec(`UPDATE mcp_relay_record SET result_status = 'ok' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	// Tamper 2: break the link.
	if _, err := s.db.Exec(`UPDATE mcp_relay_record SET chain_prev = X'00' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	res, _ = s.Verify(ctx)
	if res.OK() || res.Fault.Seq != 2 || !strings.Contains(res.Fault.Reason, "chain_prev") {
		t.Fatalf("broken link not caught: %+v", res)
	}
	if _, err := s.db.Exec(`UPDATE mcp_relay_record SET chain_prev = ? WHERE seq = 2`, r1.Record.ChainHash); err != nil {
		t.Fatal(err)
	}
	// Tamper 3: a hole in the id space (delete the completion, re-append at 4).
	if _, err := s.db.Exec(`DELETE FROM mcp_relay_record WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE sqlite_sequence SET seq = 3 WHERE name = 'mcp_relay_record'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO mcp_relay_record (seq, record_kind, ts, family, gap_from, gap_to, lost_count, gap_reason, chain_prev, chain_hash)
		VALUES (4, 'gap', 5, 'tools.mcp_access', 1, 2, 1, 'x', ?, X'00')`, r1.Record.ChainHash); err != nil {
		t.Fatal(err)
	}
	res, _ = s.Verify(ctx)
	if res.OK() || res.Fault.Seq != 4 || !strings.Contains(res.Fault.Reason, "contiguous") {
		t.Fatalf("hole not caught: %+v", res)
	}
}

// TestAppendFoldsPendingLossIntoGap pins R13.5 step 3: the next successful
// append writes the gap row FIRST, in the same transaction that zeroes the
// pending-loss columns, and the chain still verifies.
func TestAppendFoldsPendingLossIntoGap(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.SetPendingLoss(ctx, DefaultFamily, PendingLoss{Count: 3, FirstAt: 900, LastAt: 950, Reason: "disk_full", CallIDs: []string{"a", "b", "c"}}); err != nil {
		t.Fatal(err)
	}
	pl, err := s.PendingLoss(ctx, DefaultFamily)
	if err != nil || pl.Count != 3 || len(pl.CallIDs) != 3 || pl.Reason != "disk_full" {
		t.Fatalf("pending loss = %+v err=%v", pl, err)
	}
	res, err := s.Append(ctx, decision(1000, "c1"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Gap == nil || res.Gap.Kind != KindGap || res.Gap.Seq != 1 || res.Record.Seq != 2 {
		t.Fatalf("gap not folded first: %+v", res)
	}
	if *res.Gap.GapFrom != 900 || *res.Gap.GapTo != 950 || *res.Gap.LostCount != 3 || res.Gap.GapReason != "disk_full" {
		t.Fatalf("gap row = %+v", res.Gap)
	}
	pl, _ = s.PendingLoss(ctx, DefaultFamily)
	if pl.Count != 0 || pl.FirstAt != 0 || pl.Reason != "" || pl.CallIDs != nil {
		t.Fatalf("pending loss not zeroed: %+v", pl)
	}
	v, _ := s.Verify(ctx)
	if !v.OK() || v.Records != 2 {
		t.Fatalf("verify after fold = %+v", v)
	}
	// A second append writes no second gap.
	res, err = s.Append(ctx, decision(1001, "c2"))
	if err != nil || res.Gap != nil || res.Record.Seq != 3 {
		t.Fatalf("second append = %+v err=%v", res, err)
	}
	// Call ids are capped at 64 on the way in.
	ids := make([]string, 100)
	for i := range ids {
		ids[i] = "id"
	}
	if err := s.SetPendingLoss(ctx, DefaultFamily, PendingLoss{Count: 100, FirstAt: 1, LastAt: 2, CallIDs: ids}); err != nil {
		t.Fatal(err)
	}
	pl, _ = s.PendingLoss(ctx, DefaultFamily)
	if len(pl.CallIDs) != MaxPendingLossCallIDs {
		t.Fatalf("call ids = %d, want cap %d", len(pl.CallIDs), MaxPendingLossCallIDs)
	}
}

// TestGapResolutionParentRules pins R14.3's store-seam checks: nonexistent,
// wrong-kind, reversed, out-of-range are rejected; duplicate and overlapping
// resolutions are accepted (idempotent; effective loss is a surface concern).
func TestGapResolutionParentRules(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.Append(ctx, decision(1000, "c1")); err != nil { // seq 1
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, gap(1001, 900, 950, 2)); err != nil { // seq 2
		t.Fatal(err)
	}
	cases := []struct {
		name string
		rec  Record
		ok   bool
	}{
		{"nonexistent parent", resolution(1002, 99, 900, 910, ResolutionLateArrival), false},
		{"wrong-kind parent", resolution(1002, 1, 900, 910, ResolutionLateArrival), false},
		{"reversed range", resolution(1002, 2, 920, 910, ResolutionLateArrival), false},
		{"out of range low", resolution(1002, 2, 890, 910, ResolutionLateArrival), false},
		{"out of range high", resolution(1002, 2, 940, 960, ResolutionConfirmedLoss), false},
		{"in range", resolution(1002, 2, 900, 920, ResolutionLateArrival), true},
		{"duplicate", resolution(1003, 2, 900, 920, ResolutionLateArrival), true},
		{"overlapping", resolution(1004, 2, 910, 950, ResolutionConfirmedLoss), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Append(ctx, tc.rec)
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v, want ok=%v", err, tc.ok)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("error %v does not wrap ErrInvalid", err)
			}
		})
	}
	v, _ := s.Verify(ctx)
	if !v.OK() || v.Records != 5 {
		t.Fatalf("verify = %+v", v)
	}
}

// TestCompletionParentRules: a completion must point at an existing DECISION.
func TestCompletionParentRules(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.Append(ctx, gap(1000, 1, 2, 1)); err != nil { // seq 1
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, completion(1001, "c", 1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("completion on a gap parent: err=%v, want ErrInvalid", err)
	}
	if _, err := s.Append(ctx, completion(1001, "c", 7)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("completion on a missing parent: err=%v, want ErrInvalid", err)
	}
}

// TestReadOnlyStoreCannotChain: the push composer's keyless store reads but
// never appends or verifies.
func TestReadOnlyStoreCannotChain(t *testing.T) {
	d := openDB(t)
	w := NewSQLStore(d, "node-key-1")
	ctx := context.Background()
	if _, err := w.Append(ctx, decision(1000, "c1")); err != nil {
		t.Fatal(err)
	}
	ro := NewSQLStore(d, "")
	if _, err := ro.Append(ctx, decision(1001, "c2")); !errors.Is(err, ErrNoNodeKey) {
		t.Fatalf("read-only append err=%v, want ErrNoNodeKey", err)
	}
	if _, err := ro.Verify(ctx); !errors.Is(err, ErrNoNodeKey) {
		t.Fatalf("read-only verify err=%v, want ErrNoNodeKey", err)
	}
	rows, err := ro.ReadAfter(ctx, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read-only ReadAfter = %d rows err=%v", len(rows), err)
	}
	limited, _ := ro.ReadAfter(ctx, 1, 10)
	if len(limited) != 0 {
		t.Fatalf("ReadAfter(1) = %d rows, want 0", len(limited))
	}
}

// TestDailyActivityAggregatesDecisionsOnly pins the wire aggregate's shape.
func TestDailyActivityAggregatesDecisionsOnly(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	const day = int64(1_700_000_000) // 2023-11-14
	for i, c := range []string{"a", "b", "c"} {
		if _, err := s.Append(ctx, decision(day+int64(i), c)); err != nil {
			t.Fatal(err)
		}
	}
	denied := decision(day+10, "d")
	denied.Decision = DecisionDeny
	if _, err := s.Append(ctx, denied); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, completion(day+11, "a", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(ctx, gap(day+12, 1, 2, 1)); err != nil {
		t.Fatal(err)
	}
	old := decision(day-90_000, "old")
	if _, err := s.Append(ctx, old); err != nil {
		t.Fatal(err)
	}
	agg, err := s.DailyActivity(ctx, day-3600)
	if err != nil {
		t.Fatal(err)
	}
	if len(agg) != 2 {
		t.Fatalf("buckets = %+v, want allow x3 + deny x1", agg)
	}
	if agg[0].Day != "2023-11-14" || agg[0].Decision != DecisionAllow || agg[0].N != 3 || agg[0].ToolRefHMAC != "h-tool" || agg[0].ClientAttestation != AttestProcess {
		t.Fatalf("allow bucket = %+v", agg[0])
	}
	if agg[1].Decision != DecisionDeny || agg[1].N != 1 {
		t.Fatalf("deny bucket = %+v", agg[1])
	}
}

// TestLaunchSpecJournalCAS pins the crash-safe journal + generation CAS.
func TestLaunchSpecJournalCAS(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	spec := LaunchSpec{
		Client: "claude-code", ConfigPath: "/home/dev/.claude.json", EntryKey: "github",
		OrigCommand: "npx", OrigArgs: []string{"-y", "@modelcontextprotocol/server-github"},
		OrigCwd: "/repo", OrigEnvRefs: []string{"GITHUB_TOKEN"},
		ConfigGeneration: 1, BackupPath: "/home/dev/.observer/backups/claude.json.1", BackupSHA256: "abc", AppliedAt: 1000,
	}
	if err := s.PutLaunchSpec(ctx, spec, 0); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if err := s.PutLaunchSpec(ctx, spec, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("re-insert err=%v, want ErrConflict", err)
	}
	// A pre-132-shaped put (no applied digest) reads back as "" (NULL).
	if got, err := s.GetLaunchSpec(ctx, "claude-code", "/home/dev/.claude.json", "github"); err != nil || got.AppliedSHA256 != "" || got.VServer != "" || got.RegistryServerID != "" {
		t.Fatalf("applied digest / binding before recorded = %q %q %q (%v), want NULL", got.AppliedSHA256, got.VServer, got.RegistryServerID, err)
	}
	next := spec
	next.ConfigGeneration, next.AppliedAt, next.BackupSHA256 = 2, 1001, "def"
	next.AppliedSHA256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	next.VServer, next.RegistryServerID = "vs-gh", "gh"
	if err := s.PutLaunchSpec(ctx, next, 5); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS err=%v, want ErrConflict", err)
	}
	if err := s.PutLaunchSpec(ctx, next, 1); err != nil {
		t.Fatalf("CAS update: %v", err)
	}
	got, err := s.GetLaunchSpec(ctx, "claude-code", "/home/dev/.claude.json", "github")
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigGeneration != 2 || got.BackupSHA256 != "def" || got.OrigArgs[1] != "@modelcontextprotocol/server-github" || got.OrigEnvRefs[0] != "GITHUB_TOKEN" || got.OrigCwd != "/repo" {
		t.Fatalf("round trip = %+v", got)
	}
	if got.AppliedSHA256 != next.AppliedSHA256 {
		t.Fatalf("applied_sha256 round trip = %q, want %q (migration 132)", got.AppliedSHA256, next.AppliedSHA256)
	}
	if got.VServer != "vs-gh" || got.RegistryServerID != "gh" {
		t.Fatalf("binding round trip = %q/%q, want vs-gh/gh (migration 133)", got.VServer, got.RegistryServerID)
	}
	if all, _ := s.ListLaunchSpecs(ctx); len(all) != 1 || all[0].VServer != "vs-gh" || all[0].RegistryServerID != "gh" {
		t.Fatalf("list binding = %+v", all)
	}
	if err := s.PutLaunchSpec(ctx, LaunchSpec{Client: "x"}, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid spec err=%v, want ErrInvalid", err)
	}
	all, _ := s.ListLaunchSpecs(ctx)
	if len(all) != 1 {
		t.Fatalf("list = %d", len(all))
	}
	if err := s.DeleteLaunchSpec(ctx, "claude-code", "/home/dev/.claude.json", "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetLaunchSpec(ctx, "claude-code", "/home/dev/.claude.json", "github"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete err=%v, want ErrNotFound", err)
	}
}

// TestStatePolicyAndPendingLossAreIndependentColumns: PutState never touches
// the pending-loss accounting and SetPendingLoss never touches policy state.
func TestStatePolicyAndPendingLossAreIndependentColumns(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if _, err := s.State(ctx, DefaultFamily); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent state err=%v, want ErrNotFound", err)
	}
	if err := s.PutState(ctx, State{Family: DefaultFamily, RunningVersion: 7, EffectiveHash: "h7", Status: "applied", Mode: "enforce", LastApplied: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPendingLoss(ctx, DefaultFamily, PendingLoss{Count: 2, FirstAt: 10, LastAt: 20, Reason: "r"}); err != nil {
		t.Fatal(err)
	}
	st, err := s.State(ctx, DefaultFamily)
	if err != nil {
		t.Fatal(err)
	}
	if st.RunningVersion != 7 || st.EffectiveHash != "h7" || st.Mode != "enforce" || st.PendingLoss.Count != 2 || st.PendingLoss.LastAt != 20 {
		t.Fatalf("state = %+v", st)
	}
	if err := s.PutState(ctx, State{Family: DefaultFamily, RunningVersion: 8, EffectiveHash: "h8", Status: "applied", Mode: "advise", LastApplied: 1001}); err != nil {
		t.Fatal(err)
	}
	st, _ = s.State(ctx, DefaultFamily)
	if st.RunningVersion != 8 || st.PendingLoss.Count != 2 {
		t.Fatalf("PutState clobbered pending loss or lost the update: %+v", st)
	}
}

// TestCanonicalIsStableAndDomainPrefixed pins the encoding W4B's verifier and
// any future migration depend on.
func TestCanonicalIsStableAndDomainPrefixed(t *testing.T) {
	r := decision(1000, "c1")
	r.Seq = 3
	c := string(Canonical(r))
	if !strings.HasPrefix(c, canonicalDomain+"\n") || !strings.Contains(c, "seq=1:3\n") || !strings.Contains(c, "call_id=2:c1\n") || !strings.Contains(c, "decision_seq=0:\n") {
		t.Fatalf("canonical = %q", c)
	}
	if !bytes.Equal(Genesis("k"), Genesis("k")) || bytes.Equal(Genesis("k"), Genesis("j")) {
		t.Fatal("genesis is not a pure function of the node key")
	}
	if bytes.Equal(HashRecord([]byte("a"), []byte("b")), HashRecord([]byte("b"), []byte("a"))) {
		t.Fatal("hash must bind operand order")
	}
}
