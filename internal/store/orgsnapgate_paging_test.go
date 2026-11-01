// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/procmodel"
)

// This file pins snapshot PAGING (lane DEMOARCHIVE, bug 1 of
// docs/handovers/demo-archive-bloat-bugs-2026-10-27.md): a snapshot family
// whose rows exceed the envelope's snapshot budget must make forward progress
// across pushes, commit once every row has been accepted by the server, and
// then go quiet until its data changes. Before the fix, fitRows kept the same
// leading prefix on every push (the recompute is deterministic), the tail never
// shipped, the family never committed, and every push was a full-size envelope.
//
// The org server applies every snapshot family as a per-row upsert by the
// row's natural key (internal/orgserver/ingest), so the fake server below is a
// map keyed the same way: shipping a page can never wipe the rows of another
// page, and the end state must equal one unbounded push.

// snapFamPagingTest is a probe key used only by this file. Like snapFamTest it
// is never referenced by a wire, so registering it in snapProbes is safe; tests
// using it must not be parallel (snapProbes is package state).
const snapFamPagingTest snapFamily = "test_only_paging_family"

// pagingRow is a synthetic snapshot row: Key is its natural key on the fake
// server, Val its payload, Pad its size.
type pagingRow struct {
	Key string `json:"key"`
	Val string `json:"val"`
	Pad string `json:"pad,omitempty"`
}

// The synthetic row's natural key on the fake server is Key, exactly as a real
// wire row's is its server conflict key (orgsnapkeys.go).
func init() { snapNaturalKeys[reflect.TypeFor[pagingRow]()] = []string{"Key"} }

// installPagingProbe registers a probe for snapFamPagingTest that returns *fp.
func installPagingProbe(t *testing.T, fp *string) {
	t.Helper()
	snapProbes[snapFamPagingTest] = func(*Store, context.Context) (string, error) { return *fp, nil }
	t.Cleanup(func() { delete(snapProbes, snapFamPagingTest) })
}

// pagingRows returns n rows of roughly rowBytes JSON each, valued val.
func pagingRows(n, rowBytes int, val string) []pagingRow {
	out := make([]pagingRow, n)
	for i := range out {
		out[i] = pagingRow{Key: fmt.Sprintf("k%03d", i), Val: val, Pad: strings.Repeat("x", rowBytes)}
	}
	return out
}

// pagingTick is one push tick against the gate: probe, compose under a fresh
// budget, and (when accept) apply the page to the fake server and commit. It
// returns the rows the tick composed and whether the family recomputed.
func pagingTick(t *testing.T, s *Store, now time.Time, limit int64, rows []pagingRow, server map[string]pagingRow, accept bool) ([]pagingRow, bool) {
	t.Helper()
	if !s.snap.changed(context.Background(), s, snapFamPagingTest, now) {
		if accept {
			s.snap.commit(now)
		}
		return nil, false
	}
	b := &envelopeBudget{max: limit + pushEnvelopeBudgetReserve, snapshotLimit: limit}
	kept := fitSnapshot(s, b, snapFamPagingTest, rows)
	if accept {
		for _, r := range kept {
			server[r.Key] = r
		}
		s.snap.commit(now)
	}
	return kept, true
}

func TestSnapshotPaging_DeliversEveryRowThenGoesQuiet(t *testing.T) {
	fp := "v1"
	installPagingProbe(t, &fp)
	s := &Store{snap: newSnapGate()}
	rows := pagingRows(50, 150, "old")
	const limit = 1000 // a handful of rows per page
	server := map[string]pagingRow{}
	now := time.Now().UTC()

	pages := 0
	var failed []pagingRow
	for tick := 0; tick < 40 && len(server) < len(rows); tick++ {
		now = now.Add(30 * time.Second)
		// Tick 2 is a FAILED push: the server never saw it, so nothing it
		// carried may count as delivered.
		accept := tick != 2
		kept, recomputed := pagingTick(t, s, now, limit, rows, server, accept)
		if !recomputed {
			t.Fatalf("tick %d: the family was skipped with %d of %d rows delivered", tick, len(server), len(rows))
		}
		if len(kept) == 0 {
			t.Fatalf("tick %d: an undelivered family composed no rows", tick)
		}
		if !accept {
			failed = kept
			continue
		}
		if failed != nil {
			if fmt.Sprint(kept) != fmt.Sprint(failed) {
				t.Fatalf("the tick after a FAILED push must re-send what it carried: got %d rows, want %d", len(kept), len(failed))
			}
			failed = nil
		}
		pages++
	}
	if len(server) != len(rows) {
		t.Fatalf("server holds %d of %d rows: a truncated family must make forward progress across pushes", len(server), len(rows))
	}
	if pages < 5 {
		t.Fatalf("delivered in %d pages; the fixture must exceed the budget for the test to mean anything", pages)
	}
	for _, r := range rows {
		if server[r.Key] != r {
			t.Fatalf("server row %s differs from the unbounded push", r.Key)
		}
	}
	// Committed: the next pushes carry nothing for this family.
	for i := 0; i < 3; i++ {
		now = now.Add(30 * time.Second)
		if kept, recomputed := pagingTick(t, s, now, limit, rows, server, true); recomputed || len(kept) != 0 {
			t.Fatalf("post-commit tick %d recomputed=%v rows=%d: a fully delivered, unchanged family must go quiet", i, recomputed, len(kept))
		}
	}
}

// TestSnapshotPaging_ChangeMidDeliveryRefreshesEveryCurrentRow: a family whose
// rows change while it is mid-delivery ends with every row of the CURRENT
// snapshot holding its current value on the server. It deliberately says
// nothing about the five keys that left the family: under the org's per-row
// upsert a row the node stops sending is never removed (a pre-existing gap of
// every snapshot family, paged or not; see the lane report).
func TestSnapshotPaging_ChangeMidDeliveryRefreshesEveryCurrentRow(t *testing.T) {
	fp := "v1"
	installPagingProbe(t, &fp)
	s := &Store{snap: newSnapGate()}
	const limit = 1000
	oldRows := pagingRows(40, 150, "old")
	server := map[string]pagingRow{}
	now := time.Now().UTC()

	for tick := 0; tick < 2; tick++ {
		now = now.Add(30 * time.Second)
		if _, ok := pagingTick(t, s, now, limit, oldRows, server, true); !ok {
			t.Fatalf("tick %d: an undelivered family was skipped", tick)
		}
	}
	if len(server) == 0 || len(server) == len(oldRows) {
		t.Fatalf("fixture: want a PARTIAL delivery before the change, server holds %d of %d", len(server), len(oldRows))
	}

	// The source changes mid-delivery: every surviving row gets a new value,
	// five keys disappear and five new ones arrive.
	newRows := pagingRows(45, 150, "new")[5:]
	fp = "v2"
	for tick := 0; tick < 60; tick++ {
		now = now.Add(30 * time.Second)
		if _, ok := pagingTick(t, s, now, limit, newRows, server, true); !ok {
			break
		}
	}
	for _, r := range newRows {
		got, ok := server[r.Key]
		if !ok {
			t.Fatalf("row %s of the changed snapshot never reached the server", r.Key)
		}
		if got.Val != "new" {
			t.Fatalf("row %s still holds the pre-change value %q: a family that changed mid-delivery must not leave old rows behind", r.Key, got.Val)
		}
	}
	now = now.Add(30 * time.Second)
	if kept, recomputed := pagingTick(t, s, now, limit, newRows, server, true); recomputed || len(kept) != 0 {
		t.Fatalf("after delivering the changed snapshot the family must go quiet (recomputed=%v rows=%d)", recomputed, len(kept))
	}
}

func TestSnapshotPaging_OversizedRowIsReportedNotLooped(t *testing.T) {
	fp := "v1"
	installPagingProbe(t, &fp)
	s := &Store{snap: newSnapGate()}
	const limit = 1000
	// A row larger than the whole snapshot budget, FIRST in the family's order:
	// before the fix it blocked every row behind it on every push, forever.
	rows := append([]pagingRow{{Key: "huge", Val: "v", Pad: strings.Repeat("h", 4*limit)}}, pagingRows(12, 150, "small")...)
	server := map[string]pagingRow{}
	now := time.Now().UTC()

	ticks := 0
	for ; ticks < 20; ticks++ {
		now = now.Add(30 * time.Second)
		kept, ok := pagingTick(t, s, now, limit, rows, server, true)
		if !ok {
			break
		}
		for _, r := range kept {
			if r.Key == "huge" {
				t.Fatal("a row larger than the whole snapshot budget was composed")
			}
		}
	}
	if ticks == 20 {
		t.Fatal("the family never settled: an oversized row must be reported, not looped on")
	}
	if len(server) != len(rows)-1 {
		t.Fatalf("server holds %d rows, want every row but the oversized one (%d)", len(server), len(rows)-1)
	}
	if _, ok := server["huge"]; ok {
		t.Fatal("the oversized row cannot fit any envelope and must not ship")
	}
	if got := s.OrgSnapshotOversizedRows()[string(snapFamPagingTest)]; got != 1 {
		t.Fatalf("OrgSnapshotOversizedRows = %d, want the one oversized row reported exactly once", got)
	}
	// A later cycle (the freshness floor) meets the same row again: it is
	// settled again without a second report.
	now = now.Add(2 * snapGateDefaultMaxSkipAge)
	for i := 0; i < 5; i++ {
		now = now.Add(30 * time.Second)
		if _, ok := pagingTick(t, s, now, limit, rows, server, true); !ok {
			break
		}
	}
	if got := s.OrgSnapshotOversizedRows()[string(snapFamPagingTest)]; got != 1 {
		t.Fatalf("OrgSnapshotOversizedRows = %d after a second cycle, want 1 (reported once, not per push)", got)
	}
}

// TestSelectUnpushedSince_TruncatedSessionLOCPagesToCompletion is the demo-box
// shape end to end: a session_loc family larger than the snapshot budget
// (there: 1,127 rows in a 1 MiB envelope) is delivered completely over
// successive pushes through the real compose seam, the server ends up exactly
// where one unbounded push would have left it, and the push after the commit
// carries no session_loc rows.
func TestSelectUnpushedSince_TruncatedSessionLOCPagesToCompletion(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/paging-proj", "git@example.com:acme/paging.git")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	now := time.Now().UTC()
	const sessions = 48
	var changes []FileChangeRow
	for i := 0; i < sessions; i++ {
		sid := fmt.Sprintf("page-s%03d", i)
		if err := s.UpsertSession(ctx, models.Session{
			ID: sid, ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude", StartedAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("UpsertSession: %v", err)
		}
		changes = append(changes, FileChangeRow{
			SessionID: sid, ProjectID: pid,
			FilePathHash: fmt.Sprintf("fh-%d", i), InputDigest: fmt.Sprintf("dg-%d", i),
			Language: "go", Category: "code",
			Actor: LOCActorAI, Confidence: "high", Source: LOCSourceEdit,
			Stats:   loc.Stats{AddedCode: 10 + i, ModifiedCode: 2, DeletedCode: 1},
			Version: loc.Version, SavedAt: now.Add(-time.Minute),
		})
	}
	if _, err := s.InsertFileChanges(ctx, changes); err != nil {
		t.Fatalf("InsertFileChanges: %v", err)
	}

	const orgID, email = "org-1", "dev@acme.example"
	want, err := s.SelectSessionLOCSummaries(ctx, ScopeOptions{}, false)
	if err != nil {
		t.Fatalf("SelectSessionLOCSummaries: %v", err)
	}
	if len(want) != sessions {
		t.Fatalf("fixture: %d session_loc rows, want %d", len(want), sessions)
	}
	key := func(r orgcontract.SessionLOCRow) string { return r.SessionID + "|" + r.ProjectRootHash }
	wantByKey := map[string]string{}
	var total int64
	for i := range want {
		want[i].OrgID, want[i].UserEmail = orgID, email
		raw, _ := json.Marshal(want[i])
		wantByKey[key(want[i])] = string(raw)
		total += int64(len(raw))
	}
	// A snapshot budget of roughly a fifth of the family.
	maxBytes := pushEnvelopeBudgetReserve + total/5
	share := ShareOptions{}

	server := map[string]string{}
	cur := PushCursor{}
	locPages := 0
	for push := 0; push < 200 && len(server) < len(wantByKey); push++ {
		batch, err := s.SelectUnpushedSince(ctx, cur, maxBytes, orgID, email, share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince push %d: %v", push, err)
		}
		if len(batch.SessionLOC) > 0 {
			locPages++
		}
		for _, r := range batch.SessionLOC {
			raw, _ := json.Marshal(r)
			server[key(r)] = string(raw) // the org's per-row upsert
		}
		cur = batch.Cursor
		s.CommitPushedSnapshots()
	}
	if len(server) != len(wantByKey) {
		t.Fatalf("server holds %d of %d session_loc rows after paging: the truncated tail never shipped", len(server), len(wantByKey))
	}
	if locPages < 3 {
		t.Fatalf("session_loc shipped in %d pushes; the fixture must exceed the snapshot budget", locPages)
	}
	for k, v := range wantByKey {
		if server[k] != v {
			t.Fatalf("server row %s differs from one unbounded push", k)
		}
	}
	for i := 0; i < 2; i++ {
		batch, err := s.SelectUnpushedSince(ctx, cur, maxBytes, orgID, email, share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince after commit: %v", err)
		}
		if n := len(batch.SessionLOC); n != 0 {
			t.Fatalf("push %d after the commit carried %d session_loc rows; a delivered family must go quiet", i, n)
		}
		cur = batch.Cursor
		s.CommitPushedSnapshots()
	}
}

// TestSelectUnpushedSince_NetworkEventsPageThroughTheBoundedScan covers the
// one family that also truncates INSIDE its scan: the bounded selector must
// skip the rows the server already accepted, or it would stop at the same byte
// ceiling, and so the same rows, on every push.
func TestSelectUnpushedSince_NetworkEventsPageThroughTheBoundedScan(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	now := time.Now().UTC()
	body := strings.Repeat("x", 64<<10)
	const events = 20
	for i := 0; i < events; i++ {
		seedNetworkEvent(t, s, sessionID, "proxy:paging", now.Add(time.Duration(i)*time.Second),
			map[string]any{"capture_source": "proxy", "method": "POST"},
			&procmodel.NetworkBodyCapture{CaptureSource: "proxy", RequestBody: body, ResponseBody: body})
	}
	const maxBytes = 1 << 20
	share := ShareOptions{AdminManaged: true}
	delivered := map[string]bool{}
	cur := PushCursor{}
	pushes := 0
	for ; pushes < 40 && len(delivered) < events; pushes++ {
		batch, err := s.SelectUnpushedSince(ctx, cur, maxBytes, "o", "u", share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince: %v", err)
		}
		if batch.EstBytes > maxBytes {
			t.Fatalf("EstBytes = %d exceeds maxBytes = %d", batch.EstBytes, maxBytes)
		}
		for _, r := range batch.SessionNetworkEvents {
			delivered[r.EventKey] = true
		}
		cur = batch.Cursor
		s.CommitPushedSnapshots()
	}
	if len(delivered) != events {
		t.Fatalf("%d of %d network events delivered after %d pushes: the bounded scan re-read the same prefix", len(delivered), events, pushes)
	}
	batch, err := s.SelectUnpushedSince(ctx, cur, maxBytes, "o", "u", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince after commit: %v", err)
	}
	if n := len(batch.SessionNetworkEvents); n != 0 {
		t.Fatalf("the push after the commit carried %d network events, want 0", n)
	}
}

// TestSnapshotPaging_FailingProbeKeepsShipping pins the gate's fail-open rule
// under paging (audit M1): a family whose change probe keeps failing must be
// composed and shipped on every tick, page by page, never fall silent. Before
// round 2 a failing probe left every accepted row "delivered" in a cycle that
// could never close, so the family shipped once and then nothing ([3 0 0 0 0
// 0] over six ticks 30 minutes apart).
func TestSnapshotPaging_FailingProbeKeepsShipping(t *testing.T) {
	snapProbes[snapFamPagingTest] = func(*Store, context.Context) (string, error) { return "", errors.New("probe broken") }
	t.Cleanup(func() { delete(snapProbes, snapFamPagingTest) })

	t.Run("fits", func(t *testing.T) {
		s := &Store{snap: newSnapGate()}
		rows := pagingRows(3, 50, "x")
		server := map[string]pagingRow{}
		now := time.Now().UTC()
		var shipped []int
		for i := 0; i < 6; i++ {
			now = now.Add(30 * time.Minute)
			kept, _ := pagingTick(t, s, now, 100000, rows, server, true)
			shipped = append(shipped, len(kept))
		}
		for i, n := range shipped {
			if n != len(rows) {
				t.Fatalf("rows shipped per tick %v: tick %d shipped %d; a family whose probe fails must ship every tick", shipped, i, n)
			}
		}
	})
	t.Run("pages", func(t *testing.T) {
		s := &Store{snap: newSnapGate()}
		rows := pagingRows(20, 150, "x")
		server := map[string]pagingRow{}
		now := time.Now().UTC()
		var shipped []int
		for i := 0; i < 12; i++ {
			now = now.Add(30 * time.Second)
			kept, _ := pagingTick(t, s, now, 1000, rows, server, true)
			shipped = append(shipped, len(kept))
		}
		for i, n := range shipped {
			if n == 0 {
				t.Fatalf("rows shipped per tick %v: tick %d shipped nothing; a failing probe must never silence the family", shipped, i)
			}
		}
		if len(server) != len(rows) {
			t.Fatalf("server holds %d of %d rows", len(server), len(rows))
		}
	})
}

// TestSnapshotPaging_ReturnToEarlierValueIsResent (audit L1): a row that ships
// as A, changes to B (shipped), then changes back to A inside one open cycle
// must be sent again, or the server keeps B while the node holds A.
func TestSnapshotPaging_ReturnToEarlierValueIsResent(t *testing.T) {
	fp := "v1"
	installPagingProbe(t, &fp)
	s := &Store{snap: newSnapGate()}
	const limit = 1000
	rows := pagingRows(20, 150, "A")
	server := map[string]pagingRow{}
	now := time.Now().UTC().Add(30 * time.Second)
	pagingTick(t, s, now, limit, rows, server, true)
	if server["k000"].Val != "A" {
		t.Fatalf("setup: k000=%q", server["k000"].Val)
	}
	rows[0].Val, fp = "B", "v2"
	now = now.Add(30 * time.Second)
	pagingTick(t, s, now, limit, rows, server, true)
	if server["k000"].Val != "B" {
		t.Fatalf("setup: k000=%q after the change to B", server["k000"].Val)
	}
	rows[0].Val, fp = "A", "v3"
	for i := 0; i < 20; i++ {
		now = now.Add(30 * time.Second)
		if _, ok := pagingTick(t, s, now, limit, rows, server, true); !ok {
			break
		}
	}
	for _, r := range rows {
		if server[r.Key] != r {
			t.Fatalf("server %s=%q, node %q: a return to an earlier value inside one cycle must be sent again", r.Key, server[r.Key].Val, r.Val)
		}
	}
}

// TestSelectUnpushedSince_MCPInventoryPagesAcrossAClockChange (audit L2): the
// inventory rows carry the compose time (ObservedAt / LastSeen), so a page
// digest over the raw row changed on every compose and an over-budget
// inventory re-shipped its prefix forever. With the compose time out of the
// paging digest the family pages to completion and goes quiet even though the
// injected clock moves on every compose.
func TestSelectUnpushedSince_MCPInventoryPagesAcrossAClockChange(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	var entries []MCPInventoryEntry
	for i := 0; i < 60; i++ {
		entries = append(entries, MCPInventoryEntry{
			Server:     mcpsec.Server{Client: "claude-code", Name: fmt.Sprintf("server-%03d", i), Transport: "stdio", Command: "npx", Args: []string{fmt.Sprintf("@acme/server-%03d", i)}},
			ConfigPath: "/home/dev/.claude.json",
		})
	}
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.SetMCPInventoryProviders(MCPInventoryProviders{
		Inventory: func(context.Context) ([]MCPInventoryEntry, error) { return entries, nil },
		Probe:     func(context.Context) (string, error) { return "stable", nil },
		Now: func() time.Time {
			clock = clock.Add(time.Minute) // every compose sees a later time
			return clock
		},
	})
	all, err := s.SelectMCPInventory(ctx, "o", false)
	if err != nil || len(all) != len(entries) {
		t.Fatalf("fixture: %d inventory rows, err %v", len(all), err)
	}
	var total int64
	for i := range all {
		total += jsonSize(all[i])
	}
	maxBytes := pushEnvelopeBudgetReserve + total/5
	share := ShareOptions{MCPActivity: true}
	delivered := map[string]bool{}
	cur := PushCursor{}
	pushes := 0
	for ; pushes < 40 && len(delivered) < len(entries); pushes++ {
		batch, err := s.SelectUnpushedSince(ctx, cur, maxBytes, "o", "u", share, ScopeOptions{})
		if err != nil {
			t.Fatalf("SelectUnpushedSince: %v", err)
		}
		for _, r := range batch.MCPInventory {
			delivered[r.LocatorFingerprint] = true
		}
		cur = batch.Cursor
		s.CommitPushedSnapshots()
	}
	if len(delivered) != len(entries) {
		t.Fatalf("%d of %d inventory rows delivered after %d pushes: the moving compose time kept the family re-shipping its prefix", len(delivered), len(entries), pushes)
	}
	batch, err := s.SelectUnpushedSince(ctx, cur, maxBytes, "o", "u", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince after commit: %v", err)
	}
	if n := len(batch.MCPInventory); n != 0 {
		t.Fatalf("the push after the commit carried %d inventory rows, want 0", n)
	}
}

// TestOrgPushOversizedReportReachesStatusAndClears (audit L3): an oversized
// snapshot row is reported where an operator looks, through the persisted
// report org status and doctor read: family and sizes, never the row's
// content. A daemon restart with a budget the row now fits rewrites the report
// away instead of leaving a stale warning.
func TestOrgPushOversizedReportReachesStatusAndClears(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	sessionID, _ := mustProjectAndSession(t, s)
	marker := "OVERSIZED-BODY-MARKER-" + strings.Repeat("z", 64<<10)
	seedNetworkEvent(t, s, sessionID, "proxy:oversized", time.Now().UTC(),
		map[string]any{"capture_source": "proxy", "method": "POST"},
		&procmodel.NetworkBodyCapture{CaptureSource: "proxy", RequestBody: marker})
	share := ShareOptions{AdminManaged: true}
	maxBytes := int64(pushEnvelopeBudgetReserve + 8<<10)
	if _, err := s.SelectUnpushedSince(ctx, PushCursor{}, maxBytes, "o", "u", share, ScopeOptions{}); err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	rows, err := s.LoadOrgPushOversizedRows(ctx)
	if err != nil {
		t.Fatalf("LoadOrgPushOversizedRows: %v", err)
	}
	if len(rows) != 1 || rows[0].Family != string(snapFamSessionNetwork) || rows[0].Rows != 1 {
		t.Fatalf("oversized report = %+v, want one session_network row", rows)
	}
	if rows[0].LargestBytes <= 64<<10 || rows[0].BudgetBytes != maxBytes-pushEnvelopeBudgetReserve || rows[0].LastSeen == "" {
		t.Fatalf("oversized report sizes = %+v", rows[0])
	}
	var raw string
	if err := database.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, OrgPushOversizedKey).Scan(&raw); err != nil {
		t.Fatalf("read persisted report: %v", err)
	}
	if strings.Contains(raw, "OVERSIZED-BODY-MARKER") || strings.Contains(raw, "proxy:oversized") {
		t.Fatal("the persisted oversized report carries row content; it must hold names and sizes only")
	}
	if !strings.Contains(rows[0].Summary(), "max_push_bytes") {
		t.Fatalf("summary %q does not tell the operator what to change", rows[0].Summary())
	}

	// A restart (a new gate) with a budget the row fits: the report clears.
	s2 := New(database)
	if _, err := s2.SelectUnpushedSince(ctx, PushCursor{}, 64<<20, "o", "u", share, ScopeOptions{}); err != nil {
		t.Fatalf("SelectUnpushedSince (restart): %v", err)
	}
	if rows, err := s2.LoadOrgPushOversizedRows(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("after a restart with room for the row the report must clear: %+v err=%v", rows, err)
	}
}

// TestOrgPushOversizedReportSurvivesAPushNow (audit round 2, L3): a CLI or
// dashboard push-now runs its own Store and gate on the daemon's database.
// When its compose does not reach the oversized row (the budget runs out
// first), it must leave the daemon's report alone, and the daemon must keep
// the report current on its later cycles. Before round 3 the fresh gate
// started dirty and empty, the push-now deleted the report, and the daemon
// never wrote it again (report present, then [], still [] after three cycles).
func TestOrgPushOversizedReportSurvivesAPushNow(t *testing.T) {
	fp := "v1"
	installPagingProbe(t, &fp)
	s, _ := newTestStore(t)
	ctx := context.Background()
	secret := "SECRETCONTENT"
	rows := append(pagingRows(10, 150, "small"), pagingRow{Key: "huge", Val: secret, Pad: strings.Repeat("h", 5000)})
	server := map[string]pagingRow{}
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		now = now.Add(30 * time.Second)
		s.snap.beginCompose()
		_, ok := pagingTick(t, s, now, 1000, rows, server, true)
		s.persistOrgPushOversized(ctx)
		if !ok {
			break
		}
	}
	report := func(when string) []OrgPushOversizedRow {
		t.Helper()
		got, err := s.LoadOrgPushOversizedRows(ctx)
		if err != nil {
			t.Fatalf("%s: LoadOrgPushOversizedRows: %v", when, err)
		}
		return got
	}
	if got := report("daemon"); len(got) != 1 || got[0].Family != string(snapFamPagingTest) || got[0].Rows != 1 {
		t.Fatalf("daemon report = %+v, want the one oversized row", got)
	}
	raw, _ := s.readMeta(ctx, OrgPushOversizedKey)
	if strings.Contains(raw, secret) || strings.Contains(raw, "huge") {
		t.Fatal("the report carries row content")
	}

	// A push-now in another process: a fresh gate whose compose stops before
	// the oversized row (the last one) because the small rows fill the page.
	s2 := New(s.db)
	s2.snap.beginCompose()
	pagingTick(t, s2, now, 1000, rows, map[string]pagingRow{}, false)
	s2.persistOrgPushOversized(ctx)
	if got := report("after push-now"); len(got) != 1 {
		t.Fatalf("a push-now that never reached the oversized row erased the daemon's report: %+v", got)
	}

	// Even if something did erase it, the daemon's next cycles rewrite it.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM schema_meta WHERE key = ?`, OrgPushOversizedKey); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		now = now.Add(2 * time.Hour)
		s.snap.beginCompose()
		pagingTick(t, s, now, 1000, rows, server, true)
		s.persistOrgPushOversized(ctx)
	}
	if got := report("after three daemon cycles"); len(got) != 1 || got[0].Rows != 1 {
		t.Fatalf("the daemon did not rewrite the report on its later cycles: %+v", got)
	}

	// The row goes away: a complete compose without it clears the report.
	now = now.Add(2 * time.Hour)
	s.snap.beginCompose()
	pagingTick(t, s, now, 1000, rows[:10], server, true)
	s.persistOrgPushOversized(ctx)
	if got := report("after the row left"); len(got) != 0 {
		t.Fatalf("the report must clear once no oversized row remains: %+v", got)
	}
}
