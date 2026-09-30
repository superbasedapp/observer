package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/pricingfeed"
)

// historyGolden is the HISTORY-bearing signed feed Tokenomics migration 0028
// produces (model-pricing/internal/observerexport TestGoldenHistoryEnvelope),
// committed byte-identically in internal/pricingfeed/testdata.
const (
	historyGolden    = "../../internal/pricingfeed/testdata/golden-envelope-history-v1.json"
	historyGoldenPub = "../../internal/pricingfeed/testdata/golden-envelope-history-v1.pub"
	// historySnapshot is what this generator makes of that bundle. The cost
	// package reads it (TestHandTimelinesMatchSnapshot) to prove the
	// database's history reproduces the hand-written dated.go timelines at
	// every boundary, so the chain DB -> feed -> snapshot -> engine is pinned.
	historySnapshot = "testdata/history-snapshot.json"
)

// TestRunWith_HistoryBundle: a history-bearing bundle becomes one snapshot row
// per period (the top-level row is not repeated), sorted by model then start,
// and the committed testdata copy is exactly what the generator writes.
// PRICING_SNAPSHOTGEN_UPDATE=1 rewrites it after an intentional change.
func TestRunWith_HistoryBundle(t *testing.T) {
	raw, err := os.ReadFile(historyGolden)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var env pricingfeed.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode golden: %v", err)
	}
	pub, err := os.ReadFile(historyGoldenPub)
	if err != nil {
		t.Fatalf("read pub: %v", err)
	}
	keys, err := pricingfeed.NewKeySet(map[string]string{env.KeyID: strings.TrimSpace(string(pub))})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	bundle := filepath.Join(dir, "observer-pricing-v43.json")
	if err := os.WriteFile(bundle, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "snapshot.json")
	if err := runWith(bundle, out, false, keys); err != nil {
		t.Fatalf("runWith: %v", err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	var doc snapshotDoc
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	wantRows := 0
	perModel := map[string]int{}
	for _, r := range env.Rows {
		if len(r.History) >= 2 {
			wantRows += len(r.History)
			perModel[r.Model] = len(r.History)
		} else {
			wantRows++
			perModel[r.Model] = 1
		}
	}
	if len(doc.Rows) != wantRows {
		t.Fatalf("snapshot rows = %d, want %d (one per history period, one per plain row)", len(doc.Rows), wantRows)
	}
	seen := map[string]int{}
	for i, r := range doc.Rows {
		seen[r.Model]++
		if i > 0 && doc.Rows[i-1].Model == r.Model && doc.Rows[i-1].EffectiveFrom >= r.EffectiveFrom {
			t.Fatalf("%s periods out of order at row %d", r.Model, i)
		}
	}
	for m, n := range perModel {
		if seen[m] != n {
			t.Fatalf("%s: %d snapshot rows, want %d", m, seen[m], n)
		}
	}
	// deepseek-v4-pro: no peak before the overhaul; every-day peak from
	// 2026-08-16; weekday peak from 2026-09-10 (inferred for Pro).
	var pro []snapshotRow
	for _, r := range doc.Rows {
		if r.Model == "deepseek-v4-pro" {
			pro = append(pro, r)
		}
	}
	if len(pro) != 3 || pro[0].Peak != nil || pro[1].Peak == nil || pro[1].EffectiveFrom != "2026-08-16T16:00:00Z" ||
		pro[2].Peak == nil || pro[2].EffectiveFrom != "2026-09-10T04:00:00Z" ||
		len(pro[1].Peak.Schedule.Windows[0].Days) != 7 || len(pro[2].Peak.Schedule.Windows[0].Days) != 5 {
		t.Fatalf("deepseek-v4-pro periods = %+v", pro)
	}

	if os.Getenv("PRICING_SNAPSHOTGEN_UPDATE") != "" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(historySnapshot, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(historySnapshot)
	if err != nil {
		t.Fatalf("read %s (PRICING_SNAPSHOTGEN_UPDATE=1 creates it): %v", historySnapshot, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("generated snapshot diverged from %s", historySnapshot)
	}
}
