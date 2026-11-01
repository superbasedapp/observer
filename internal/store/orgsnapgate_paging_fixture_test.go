//go:build !sbo_omit_benchmark

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"reflect"
	"testing"
	"time"
)

// TestSnapshotFamiliesComposeDeterministically pins the assumption snapshot
// paging rests on (orgsnapgate.go): with no source change, two recomputes of a
// gated family produce the same paging digest for every row, so a row the
// server already accepted is recognised and skipped. The two composes run
// across a clock change (the MCP inventory's injected clock moves an hour), so
// a family whose rows carry the compose time fails here unless that field is
// in snapVolatileFields. A family whose digest moved on every compose would
// never page: every tick would see every row as new and re-ship the same
// prefix, the defect paging fixes.
func TestSnapshotFamiliesComposeDeterministically(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	seedEveryWireFamily(t, s)
	share := envelopeShareOptions()
	const wide = 64 << 20
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	s.mcpInventory.Now = func() time.Time { return clock }

	first, err := s.SelectUnpushedSince(ctx, PushCursor{}, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (first): %v", err)
	}
	clock = clock.Add(time.Hour)
	// No commit: the second compose recomputes every family again.
	second, err := s.SelectUnpushedSince(ctx, PushCursor{}, wide, "org-1", "dev@acme.example", share, ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince (second): %v", err)
	}
	if reflect.DeepEqual(first.MCPInventory, second.MCPInventory) {
		t.Fatal("fixture: the clock change did not reach the MCP inventory rows; the test would be vacuous")
	}
	a, b := reflect.ValueOf(first), reflect.ValueOf(second)
	for name := range gatedWireFamilies {
		x, y := a.FieldByName(name), b.FieldByName(name)
		if x.Len() != y.Len() {
			t.Errorf("gated family %s composed %d then %d rows with no source change", name, x.Len(), y.Len())
			continue
		}
		for i := 0; i < x.Len(); i++ {
			if snapRowValue(x.Index(i)).key != snapRowValue(y.Index(i)).key {
				t.Errorf("gated family %s row %d has a different paging digest across a clock change; "+
					"snapshot paging cannot recognise its delivered rows (a compose-time field missing from snapVolatileFields?)", name, i)
				break
			}
		}
	}
}

// TestSnapshotPagingKeysCoverEveryGatedWire pins orgsnapkeys.go: every gated
// wire row type has a natural key whose fields exist, and on the fully seeded
// fixture no family composes two rows with one key (a key coarser than the
// server's would make the gate fall back to the digest for the repeat).
func TestSnapshotPagingKeysCoverEveryGatedWire(t *testing.T) {
	t.Parallel()
	bt := reflect.TypeOf(PushBatch{})
	for name := range gatedWireFamilies {
		f, _ := bt.FieldByName(name)
		et := f.Type.Elem()
		fields, ok := snapNaturalKeys[et]
		if !ok || len(fields) == 0 {
			t.Errorf("gated wire %s (%s) has no natural key in snapNaturalKeys", name, et)
			continue
		}
		for _, fn := range fields {
			if _, ok := et.FieldByName(fn); !ok {
				t.Errorf("snapNaturalKeys[%s] names %q, which the type does not have", et, fn)
			}
		}
	}
	for et, fields := range snapVolatileFields {
		for _, fn := range fields {
			if _, ok := et.FieldByName(fn); !ok {
				t.Errorf("snapVolatileFields[%s] names %q, which the type does not have", et, fn)
			}
		}
	}

	s, _ := newTestStore(t)
	seedEveryWireFamily(t, s)
	batch, err := s.SelectUnpushedSince(context.Background(), PushCursor{}, 64<<20, "org-1", "dev@acme.example", envelopeShareOptions(), ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	v := reflect.ValueOf(batch)
	for name := range gatedWireFamilies {
		f := v.FieldByName(name)
		seen := map[string]bool{}
		for i := 0; i < f.Len(); i++ {
			id := snapRowValue(f.Index(i)).id
			if seen[id] {
				t.Errorf("gated wire %s composed two rows with natural key %q: the key is coarser than the server's", name, id)
				break
			}
			seen[id] = true
		}
	}
}
