package nodegov

import (
	"strings"
	"testing"
)

// TestLoweringOnlyPinRowsAreInts pins the one place DirLoweringOnly may appear
// in PinnableKeys: an "int" row with explicit bounds. The direction is the
// numeric CEILING rule (govern.LowerInt), which has no meaning for a bool or a
// string, and an unbounded ceiling would let a typo stop a node reporting.
// Bounds are allowed on any int row (the sandbox timeout and retention rows,
// sandbox plan v2 section 10.1) and on no other kind.
func TestLoweringOnlyPinRowsAreInts(t *testing.T) {
	seen := 0
	for _, row := range PinnableKeys {
		if row.Direction != DirLoweringOnly {
			if (row.Min != 0 || row.Max != 0) && row.Kind != "int" {
				t.Errorf("%s carries bounds but is not an int row", row.Key)
			}
			continue
		}
		seen++
		if row.Kind != "int" {
			t.Errorf("%s is lowering_only with kind %q; only int rows may be", row.Key, row.Kind)
		}
		if row.Min <= 0 || row.Max <= row.Min {
			t.Errorf("%s has degenerate bounds %d..%d", row.Key, row.Min, row.Max)
		}
	}
	if seen == 0 {
		t.Fatal("no lowering-only row: org_client.push_interval_seconds must be pinnable")
	}
}

// TestPushIntervalPinCompile walks the publish/accept compiler over the push
// interval ceiling: in-range whole numbers compile, anything else is a HARD
// error at publish (never a silent skip on the node).
func TestPushIntervalPinCompile(t *testing.T) {
	cases := []struct {
		name    string
		val     any
		wantErr string
	}{
		{name: "two minutes", val: float64(120)},
		{name: "lower bound", val: float64(30)},
		{name: "upper bound", val: float64(3600)},
		{name: "below floor", val: float64(29), wantErr: "outside the permitted range"},
		{name: "above ceiling", val: float64(3601), wantErr: "outside the permitted range"},
		{name: "fraction", val: 60.5, wantErr: "whole number"},
		{name: "string", val: "60", wantErr: "must be a number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := compilePinned(map[string]any{"org_client.push_interval_seconds": tc.val})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if _, ok := out["org_client.push_interval_seconds"].(int64); !ok {
				t.Fatalf("compiled value %T, want int64", out["org_client.push_interval_seconds"])
			}
		})
	}
	row, ok := LookupPinnableKey("org_client.push_interval_seconds")
	if !ok || !row.Hot {
		t.Fatal("push interval must be a HOT pinnable key (applied live, excluded from pending_restart)")
	}
	for _, k := range BootstrapEnvelopeKeys {
		if k == row.Key {
			t.Fatal("the push interval ceiling must not be a bootstrap-envelope key")
		}
	}
}
