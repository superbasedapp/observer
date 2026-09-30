package db

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIntegrityCheckSkipForSize pins THE size gate every whole-DB
// quick_check caller (daemon startup, `observer doctor`) asks.
func TestIntegrityCheckSkipForSize(t *testing.T) {
	const gib = int64(1) << 30
	for _, tc := range []struct {
		name  string
		size  int64
		maxGB int
		want  bool
	}{
		{"gate_disabled_zero", 100 * gib, 0, false},
		{"gate_disabled_negative", 100 * gib, -1, false},
		{"under_cap", 7 * gib, 8, false},
		{"exactly_cap_runs", 8 * gib, 8, false},
		{"one_byte_over_skips", 8*gib + 1, 8, true},
		{"live_27gb_over_default", 27 * gib, 8, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IntegrityCheckSkipForSize(tc.size, tc.maxGB); got != tc.want {
				t.Errorf("IntegrityCheckSkipForSize(%d, %d) = %v, want %v", tc.size, tc.maxGB, got, tc.want)
			}
		})
	}
}

// TestIntegrityCheckShouldSkip drives the stat path with a sparse file
// (the size is injected without writing the bytes) and pins fail-open on a
// missing file.
func TestIntegrityCheckShouldSkip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "big.db")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(int64(1)<<30 + 1); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if skip, size := IntegrityCheckShouldSkip(path, 1); !skip || size != int64(1)<<30+1 {
		t.Errorf("over cap: skip=%v size=%d, want true / 1GiB+1", skip, size)
	}
	if skip, _ := IntegrityCheckShouldSkip(path, 2); skip {
		t.Error("under cap must run")
	}
	if skip, size := IntegrityCheckShouldSkip(path, 0); skip || size != 0 {
		t.Errorf("disabled gate: skip=%v size=%d, want false / 0 (no stat)", skip, size)
	}
	if skip, _ := IntegrityCheckShouldSkip(filepath.Join(t.TempDir(), "missing.db"), 1); skip {
		t.Error("a stat failure must fail open (run the probe)")
	}
}
