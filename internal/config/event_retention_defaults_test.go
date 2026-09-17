package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEventRetentionDefaults pins the two horizons added 2026-09-16 for the
// event tables that had NO retention at all: compaction_events (1.4 GiB in
// 1,333 rows on the operator's live DB, ~1.1 MB of file-state blob per row)
// and compression_events (915 MB in 3.59M rows).
//
// They default ON, unlike most new knobs, because "keep forever" is what
// created the problem; 0 remains the explicit keep-forever opt-out. The
// compaction horizon is deliberately the shorter of the two: its payload is
// a point-in-time snapshot, while compression_events is a small-row
// debugging tail behind rollups api_turns already serves.
//
// The partial-merge case is the one that actually bites (the CacheTrack
// rule): an operator whose config already carries an [observer.retention]
// section that never mentions these keys must inherit 30/90, never a zero
// that silently disables the sweep.
func TestEventRetentionDefaults(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		toml            string // "" = no config file at all
		wantCompaction  int
		wantCompression int
	}{
		{
			name:            "no config file uses Default()",
			toml:            "",
			wantCompaction:  30,
			wantCompression: 90,
		},
		{
			name:            "partial [observer.retention] keeps both defaults",
			toml:            "[observer.retention]\nmax_age_days = 30\n",
			wantCompaction:  30,
			wantCompression: 90,
		},
		{
			name:            "explicit values override",
			toml:            "[observer.retention]\ncompaction_events_days = 7\ncompression_events_days = 14\n",
			wantCompaction:  7,
			wantCompression: 14,
		},
		{
			name:            "explicit zero keeps forever",
			toml:            "[observer.retention]\ncompaction_events_days = 0\ncompression_events_days = 0\n",
			wantCompaction:  0,
			wantCompression: 0,
		},
		{
			name:            "one key set leaves the other at its default",
			toml:            "[observer.retention]\ncompaction_events_days = 0\n",
			wantCompaction:  0,
			wantCompression: 90,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "config.toml")
			if tc.toml != "" {
				if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			cfg, err := Load(LoadOptions{GlobalPath: path, Env: func(string) string { return "" }})
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got := cfg.Observer.Retention.CompactionEventsDays; got != tc.wantCompaction {
				t.Errorf("observer.retention.compaction_events_days = %d, want %d", got, tc.wantCompaction)
			}
			if got := cfg.Observer.Retention.CompressionEventsDays; got != tc.wantCompression {
				t.Errorf("observer.retention.compression_events_days = %d, want %d", got, tc.wantCompression)
			}
		})
	}
}
