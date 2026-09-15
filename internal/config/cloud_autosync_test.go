package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCloudAutoSyncAndEnrichDefaults pins the arc-2 R2a/R8 knobs: both default
// OFF via the zero value (no Default() seeding, mirroring the rest of
// CloudConfig), a partial [cloud] section overrides only the keys present, and
// the interval resolves through the 0-means-default rule.
func TestCloudAutoSyncAndEnrichDefaults(t *testing.T) {
	t.Parallel()

	c := Default().Cloud
	if c.AutoSync || c.AutoEnrich || c.AutoSyncIntervalMinutes != 0 {
		t.Fatalf("cloud auto knobs default = %+v, want all zero/off", c)
	}
	// 0 resolves to the built-in default; the min floor is a positive value.
	if got := c.ResolvedCloudAutoSyncMinutes(); got != CloudAutoSyncDefaultMinutes {
		t.Fatalf("ResolvedCloudAutoSyncMinutes with 0 = %d, want %d", got, CloudAutoSyncDefaultMinutes)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[cloud]\nauto_sync = true\nauto_enrich = true\nauto_sync_interval_minutes = 15\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Cloud.AutoSync || !cfg.Cloud.AutoEnrich {
		t.Errorf("cloud toggles did not take effect: %+v", cfg.Cloud)
	}
	if cfg.Cloud.AutoSyncIntervalMinutes != 15 {
		t.Errorf("auto_sync_interval_minutes = %d, want 15", cfg.Cloud.AutoSyncIntervalMinutes)
	}
	if got := cfg.Cloud.ResolvedCloudAutoSyncMinutes(); got != 15 {
		t.Errorf("ResolvedCloudAutoSyncMinutes = %d, want 15", got)
	}
	// Base URL/login-port siblings keep their zero-value defaults through the
	// partial merge (they were absent from the section).
	if cfg.Cloud.BaseURL != "" || cfg.Cloud.LoginPort != 0 {
		t.Errorf("partial [cloud] merge disturbed siblings: %+v", cfg.Cloud)
	}
}

// TestCloudAutoSyncIntervalValidation pins the floor: a positive interval below
// CloudAutoSyncMinMinutes is refused; 0 and >= the floor pass.
func TestCloudAutoSyncIntervalValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mins    int
		wantErr bool
	}{
		{0, false},
		{CloudAutoSyncMinMinutes, false},
		{CloudAutoSyncMinMinutes + 30, false},
		{CloudAutoSyncMinMinutes - 1, true},
		{-1, true},
	} {
		err := validateCloud(CloudConfig{AutoSyncIntervalMinutes: tc.mins})
		if (err != nil) != tc.wantErr {
			t.Errorf("validateCloud(interval=%d) err=%v, wantErr=%v", tc.mins, err, tc.wantErr)
		}
	}
}

// TestCloudAutoEnrichDefaults pins the value-upgrade plan's W3 knobs: both
// default to 0 (zero value, no Default() seeding — same convention as the
// rest of CloudConfig) and resolve through the 0-means-default rule.
func TestCloudAutoEnrichDefaults(t *testing.T) {
	t.Parallel()

	c := Default().Cloud
	if c.AutoEnrichIntervalMinutes != 0 || c.AutoEnrichQuietMinutes != 0 {
		t.Fatalf("cloud auto-enrich knobs default = %+v, want both zero", c)
	}
	if got := c.ResolvedCloudAutoEnrichIntervalMinutes(); got != CloudAutoEnrichDefaultMinutes {
		t.Fatalf("ResolvedCloudAutoEnrichIntervalMinutes with 0 = %d, want %d", got, CloudAutoEnrichDefaultMinutes)
	}
	if got := c.ResolvedCloudAutoEnrichQuietMinutes(); got != CloudAutoEnrichQuietDefaultMinutes {
		t.Fatalf("ResolvedCloudAutoEnrichQuietMinutes with 0 = %d, want %d", got, CloudAutoEnrichQuietDefaultMinutes)
	}

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[cloud]\nauto_enrich_interval_minutes = 3\nauto_enrich_quiet_minutes = 20\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Cloud.AutoEnrichIntervalMinutes != 3 || cfg.Cloud.AutoEnrichQuietMinutes != 20 {
		t.Errorf("cloud auto-enrich knobs did not take effect: %+v", cfg.Cloud)
	}
	if got := cfg.Cloud.ResolvedCloudAutoEnrichIntervalMinutes(); got != 3 {
		t.Errorf("ResolvedCloudAutoEnrichIntervalMinutes = %d, want 3", got)
	}
	if got := cfg.Cloud.ResolvedCloudAutoEnrichQuietMinutes(); got != 20 {
		t.Errorf("ResolvedCloudAutoEnrichQuietMinutes = %d, want 20", got)
	}
}

// TestCloudAutoEnrichIntervalValidation pins the shared floor for both knobs.
// CloudAutoEnrichMinMinutes is 1, so there is no positive-but-below-floor
// value to test (0 itself is the "use the built-in default" sentinel, not a
// violation) — only 0/floor/above-floor passing and negative refused.
func TestCloudAutoEnrichIntervalValidation(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		mins    int
		wantErr bool
	}{
		{0, false},
		{CloudAutoEnrichMinMinutes, false},
		{CloudAutoEnrichMinMinutes + 10, false},
		{-1, true},
	} {
		if err := validateCloud(CloudConfig{AutoEnrichIntervalMinutes: tc.mins}); (err != nil) != tc.wantErr {
			t.Errorf("validateCloud(auto_enrich_interval=%d) err=%v, wantErr=%v", tc.mins, err, tc.wantErr)
		}
		if err := validateCloud(CloudConfig{AutoEnrichQuietMinutes: tc.mins}); (err != nil) != tc.wantErr {
			t.Errorf("validateCloud(auto_enrich_quiet=%d) err=%v, wantErr=%v", tc.mins, err, tc.wantErr)
		}
	}
}
