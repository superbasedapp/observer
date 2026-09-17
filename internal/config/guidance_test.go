package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGuidanceDefaults pins the [guidance] seed values. These are the
// numbers the scan loop, the CLI and the dashboard all inherit when the
// operator writes no [guidance] section at all.
func TestGuidanceDefaults(t *testing.T) {
	d := Default()
	if !d.Guidance.Enabled {
		t.Error("guidance.enabled = false, want true (default-ON like cachetrack)")
	}
	if d.Guidance.RescanMinutes != 15 {
		t.Errorf("guidance.rescan_minutes = %d, want 15", d.Guidance.RescanMinutes)
	}
	if d.Guidance.MaxFileBytes != 512*1024 {
		t.Errorf("guidance.max_file_bytes = %d, want %d", d.Guidance.MaxFileBytes, 512*1024)
	}
	if d.Guidance.MaxDepth != 4 {
		t.Errorf("guidance.max_depth = %d, want 4", d.Guidance.MaxDepth)
	}
	if !d.Guidance.IncludeUserScope {
		t.Error("guidance.include_user_scope = false, want true")
	}
	// The scan budgets. They are seeded (not left at zero) because a zero
	// budget is an UNBOUNDED pass, which is the live failure they exist to
	// prevent: 404 recorded roots, most of them slow DrvFs mounts, turned
	// one start-up pass into four CPU-minutes that persisted nothing.
	if d.Guidance.MaxRootsPerPass != 50 {
		t.Errorf("guidance.max_roots_per_pass = %d, want 50", d.Guidance.MaxRootsPerPass)
	}
	if d.Guidance.RootTimeoutSeconds != 20 {
		t.Errorf("guidance.root_timeout_seconds = %d, want 20", d.Guidance.RootTimeoutSeconds)
	}
	if d.Guidance.PassTimeoutMinutes != 10 {
		t.Errorf("guidance.pass_timeout_minutes = %d, want 10", d.Guidance.PassTimeoutMinutes)
	}
	if d.Guidance.StartupDelaySeconds != 90 {
		t.Errorf("guidance.startup_delay_seconds = %d, want 90", d.Guidance.StartupDelaySeconds)
	}
}

// TestGuidancePartialMerge is the CacheTrack partial-merge rule applied to
// [guidance]: a config that omits the section entirely, and a config that
// sets ONE key inside it, must both come back with Enabled=true and the
// untouched keys at their seeded values — never zero-valued.
func TestGuidancePartialMerge(t *testing.T) {
	cases := []struct {
		name    string
		toml    string
		wantOn  bool
		wantMin int
		wantDep int
		// Budget expectations. Zero means "the seeded default"; -1 means
		// "explicitly zero", which for startup_delay_seconds is a real
		// setting ("scan now") rather than an unset key.
		wantMaxRoots int
		wantRootTO   int
		wantPassTO   int
		wantStartup  int
	}{
		{
			name:    "no section at all",
			toml:    "[observer]\nlog_level = \"info\"\n",
			wantOn:  true,
			wantMin: 15,
			wantDep: 4,
		},
		{
			name:    "empty section",
			toml:    "[guidance]\n",
			wantOn:  true,
			wantMin: 15,
			wantDep: 4,
		},
		{
			name:    "one key set",
			toml:    "[guidance]\nrescan_minutes = 30\n",
			wantOn:  true,
			wantMin: 30,
			wantDep: 4,
		},
		{
			name:    "explicitly disabled",
			toml:    "[guidance]\nenabled = false\n",
			wantOn:  false,
			wantMin: 15,
			wantDep: 4,
		},
		{
			name:    "depth override",
			toml:    "[guidance]\nmax_depth = 7\n",
			wantOn:  true,
			wantMin: 15,
			wantDep: 7,
		},
		{
			name:       "one budget key set leaves the other budgets seeded",
			toml:       "[guidance]\nroot_timeout_seconds = 5\n",
			wantOn:     true,
			wantMin:    15,
			wantDep:    4,
			wantRootTO: 5,
		},
		{
			name:         "every budget overridden",
			toml:         "[guidance]\nmax_roots_per_pass = 10\nroot_timeout_seconds = 7\npass_timeout_minutes = 3\nstartup_delay_seconds = 0\n",
			wantOn:       true,
			wantMin:      15,
			wantDep:      4,
			wantMaxRoots: 10,
			wantRootTO:   7,
			wantPassTO:   3,
			wantStartup:  -1,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := Load(LoadOptions{GlobalPath: path})
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Guidance.Enabled != tc.wantOn {
				t.Errorf("guidance.enabled = %v, want %v", cfg.Guidance.Enabled, tc.wantOn)
			}
			if cfg.Guidance.RescanMinutes != tc.wantMin {
				t.Errorf("guidance.rescan_minutes = %d, want %d", cfg.Guidance.RescanMinutes, tc.wantMin)
			}
			if cfg.Guidance.MaxDepth != tc.wantDep {
				t.Errorf("guidance.max_depth = %d, want %d", cfg.Guidance.MaxDepth, tc.wantDep)
			}
			// max_file_bytes / include_user_scope are never set by any case
			// above — they must survive the merge at their seeded values.
			if cfg.Guidance.MaxFileBytes != 512*1024 {
				t.Errorf("guidance.max_file_bytes = %d, want %d (untouched key downgraded)",
					cfg.Guidance.MaxFileBytes, 512*1024)
			}
			if !cfg.Guidance.IncludeUserScope {
				t.Error("guidance.include_user_scope = false, want true (untouched key downgraded)")
			}
			checkGuidanceBudget(t, "max_roots_per_pass", cfg.Guidance.MaxRootsPerPass, tc.wantMaxRoots, 50)
			checkGuidanceBudget(t, "root_timeout_seconds", cfg.Guidance.RootTimeoutSeconds, tc.wantRootTO, 20)
			checkGuidanceBudget(t, "pass_timeout_minutes", cfg.Guidance.PassTimeoutMinutes, tc.wantPassTO, 10)
			checkGuidanceBudget(t, "startup_delay_seconds", cfg.Guidance.StartupDelaySeconds, tc.wantStartup, 90)
		})
	}
}

// checkGuidanceBudget asserts one budget key. want == 0 means "the case did
// not set it, so it must still carry its seeded value"; want == -1 means "the
// case set it to an explicit 0" — the distinction that makes
// startup_delay_seconds = 0 ("scan now") expressible at all.
func checkGuidanceBudget(t *testing.T, key string, got, want, seeded int) {
	t.Helper()
	expect := want
	switch want {
	case 0:
		expect = seeded
	case -1:
		expect = 0
	}
	if got != expect {
		t.Errorf("guidance.%s = %d, want %d", key, got, expect)
	}
}

// TestGuidanceFirstScanPollKey pins the wave-2 key: seeded at 60, an
// explicit 0 survives the merge (it means "never poll", not "use the
// default"), and a negative value is refused by Validate.
func TestGuidanceFirstScanPollKey(t *testing.T) {
	if got := Default().Guidance.FirstScanPollSeconds; got != 60 {
		t.Errorf("guidance.first_scan_poll_seconds default = %d, want 60", got)
	}
	cases := []struct {
		name string
		toml string
		want int
	}{
		{"absent section keeps the seed", "", 60},
		{"unrelated key keeps the seed", "[guidance]\nrescan_minutes = 30\n", 60},
		{"explicit zero disables the poll", "[guidance]\nfirst_scan_poll_seconds = 0\n", 0},
		{"explicit override", "[guidance]\nfirst_scan_poll_seconds = 5\n", 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.toml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg, err := Load(LoadOptions{GlobalPath: path})
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Guidance.FirstScanPollSeconds != tc.want {
				t.Errorf("guidance.first_scan_poll_seconds = %d, want %d",
					cfg.Guidance.FirstScanPollSeconds, tc.want)
			}
		})
	}

	cfg := Default()
	cfg.Guidance.FirstScanPollSeconds = -1
	if err := Validate(cfg); err == nil {
		t.Error("Validate accepted a negative guidance.first_scan_poll_seconds")
	}
	cfg.Guidance.FirstScanPollSeconds = 0
	if err := Validate(cfg); err != nil {
		t.Errorf("Validate rejected first_scan_poll_seconds = 0 (a real setting): %v", err)
	}
}
