package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestReturnedCopyRetentionDays pins [terminal.sandbox].returned_copy_retention_days
// (decision SBXD-2): default 30, 0 (never remove automatically) to 3650,
// checked by Validate, and workspace_retention_days is left at its own
// default.
func TestReturnedCopyRetentionDays(t *testing.T) {
	d := Default().Terminal.Sandbox
	if d.ReturnedCopyRetentionDays != 30 || d.WorkspaceRetentionDays != 0 {
		t.Fatalf("defaults %d / %d, want 30 / 0", d.ReturnedCopyRetentionDays, d.WorkspaceRetentionDays)
	}
	for _, tc := range []struct {
		days int
		want string
	}{
		{0, ""},
		{1, ""},
		{30, ""},
		{3650, ""},
		{-1, "returned_copy_retention_days"},
		{3651, "returned_copy_retention_days"},
	} {
		c := Default()
		c.Terminal.Sandbox.ReturnedCopyRetentionDays = tc.days
		err := Validate(c)
		if tc.want == "" && err != nil {
			t.Errorf("%d: %v", tc.days, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%d: err %v, want %q", tc.days, err, tc.want)
		}
	}
}

// TestHostedDiffAgainst pins [terminal.sandbox.hosted].diff_against: default
// baseline, "" reads as baseline, head is the other value, and anything else
// is refused by Validate.
func TestHostedDiffAgainst(t *testing.T) {
	if got := Default().Terminal.Sandbox.Hosted.DiffAgainst; got != HostedDiffAgainstBaseline {
		t.Fatalf("default %q", got)
	}
	for _, tc := range []struct {
		v    string
		want string
	}{
		{"", ""},
		{"baseline", ""},
		{"head", ""},
		{"HEAD", "diff_against"},
		{"tip", "diff_against"},
	} {
		c := Default()
		c.Terminal.Sandbox.Hosted.DiffAgainst = tc.v
		err := Validate(c)
		if tc.want == "" && err != nil {
			t.Errorf("%q: %v", tc.v, err)
		}
		if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%q: err %v, want %q", tc.v, err, tc.want)
		}
	}
}

// TestCopiesKeysLoadFromTOML: both keys read from a file, and a file that
// names neither keeps the defaults (the partial merge).
func TestCopiesKeysLoadFromTOML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte("[terminal.sandbox]\nreturned_copy_retention_days = 0\n\n[terminal.sandbox.hosted]\ndiff_against = \"head\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, GovernanceSidecar: NoGovernanceSidecar})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Terminal.Sandbox.ReturnedCopyRetentionDays != 0 || cfg.Terminal.Sandbox.Hosted.DiffAgainst != HostedDiffAgainstHead {
		t.Fatalf("loaded %d / %q", cfg.Terminal.Sandbox.ReturnedCopyRetentionDays, cfg.Terminal.Sandbox.Hosted.DiffAgainst)
	}
	if err := os.WriteFile(p, []byte("[terminal.sandbox]\nenabled = true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if cfg, err = Load(LoadOptions{GlobalPath: p, GovernanceSidecar: NoGovernanceSidecar}); err != nil {
		t.Fatal(err)
	}
	if cfg.Terminal.Sandbox.ReturnedCopyRetentionDays != 30 || cfg.Terminal.Sandbox.Hosted.DiffAgainst != HostedDiffAgainstBaseline {
		t.Fatalf("partial file %d / %q", cfg.Terminal.Sandbox.ReturnedCopyRetentionDays, cfg.Terminal.Sandbox.Hosted.DiffAgainst)
	}
}
