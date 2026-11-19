package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestHostedPrivateRangesDefaultAndOverride (SBXD-7): the shared key defaults
// to false (the ranges denied); a provider table's override wins in both
// directions; nil follows the shared value.
func TestHostedPrivateRangesDefaultAndOverride(t *testing.T) {
	c := Default().Terminal.Sandbox.Hosted
	if c.AllowPrivateRanges {
		t.Fatal("allow_private_ranges defaults to true")
	}
	on, off := true, false
	cases := []struct {
		shared   bool
		override *bool
		want     bool
	}{
		{false, nil, false},
		{true, nil, true},
		{false, &on, true},
		{true, &off, false},
	}
	for _, tc := range cases {
		c.AllowPrivateRanges = tc.shared
		if got := c.PrivateRangesAllowed(TerminalSandboxHostedProviderConfig{AllowPrivateRanges: tc.override}); got != tc.want {
			t.Errorf("shared %v override %v: %v", tc.shared, tc.override, got)
		}
	}
}

// TestHostedPrivateRangesValidated: an override is accepted on a provider
// table whose vendor can deny ranges and refused, naming the table, on any
// other (it would do nothing).
func TestHostedPrivateRangesValidated(t *testing.T) {
	on := true
	for _, name := range []string{"e2b", "modal", "vercel", "docker", "instabox", "daytona"} {
		c := Default().Terminal.Sandbox.Hosted
		c.ProviderTable(name).AllowPrivateRanges = &on
		err := validateTerminalSandboxHosted(c)
		capable := false
		for _, n := range HostedPrivateRangeDenyProviders {
			capable = capable || n == name
		}
		if capable && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !capable && (err == nil || !strings.Contains(err.Error(), "hosted."+name+".allow_private_ranges")) {
			t.Errorf("%s: an override with no effect was accepted: %v", name, err)
		}
	}
	if (&TerminalSandboxHostedConfig{}).ProviderTable("openshell-org") != nil {
		t.Error("the org row's table is not a provider table")
	}
}

// TestHostedPrivateRangesFromTOML: both keys decode, the per-provider one as
// an optional bool.
func TestHostedPrivateRangesFromTOML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	body := "[terminal.sandbox.hosted]\nallow_private_ranges = true\n[terminal.sandbox.hosted.e2b]\nallow_private_ranges = false\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(LoadOptions{GlobalPath: p, Env: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Terminal.Sandbox.Hosted
	if !h.AllowPrivateRanges || h.E2B.AllowPrivateRanges == nil || *h.E2B.AllowPrivateRanges || h.Vercel.AllowPrivateRanges != nil {
		t.Fatalf("decoded %+v / e2b %v / vercel %v", h.AllowPrivateRanges, h.E2B.AllowPrivateRanges, h.Vercel.AllowPrivateRanges)
	}
	if h.PrivateRangesAllowed(h.E2B) || !h.PrivateRangesAllowed(h.Vercel) {
		t.Error("the override does not decide its vendor")
	}
}

// TestGovernancePinOfPrivateRangesClearsOverrides: the org may only pin the
// shared key to false (the ranges denied); the pin clears every provider
// table's override, each reported as the organization's, and a pin to true
// is skipped.
func TestGovernancePinOfPrivateRangesClearsOverrides(t *testing.T) {
	dbDir := t.TempDir()
	cfgPath := govTempConfig(t, dbDir, "[terminal.sandbox.hosted]\nallow_private_ranges = true\n[terminal.sandbox.hosted.vercel]\nallow_private_ranges = true\n")
	govWriteSidecar(t, dbDir, `{"schema":1,"state":"applied","pinned":{"terminal.sandbox.hosted.allow_private_ranges":false}}`)
	cfg, out, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath, Env: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Terminal.Sandbox.Hosted
	if h.AllowPrivateRanges || h.Vercel.AllowPrivateRanges != nil || h.PrivateRangesAllowed(h.Vercel) {
		t.Fatalf("the pin did not hold: shared %v vercel %v", h.AllowPrivateRanges, h.Vercel.AllowPrivateRanges)
	}
	want := []string{
		"terminal.sandbox.hosted.allow_private_ranges",
		"terminal.sandbox.hosted.docker.allow_private_ranges",
		"terminal.sandbox.hosted.e2b.allow_private_ranges",
		"terminal.sandbox.hosted.vercel.allow_private_ranges",
	}
	if !reflect.DeepEqual(out.Applied, want) {
		t.Fatalf("applied %v, want %v", out.Applied, want)
	}

	dbDir2 := t.TempDir()
	cfgPath2 := govTempConfig(t, dbDir2, "")
	govWriteSidecar(t, dbDir2, `{"schema":1,"state":"applied","pinned":{"terminal.sandbox.hosted.allow_private_ranges":true}}`)
	cfg2, out2, err := LoadGovernance(LoadOptions{GlobalPath: cfgPath2, Env: noEnv})
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Terminal.Sandbox.Hosted.AllowPrivateRanges || out2.Skipped["terminal.sandbox.hosted.allow_private_ranges"] == "" {
		t.Fatalf("a pin opening the ranges applied: %+v", out2)
	}
}
