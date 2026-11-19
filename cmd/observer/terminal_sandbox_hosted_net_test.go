//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// hostedNetTableOf names the config provider table a vendor's row reads
// (found by marking each table and reading it back through the row).
func hostedNetTableOf(t *testing.T, vendor string) string {
	t.Helper()
	on := true
	for _, name := range []string{"e2b", "modal", "vercel", "docker", "instabox", "daytona"} {
		var c config.TerminalSandboxHostedConfig
		c.ProviderTable(name).AllowPrivateRanges = &on
		if hostedVendorConfig(c, vendor).AllowPrivateRanges != nil {
			return name
		}
	}
	return ""
}

// TestHostedNetDenyProvidersMirror: config's HostedPrivateRangeDenyProviders
// (the tables whose override validates) is exactly the vendor rows whose
// create can deny ranges.
func TestHostedNetDenyProvidersMirror(t *testing.T) {
	var want []string
	for _, id := range sandboxremote.VendorIDs() {
		v, _ := sandboxremote.VendorFor(id)
		name := hostedNetTableOf(t, id)
		if name == "" {
			if v.DenyRanges.Supported() {
				t.Errorf("%s can deny but has no provider table", id)
			}
			continue
		}
		if v.DenyRanges.Supported() {
			want = append(want, name)
		}
	}
	slices.Sort(want)
	got := slices.Clone(config.HostedPrivateRangeDenyProviders)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("config mirror %v, vendor table %v", got, want)
	}
}

// TestHostedNetRangeDenyFollowsSettings: the shared key and a provider
// override decide what the create carries, per vendor.
func TestHostedNetRangeDenyFollowsSettings(t *testing.T) {
	e2b, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	modal, _ := sandboxremote.VendorFor(sandboxremote.VendorModal)
	on, off := true, false
	cfg := config.Default().Terminal.Sandbox.Hosted
	if d := hostedRangeDeny(e2b, cfg, vocab.TierInternet); d.Posture != sandboxremote.PrivateRangesDenied || !slices.Contains(d.CIDRs, "169.254.0.0/16") {
		t.Errorf("default: %+v", d)
	}
	cfg.AllowPrivateRanges = true
	if d := hostedRangeDeny(e2b, cfg, vocab.TierInternet); d.Posture != sandboxremote.PrivateRangesAllowedBySetting || d.CIDRs != nil {
		t.Errorf("shared allow: %+v", d)
	}
	cfg.E2B.AllowPrivateRanges = &off
	if d := hostedRangeDeny(e2b, cfg, vocab.TierInternet); d.Posture != sandboxremote.PrivateRangesDenied {
		t.Errorf("override deny under a shared allow: %+v", d)
	}
	cfg.AllowPrivateRanges, cfg.E2B.AllowPrivateRanges = false, &on
	if d := hostedRangeDeny(e2b, cfg, vocab.TierInternet); d.Posture != sandboxremote.PrivateRangesAllowedBySetting {
		t.Errorf("override allow: %+v", d)
	}
	if d := hostedRangeDeny(modal, cfg, vocab.TierInternet); d.Posture != sandboxremote.PrivateRangesNotDeniable || d.CIDRs != nil {
		t.Errorf("modal: %+v", d)
	}
	if d := hostedRangeDeny(e2b, config.Default().Terminal.Sandbox.Hosted, vocab.TierProxyOnly); d.Posture != sandboxremote.PrivateRangesNotApplicable || d.CIDRs != nil {
		t.Errorf("proxy_only: %+v", d)
	}
}

// TestHostedNetConsentReopensOnSettingChange: a consent recorded on the
// internet tier binds the deny; turning allow_private_ranges on (shared or
// for the vendor) reopens it with plain words; on a vendor that cannot deny
// the setting reopens nothing; a record made before the fact existed reopens
// once the deny is in force, and not on a blocked tier.
func TestHostedNetConsentReopensOnSettingChange(t *testing.T) {
	cfg := config.Default().Terminal.Sandbox.Hosted
	for _, tc := range []struct {
		vendor  string
		reopens bool
	}{{sandboxremote.VendorE2B, true}, {sandboxremote.VendorVercel, true}, {sandboxremote.VendorDockerSandboxes, true}, {sandboxremote.VendorModal, false}, {sandboxremote.VendorDaytona, false}} {
		v, _ := sandboxremote.VendorFor(tc.vendor)
		d := &hostedDriver{cfg: cfg, vendor: v}
		f, ok := d.consentFactsStatic()
		if !ok {
			t.Fatalf("%s: no static facts", tc.vendor)
		}
		f.Tier, f.Capture, f.ScopeKey = string(vocab.TierInternet), "full", "k"
		f.PrivateRanges = hostedPrivateRangesFact(v, cfg, vocab.TierInternet)
		rec := sandboxremote.NewConsent(f, "2026-11-18T00:00:00Z")
		static, _ := d.consentFactsStatic()
		if got := hostedStaticConsentVerdict(rec, static, v, cfg); got != sandboxremote.ConsentOK {
			t.Fatalf("%s: unchanged settings: %s", tc.vendor, got)
		}
		opened := cfg
		opened.AllowPrivateRanges = true
		got := hostedStaticConsentVerdict(rec, static, v, opened)
		if (got == sandboxremote.ConsentChangedPrefix+"private_ranges") != tc.reopens || (!tc.reopens && got != sandboxremote.ConsentOK) {
			t.Errorf("%s: allow_private_ranges on: %s", tc.vendor, got)
		}
		if tc.reopens {
			if r := consentChangeReason(got); !strings.Contains(r, "private network addresses") || strings.Contains(r, "private_ranges") {
				t.Errorf("%s: reason %q", tc.vendor, r)
			}
		}
	}

	// A record made before the fact: the deny now in force reopens it on the
	// internet tier, never on a blocked one.
	e2b, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	d := &hostedDriver{cfg: cfg, vendor: e2b}
	for _, tier := range []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly} {
		f, _ := d.consentFactsStatic()
		f.Tier, f.Capture, f.ScopeKey = string(tier), "full", "k"
		rec := sandboxremote.NewConsent(f, "2026-10-22T00:00:00Z")
		static, _ := d.consentFactsStatic()
		got := hostedStaticConsentVerdict(rec, static, e2b, cfg)
		if want := map[vocab.Tier]string{vocab.TierInternet: sandboxremote.ConsentChangedPrefix + "private_ranges", vocab.TierProxyOnly: sandboxremote.ConsentOK}[tier]; got != want {
			t.Errorf("older record on %s: %s, want %s", tier, got, want)
		}
	}
}

// TestHostedNetTierNetworkNotesInProbe: the New Terminal dialog's "The box's
// network" notes say denied, allowed by the setting, or not deniable.
func TestHostedNetTierNetworkNotesInProbe(t *testing.T) {
	cfg := config.Default().Terminal.Sandbox
	for _, tc := range []struct {
		backend string
		allow   bool
		says    string
	}{
		{sandboxbackend.BackendE2B, false, "Observer's request asks E2B to refuse"},
		{sandboxbackend.BackendE2B, true, "Your setting allows private network ranges for E2B"},
		{sandboxremote.VendorModal, false, "Modal's API takes no rule"},
	} {
		row, ok := sandboxbackend.Get(tc.backend)
		if !ok {
			t.Fatalf("no row %s", tc.backend)
		}
		c := cfg
		c.Hosted.AllowPrivateRanges = tc.allow
		var e dashapi.SandboxBackendAvail
		hostedFillProbeRow(&e, row, c, vocab.TierInternet)
		if len(e.NetworkNotes) == 0 || !strings.Contains(e.NetworkNotes[0], tc.says) {
			t.Errorf("%s allow=%v: %v", tc.backend, tc.allow, e.NetworkNotes)
		}
	}
}
