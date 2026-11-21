package sandboxremote

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// v4Ranges and allRanges are what a denying create carries.
var (
	v4Ranges  = []string{"169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"}
	allRanges = append(slices.Clone(v4Ranges), "fd00:ec2::254/128", "fc00::/7", "fe80::/10")
)

// TestPrivateRangeDenyTable (SBXD-7): one case per vendor x tier x setting,
// the posture and the exact ranges the create carries.
func TestPrivateRangeDenyTable(t *testing.T) {
	type want struct {
		posture PrivateRangePosture
		cidrs   []string
	}
	na := want{PrivateRangesNotApplicable, nil}
	nd := want{PrivateRangesNotDeniable, nil}
	al := want{PrivateRangesAllowedBySetting, nil}
	cases := []struct {
		vendor string
		tier   vocab.Tier
		allow  bool
		want   want
	}{
		{VendorE2B, vocab.TierInternet, false, want{PrivateRangesDenied, v4Ranges}},
		{VendorE2B, "", false, want{PrivateRangesDenied, v4Ranges}},
		{VendorE2B, vocab.TierInternet, true, al},
		{VendorE2B, vocab.TierProxyOnly, false, na},
		{VendorE2B, vocab.TierNone, true, na},
		{VendorVercel, vocab.TierInternet, false, want{PrivateRangesDenied, v4Ranges}},
		{VendorVercel, vocab.TierInternet, true, al},
		{VendorVercel, vocab.TierProxyOnly, false, na},
		{VendorDockerSandboxes, vocab.TierInternet, false, want{PrivateRangesDenied, allRanges}},
		{VendorDockerSandboxes, vocab.TierInternet, true, al},
		{VendorDockerSandboxes, vocab.TierNone, false, na},
		{VendorModal, vocab.TierInternet, false, nd},
		{VendorModal, vocab.TierInternet, true, nd},
		{VendorModal, vocab.TierProxyOnly, false, na},
		{VendorDaytona, vocab.TierInternet, false, nd},
		{VendorDaytona, vocab.TierInternet, true, nd},
		{VendorDaytona, vocab.TierNone, false, na},
		{VendorInstaBox, vocab.TierInternet, false, nd},
		{VendorInstaBox, vocab.TierProxyOnly, false, na}, // no such tier
		{VendorOpenShellOrg, vocab.TierInternet, false, na},
		{VendorOpenShellOrg, vocab.TierInternet, true, na},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		v, ok := VendorFor(c.vendor)
		if !ok {
			t.Fatalf("no vendor %s", c.vendor)
		}
		seen[c.vendor] = true
		got := PrivateRangeDeny(v, c.tier, c.allow)
		if got.Posture != c.want.posture || !slices.Equal(got.CIDRs, c.want.cidrs) {
			t.Errorf("%s %q allow=%v: %+v, want %+v", c.vendor, c.tier, c.allow, got, c.want)
		}
	}
	for _, id := range VendorIDs() {
		if !seen[id] {
			t.Errorf("vendor %s has no case", id)
		}
	}
}

// TestRangeDenyRulesEachReached: every row of the ordered table decides at
// least one case.
func TestRangeDenyRulesEachReached(t *testing.T) {
	hit := map[PrivateRangePosture]bool{}
	for _, id := range VendorIDs() {
		v, _ := VendorFor(id)
		for _, tier := range []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone} {
			for _, allow := range []bool{false, true} {
				hit[PrivateRangeDeny(v, tier, allow).Posture] = true
			}
		}
	}
	for _, r := range rangeDenyRules {
		if !hit[r.posture] {
			t.Errorf("rule %q is never reached", r.name)
		}
	}
}

// TestPrivateRangesList: every entry parses as a prefix of its stated
// family, carries a reason, holds the metadata addresses it names, and no
// entry is loopback or public.
func TestPrivateRangesList(t *testing.T) {
	var prefixes []netip.Prefix
	for _, r := range PrivateRanges {
		p, err := netip.ParsePrefix(r.CIDR)
		if err != nil || p.Masked() != p {
			t.Fatalf("%s: %v (not a canonical prefix)", r.CIDR, err)
		}
		if p.Addr().Is6() != r.IPv6 || r.Why == "" {
			t.Errorf("%s: family or reason wrong: %+v", r.CIDR, r)
		}
		// 100.64.0.0/10 is shared address space, which netip counts as
		// neither private nor link-local.
		if a := p.Addr(); a.IsLoopback() || (!a.IsPrivate() && !a.IsLinkLocalUnicast() && r.CIDR != "100.64.0.0/10") {
			t.Errorf("%s is loopback or public", r.CIDR)
		}
		prefixes = append(prefixes, p)
	}
	for _, a := range []string{"169.254.169.254", "fd00:ec2::254", "100.100.100.200", "10.0.0.1", "172.31.255.255", "192.168.1.1", "fe80::1", "fd12::1"} {
		addr := netip.MustParseAddr(a)
		if !slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			t.Errorf("%s is not denied", a)
		}
	}
	for _, a := range []string{"127.0.0.1", "1.1.1.1", "8.8.8.8", "2606:4700::1111"} {
		addr := netip.MustParseAddr(a)
		if slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) }) {
			t.Errorf("%s is denied", a)
		}
	}
}

// TestDenyCapabilitiesGrounded: a vendor that can deny names how and where
// that is grounded (a dated source); one that cannot names what was not
// found in its Unverified list.
func TestDenyCapabilitiesGrounded(t *testing.T) {
	for _, id := range VendorIDs() {
		v, _ := VendorFor(id)
		if !claimedTier(v, vocab.TierInternet) {
			continue
		}
		if v.DenyRanges.Supported() {
			if !strings.Contains(v.DenyRanges.Source, "2026-") || !strings.Contains(v.DenyRanges.Source, "read") {
				t.Errorf("%s: deny source is not dated: %q", id, v.DenyRanges.Source)
			}
			continue
		}
		if !slices.ContainsFunc(v.Unverified, func(s string) bool { return strings.Contains(s, "SBXD-7") }) {
			t.Errorf("%s cannot deny and its Unverified list does not say what was not found", id)
		}
	}
}

// TestTierNetworkNotesPerPosture: the sentence says denied by Observer's
// request, not deniable on that vendor, or allowed by the setting.
func TestTierNetworkNotesPerPosture(t *testing.T) {
	cases := []struct {
		vendor string
		allow  bool
		says   []string
		never  []string
	}{
		{VendorE2B, false, []string{"Observer's request asks E2B to refuse", "E2B enforces that, not Observer", "IPv4 ranges"}, []string{"may reach them"}},
		{VendorDockerSandboxes, false, []string{"Observer's request asks Docker Sandboxes to refuse"}, []string{"IPv4 ranges", "may reach them"}},
		{VendorE2B, true, []string{"Your setting allows private network ranges for E2B", "may reach them"}, []string{"Observer's request asks"}},
		{VendorModal, false, []string{"Modal's API takes no rule", "may reach them"}, []string{"Observer's request asks", "Your setting"}},
		{VendorModal, true, []string{"Modal's API takes no rule"}, []string{"Your setting"}},
	}
	for _, c := range cases {
		v, _ := VendorFor(c.vendor)
		n := TierNetworkNotes(v, vocab.TierInternet, c.allow)[0]
		for _, s := range c.says {
			if !strings.Contains(n, s) {
				t.Errorf("%s allow=%v: %q lacks %q", c.vendor, c.allow, n, s)
			}
		}
		for _, s := range c.never {
			if strings.Contains(n, s) {
				t.Errorf("%s allow=%v: %q says %q", c.vendor, c.allow, n, s)
			}
		}
		if internalWordRE.MatchString(n) {
			t.Errorf("%s: internal word in %q", c.vendor, n)
		}
	}
}

// TestConsentBindsPrivateRanges: a record made before the fact existed
// still verifies; a change of the posture reopens consent with its own
// verdict; the consent screen's network line follows the bound fact.
func TestConsentBindsPrivateRanges(t *testing.T) {
	old := baseFacts()
	rec := NewConsent(old, "2026-10-22T00:00:00Z")
	// A record written before the field: no key in its JSON, the digest of
	// the old field set.
	if strings.Contains(fmt.Sprint(rec.Facts), "denied") {
		t.Fatal("baseFacts carries a posture")
	}
	if v := CheckConsent(&rec, old); v != ConsentOK {
		t.Fatalf("an older record no longer verifies: %s", v)
	}
	for _, now := range []string{"denied", "allowed"} {
		f := old
		f.PrivateRanges = now
		if v := CheckConsent(&rec, f); v != ConsentChangedPrefix+"private_ranges" {
			t.Errorf("%s: %s", now, v)
		}
	}
	denied := old
	denied.PrivateRanges = "denied"
	rec2 := NewConsent(denied, "2026-11-18T00:00:00Z")
	if v := CheckConsent(&rec2, denied); v != ConsentOK {
		t.Fatalf("denied record: %s", v)
	}
	allowed := denied
	allowed.PrivateRanges = "allowed"
	if v := CheckConsent(&rec2, allowed); v != ConsentChangedPrefix+"private_ranges" {
		t.Errorf("denied -> allowed: %s", v)
	}

	v, _ := VendorFor(VendorE2B)
	screen := func(f ConsentFacts) string {
		f.Tier = string(vocab.TierInternet)
		return fmt.Sprint(BuildConsentScreen(v, f, Manifest{Root: "/w/p"}, v.EstimateCost(60)).Lines)
	}
	if s := screen(denied); !strings.Contains(s, "Observer's request asks E2B to refuse") {
		t.Errorf("denied screen: %s", s)
	}
	if s := screen(allowed); !strings.Contains(s, "Your setting allows private network ranges for E2B") {
		t.Errorf("allowed screen: %s", s)
	}
}
