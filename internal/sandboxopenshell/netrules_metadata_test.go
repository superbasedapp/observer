package sandboxopenshell

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/ipclass"
	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestNetAllowedIPsNeverOpensMetadata pins FR-SEC-6 (review 2026-11-22),
// the OpenShell counterpart of sandboxnet's
// TestPolicyAllowListNeverOpensMetadata: NetAllowedIPs added an
// allow-listed prefix whole, so `egress_allow_cidrs = ["100.64.0.0/10"]`
// put Alibaba Cloud's metadata endpoint 100.100.100.200 in allowed_ips, and
// `["fd00::/8"]` AWS IMDS over IPv6 (fd00:ec2::254). Every address
// ipclass.MetadataAddresses names stays out of allowed_ips under any
// allow-list, while the rest of the listed prefix stays open, and a refused
// metadata literal is explained by the SSRF-floor row (an address no
// allow-list lifts), not as a literal the host list could name.
func TestNetAllowedIPsNeverOpensMetadata(t *testing.T) {
	t.Parallel()
	var allowAll []string
	for _, r := range sandboxcidr.PrivateRanges() {
		for _, p := range r.Prefixes {
			allowAll = append(allowAll, p.String())
		}
	}
	lists := map[string][]string{
		"every allow-listable private range": allowAll,
		"shared address space":               {"100.64.0.0/10"},
		"unique local":                       {"fd00::/8"},
		"the AWS IPv6 metadata /64":          {"fd00:ec2::/64"},
	}
	for name, allow := range lists {
		allowed, err := NetAllowedIPs(allow, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		inside := func(a netip.Addr) bool {
			return slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(a) })
		}
		for _, ip := range ipclass.MetadataAddresses() {
			a, ok := netip.AddrFromSlice(ip)
			if !ok {
				t.Fatalf("bad metadata address %v", ip)
			}
			if a = a.Unmap(); inside(a) {
				t.Errorf("%s: metadata address %s is in allowed_ips", name, a)
			}
		}
		for i := 1; i < len(allowed); i++ {
			if allowed[i-1].Overlaps(allowed[i]) {
				t.Errorf("%s: %s overlaps %s", name, allowed[i-1], allowed[i])
			}
		}
	}

	// The rest of a listed prefix stays open.
	allowed, err := NetAllowedIPs([]string{"100.64.0.0/10", "fd00::/8"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"100.64.0.1", "100.100.100.199", "100.100.100.201", "fd00::1", "fd00:ec2::253"} {
		a := netip.MustParseAddr(s)
		if !slices.ContainsFunc(allowed, func(p netip.Prefix) bool { return p.Contains(a) }) {
			t.Errorf("%s: allow-listed address is not in allowed_ips", s)
		}
	}

	// A refused metadata literal is the SSRF floor (M4), not M7.
	run := RunEgress{Tier: vocab.TierInternet, AllowCIDRs: []string{"100.64.0.0/10", "fd00::/8"}}
	for _, s := range []string{"100.100.100.200", "fd00:ec2::254"} {
		a := netip.MustParseAddr(s)
		rule, key, row := MapOCSFDenial(OCSFDenial{Host: a.String(), Addr: a, Port: 80, RuleType: "opa"}, run)
		if rule != OCSFRuleSSRFFloor || key != OCSFKeyEgress {
			t.Errorf("MapOCSFDenial(%s) = %s/%s (row %s), want %s/%s", s, rule, key, row, OCSFRuleSSRFFloor, OCSFKeyEgress)
		}
	}
}
