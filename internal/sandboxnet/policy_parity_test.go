package sandboxnet

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/ipclass"
	"github.com/marmutapp/superbased-observer/internal/sandboxcidr"
)

// parityAddresses is the fixed table the two classifiers are compared on: one
// or more addresses per range either names, in plain, IPv4-mapped, NAT64 and
// 6to4 forms.
var parityAddresses = []string{
	"0.0.0.0", "0.1.2.3", "::", "127.0.0.1", "127.255.255.254", "::1",
	"169.254.0.1", "169.254.169.254", "169.254.170.2", "169.254.170.23", "fe80::1",
	"224.0.0.1", "239.1.2.3", "ff01::1", "ff02::1", "ff0e::1",
	"10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.1.1",
	"100.64.0.1", "100.100.100.200", "100.127.255.254",
	"fc00::1", "fd12:3456::1", "fd00:ec2::254", "fd00:ec2::23",
	"::7f00:1", "::a00:1",
	"::ffff:127.0.0.1", "::ffff:10.1.2.3", "::ffff:169.254.169.254", "::ffff:100.100.100.200", "::ffff:8.8.8.8",
	"64:ff9b::7f00:1", "64:ff9b::a01:203", "64:ff9b::a9fe:a9fe", "64:ff9b::6464:64c8", "64:ff9b::808:808",
	"2002:7f00:1::", "2002:a00:1::", "2002:a9fe:a9fe::", "2002:6440:1::", "2002:6464:64c8::", "2002:808:808::",
	"8.8.8.8", "203.0.113.7", "172.32.0.1", "100.128.0.1", "2001:4860:4860::8888",
	"255.255.255.255", "fec0::1",
}

// parityExceptions are the addresses on which sandboxnet refuses what
// ipclass.Classify calls public, each with its reason. ipclass is the
// weaker classifier on both, and it also backs the dial policy of
// netpolicy, aigateway, mcpegress and netguard, so tightening it is a
// separate decision (lane report); sandboxnet keeps its own refinement.
var parityExceptions = map[string]struct {
	reason        string
	allowListable bool
}{
	"255.255.255.255": {"limited broadcast: ipclass reads it public", false},
	"fec0::1":         {"deprecated site-local fec0::/10: ipclass reads it public", true},
}

// TestPolicyParityWithIPClass pins that the egress policy and internal/ipclass
// cannot drift again (SEC-02): with no allow-list, sandboxnet refuses exactly
// the addresses ipclass.Classify does not call public; with every private
// range allow-listed, it refuses exactly the forbidden, loopback and metadata
// ones (ipclass.Detail). The host's own addresses (a sandboxnet-only rule by
// design) are not in play: local is nil.
func TestPolicyParityWithIPClass(t *testing.T) {
	t.Parallel()
	var allowAll []netip.Prefix
	for _, r := range sandboxcidr.PrivateRanges() {
		allowAll = append(allowAll, r.Prefixes...)
	}
	for _, s := range parityAddresses {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad table address %q", s)
		}
		class, kind := ipclass.Classify(ip), ipclass.Detail(ip)

		exc, isExc := parityExceptions[s]
		refused := DestinationAllowed(ip, nil) != nil
		want := class != ipclass.ClassPublic || isExc
		if refused != want {
			t.Errorf("%s: sandboxnet refused=%v, ipclass class=%v kind=%v", s, refused, class, kind)
		}

		err := Policy{Allow: allowAll}.Check(ip, nil)
		refusedAll := err != nil
		wantAll := class == ipclass.ClassForbidden || class == ipclass.ClassLoopback || kind == ipclass.KindMetadata
		if isExc {
			wantAll = !exc.allowListable
		}
		if refusedAll != wantAll {
			t.Errorf("%s under an allow-all-private list: refused=%v (%v), want %v (class=%v kind=%v)", s, refusedAll, err, wantAll, class, kind)
		}
		var re *RefusedError
		if kind == ipclass.KindMetadata && (!errors.As(err, &re) || re.AllowListable) {
			t.Errorf("%s: a metadata address must be refused by a never-liftable rule, got %v", s, err)
		}
	}
}
