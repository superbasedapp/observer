package ipclass

import (
	"net"
	"testing"
)

// TestClassify pins the coarse buckets, including the transition forms the
// stdlib predicates do not look through. These rows mirror the ones
// internal/netpolicy pinned before the move, so the re-export shim is proven
// byte-equivalent.
func TestClassify(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip   string
		want Class
	}{
		{"8.8.8.8", ClassPublic},
		{"2606:4700::1111", ClassPublic},
		{"127.0.0.1", ClassLoopback},
		{"127.8.8.8", ClassLoopback},
		{"::1", ClassLoopback},
		{"10.0.0.1", ClassPrivate},
		{"172.16.5.5", ClassPrivate},
		{"192.168.1.1", ClassPrivate},
		{"100.64.0.1", ClassPrivate}, // CGNAT
		{"fd12::1", ClassPrivate},    // ULA
		{"169.254.169.254", ClassForbidden},
		{"169.254.0.1", ClassForbidden},
		{"fe80::1", ClassForbidden},
		{"0.0.0.0", ClassForbidden},
		{"0.1.2.3", ClassForbidden},
		{"::", ClassForbidden},
		{"224.0.0.1", ClassForbidden},
		{"ff02::1", ClassForbidden},
		{"::ffff:169.254.169.254", ClassForbidden}, // IPv4-mapped metadata
		{"::ffff:10.0.0.1", ClassPrivate},          // IPv4-mapped private
		{"::ffff:127.0.0.1", ClassLoopback},
		{"::127.0.0.1", ClassForbidden},        // IPv4-compatible (deprecated)
		{"::169.254.169.254", ClassForbidden},  //
		{"64:ff9b::a9fe:a9fe", ClassForbidden}, // NAT64-wrapped metadata
		{"64:ff9b::a00:1", ClassPrivate},       // NAT64-wrapped 10.0.0.1
		{"64:ff9b::808:808", ClassPublic},      // NAT64-wrapped 8.8.8.8
		{"2002:0a00:0001::", ClassPrivate},     // 6to4-wrapped 10.0.0.1
		{"2002:a9fe:a9fe::", ClassForbidden},   // 6to4-wrapped metadata
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test IP %q did not parse", tc.ip)
		}
		if got := Classify(ip); got != tc.want {
			t.Errorf("Classify(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if got := Classify(nil); got != ClassForbidden {
		t.Errorf("Classify(nil) = %v, want forbidden", got)
	}
}

// TestClassString pins the error-text forms internal/netpolicy's dial-refusal
// messages embed.
func TestClassString(t *testing.T) {
	t.Parallel()
	for c, want := range map[Class]string{
		ClassForbidden: "link-local/metadata/multicast",
		ClassLoopback:  "loopback",
		ClassPrivate:   "private-network",
		ClassPublic:    "public",
	} {
		if got := c.String(); got != want {
			t.Errorf("Class(%d).String() = %q, want %q", int(c), got, want)
		}
	}
}

// TestDetail covers every finer Kind, the metadata set in every encoding, and
// the transition-form unwrapping.
func TestDetail(t *testing.T) {
	t.Parallel()
	cases := []struct {
		ip   string
		want Kind
	}{
		// Metadata, one row per endpoint.
		{"169.254.169.254", KindMetadata},
		{"169.254.170.2", KindMetadata},
		{"169.254.170.23", KindMetadata},
		{"100.100.100.200", KindMetadata},
		{"fd00:ec2::254", KindMetadata},
		{"fd00:ec2::23", KindMetadata},
		// Metadata in every wrapping.
		{"::ffff:169.254.169.254", KindMetadata},
		{"64:ff9b::a9fe:a9fe", KindMetadata},
		{"2002:a9fe:a9fe::", KindMetadata},
		// Link-local that is not metadata.
		{"169.254.0.1", KindLinkLocal},
		{"fe80::1", KindLinkLocal},
		// Loopback and unspecified.
		{"127.0.0.1", KindLoopback},
		{"::1", KindLoopback},
		{"0.0.0.0", KindUnspecified},
		{"0.1.2.3", KindUnspecified}, // 0.0.0.0/8
		{"::", KindUnspecified},
		{"::127.0.0.1", KindUnspecified}, // deprecated IPv4-compatible
		// Private ranges.
		{"10.0.0.1", KindPrivate},
		{"172.16.5.5", KindPrivate},
		{"192.168.1.1", KindPrivate},
		{"::ffff:10.0.0.1", KindPrivate},
		{"64:ff9b::a00:1", KindPrivate}, // NAT64-wrapped 10.0.0.1
		// CGNAT (minus its metadata address, tested above).
		{"100.64.0.1", KindCGNAT},
		{"100.127.255.255", KindCGNAT},
		// ULA that is not metadata.
		{"fd12::1", KindULA},
		{"fc00::1", KindULA},
		// Multicast.
		{"224.0.0.1", KindMulticast},
		{"ff02::1", KindMulticast},
		// Public.
		{"8.8.8.8", KindPublic},
		{"2606:4700::1111", KindPublic},
		{"64:ff9b::808:808", KindPublic}, // NAT64-wrapped 8.8.8.8
	}
	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test IP %q did not parse", tc.ip)
		}
		if got := Detail(ip); got != tc.want {
			t.Errorf("Detail(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	if got := Detail(nil); got != KindUnspecified {
		t.Errorf("Detail(nil) = %v, want unspecified", got)
	}
}

// TestKindPrivate pins which Kinds R-175 counts as a non-public internal
// address.
func TestKindPrivate(t *testing.T) {
	t.Parallel()
	for k, want := range map[Kind]bool{
		KindPrivate:     true,
		KindLinkLocal:   true,
		KindCGNAT:       true,
		KindULA:         true,
		KindLoopback:    false,
		KindUnspecified: false,
		KindMetadata:    false,
		KindMulticast:   false,
		KindPublic:      false,
	} {
		if got := k.Private(); got != want {
			t.Errorf("Kind(%s).Private() = %t, want %t", k, got, want)
		}
	}
}

// TestParseHostIP covers every loose encoding, each resolving to the address
// a command would dial, plus the forms that are not addresses at all.
func TestParseHostIP(t *testing.T) {
	t.Parallel()
	meta := net.IPv4(169, 254, 169, 254).To4()
	cases := []struct {
		in   string
		want string // canonical form, "" = not an IP
	}{
		// Canonical.
		{"169.254.169.254", "169.254.169.254"},
		{"8.8.8.8", "8.8.8.8"},
		{"::1", "::1"},
		// Bracketed IPv6 and zone id.
		{"[::1]", "::1"},
		{"[fe80::1]", "fe80::1"},
		{"fe80::1%eth0", "fe80::1"},
		{"169.254.169.254%2", "169.254.169.254"},
		// Single decimal / hex (169.254.169.254 == 0xa9fea9fe).
		{"2852039166", "169.254.169.254"},
		{"0xa9fea9fe", "169.254.169.254"},
		{"0Xa9fea9fe", "169.254.169.254"},
		// Octal components.
		{"0251.0376.0251.0376", "169.254.169.254"},
		// 2-part and 3-part short forms (127.1 == 127.0.0.1).
		{"127.1", "127.0.0.1"},
		{"127.0.1", "127.0.0.1"},
		{"169.254.43518", "169.254.169.254"}, // a.b.c with c = 0xa9fe
		// Mixed radix.
		{"0xa9.254.169.254", "169.254.169.254"},
		// Not addresses.
		{"example.com", ""},
		{"", ""},
		{"169.254.169.254.5", ""}, // five parts
		{"256.1.1.1", ""},         // component out of range
		{"10.0.0.0x", ""},         // malformed hex
		{"metadata.google.internal", ""},
	}
	for _, tc := range cases {
		got, ok := ParseHostIP(tc.in)
		if tc.want == "" {
			if ok {
				t.Errorf("ParseHostIP(%q) = %v, want not-an-IP", tc.in, got)
			}
			continue
		}
		if !ok {
			t.Errorf("ParseHostIP(%q) = not-an-IP, want %s", tc.in, tc.want)
			continue
		}
		if want := net.ParseIP(tc.want); !want.Equal(got) {
			t.Errorf("ParseHostIP(%q) = %v, want %s", tc.in, got, tc.want)
		}
	}
	// The single-decimal metadata form really does classify as metadata -
	// the point of accepting loose encodings.
	if ip, ok := ParseHostIP("2852039166"); !ok || !ip.Equal(meta) || Detail(ip) != KindMetadata {
		t.Errorf("ParseHostIP(decimal metadata) = %v ok=%t detail=%v, want the metadata address", ip, ok, Detail(ip))
	}
}
