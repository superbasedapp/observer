package hostguard

import "testing"

// TestIsLoopbackHost is the table pin for the shared Host-header predicate
// both ingest listeners depend on. One row per rule in the doc comment,
// including the two that matter for DNS rebinding: a name that is not
// "localhost" is never loopback (no resolver is consulted), and a
// non-loopback IP is never loopback however it is spelled.
func TestIsLoopbackHost(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
		want bool
	}{
		{"empty host (HTTP/1.0)", "", true},
		{"bare localhost", "localhost", true},
		{"localhost with port", "localhost:8821", true},
		{"ipv4 loopback", "127.0.0.1", true},
		{"ipv4 loopback with port", "127.0.0.1:4318", true},
		{"ipv4 loopback elsewhere in 127/8", "127.5.6.7:4318", true},
		{"ipv6 loopback bracketed with port", "[::1]:4318", true},
		{"ipv6 loopback bare", "::1", true},
		// RFC 7230 permits a bracketed literal with no port. Both
		// SplitHostPort (no port) and ParseIP (brackets) reject this form, so
		// it needs the explicit unwrap — without it a legitimate local client
		// is refused 403.
		{"ipv6 loopback bracketed without port", "[::1]", true},
		{"ipv6 loopback long form bracketed", "[0:0:0:0:0:0:0:1]", true},
		{"ipv6 non-loopback bracketed without port", "[2001:db8::1]", false},
		{"ipv6 non-loopback bracketed with port", "[2001:db8::1]:4318", false},
		{"empty brackets are not an address", "[]", false},
		{"rebinding domain", "evil.example", false},
		{"rebinding domain with port", "evil.example:4318", false},
		{"subdomain of localhost is not localhost", "a.localhost", false},
		{"public ip", "203.0.113.7", false},
		{"public ip with port", "203.0.113.7:4318", false},
		{"private lan ip", "192.168.1.10:4318", false},
		{"link-local metadata ip", "169.254.169.254", false},
		{"unresolvable garbage", "?!", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsLoopbackHost(tc.host); got != tc.want {
				t.Errorf("IsLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
			}
		})
	}
}
