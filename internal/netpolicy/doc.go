// Package netpolicy is the PURE IP-classification and dial-control primitive
// shared by every outbound dial Observer makes on behalf of an admin-supplied
// URL (Agent Access implementation plan section 5, ruling R8.23.b):
// internal/mcpegress builds its SSRF-safe egress client on it; the older
// internal/aigateway/ssrf.go and internal/orgserver/llmprovider/ssrf.go
// carry byte-equivalent classification of their own and remain the owners of
// their product-specific error text and unlock tables (a re-export shim was
// judged invasive for this wave and deliberately not applied - see the P2
// Lane A report).
//
// Two layers with sharply different jobs, and the package only supplies the
// second half of each:
//
//   - a PRE-FLIGHT check at upsert time (the caller's ValidateUpstreamBaseURL)
//     gives an admin an inline error. It is NOT the security boundary: a
//     hostname it accepts can resolve anywhere, at any time.
//
//   - DialPolicy.CheckDialAddress IS the boundary. It runs per connection
//     attempt, in net.Dialer.Control, on the address the RESOLVER actually
//     produced, so a DNS answer that flips between the check and the dial
//     (rebinding) is caught at the dial and a name with several A records is
//     checked per address.
//
// The zero DialPolicy is the strictest one (public only), so a caller that
// forgets to resolve a policy fails closed. Link-local / cloud-metadata
// (169.254.0.0/16, fe80::/10), multicast, the unspecified address, 0.0.0.0/8
// and the deprecated IPv4-compatible ::/96 form are ClassForbidden: NO policy
// reaches them. NAT64 (64:ff9b::/96) and 6to4 (2002::/16) are unwrapped and
// classified as the IPv4 they embed, so `64:ff9b::a9fe:a9fe` is refused as the
// metadata address it really is while a legitimate IPv6-only network keeps
// reaching public providers through NAT64.
//
// IP classification itself lives in internal/ipclass, the one owner, which
// this package re-exports unchanged (NetworkClass, the four Class values,
// ClassifyIP and IsLoopbackHost in classify.go): the dial policy here and the
// developer-side guard's network rules both classify an address through that
// single leaf, so a metadata or private-range verdict can never fork between
// the two. This package adds only the dial-time policy on top.
//
// The package imports only the standard library's net/syscall/fmt/errors plus
// internal/ipclass: no database/sql, no net/http, no fsnotify (imports_test.go
// pins it).
package netpolicy
