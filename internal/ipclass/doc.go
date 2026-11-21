// Package ipclass is the ONE owner of IP-address classification across
// Observer: the coarse dial-policy bucket every outbound dial consults and
// the finer, named classification the developer-side guard's network rules
// need. It is a PURE leaf: it imports only the standard library (net,
// strings, strconv) and no Observer package at all, so the same address
// yields the same class on every OS (imports_test.go pins it, StdlibOnly).
//
// Two classifications, one address model:
//
//   - Classify(ip) Class buckets an address into Forbidden / Loopback /
//     Private / Public — the coarse set internal/netpolicy's DialPolicy
//     reaches for. internal/netpolicy re-exports Class, its four consts,
//     ClassifyIP and IsLoopbackHost unchanged, so every existing caller is
//     byte-for-byte unaffected.
//
//   - Detail(ip) Kind buckets the SAME address into the finer set the guard
//     wants: Metadata (every cloud instance-metadata address), LinkLocal,
//     Loopback, Unspecified ("this network" 0.0.0.0/8 included), Private
//     (RFC 1918), CGNAT (RFC 6598 100.64/10 minus the metadata address),
//     ULA (fc00::/7), Multicast and Public. The guard's R-174 metadata row
//     and R-175 private-range row branch on Kind, so the "what is this
//     address" question has one answer that both the dial policy and the
//     guard agree on.
//
// Both unwrap the IPv4-in-IPv6 transition forms the stdlib predicates do not
// look through — IPv4-mapped (::ffff:a.b.c.d), NAT64 (64:ff9b::/96) and 6to4
// (2002::/16) — so a metadata address wrapped in any of them is still seen as
// the metadata address it really is.
//
// ParseHostIP accepts the LOOSE address spellings curl, wget and browsers
// accept — a single decimal (2852039166), hex (0xa9fea9fe), octal parts
// (0251.0376.0251.0376), the 2- and 3-part short forms, bracketed IPv6
// ([::1]) and a zone id to strip — so a network rule classifies the address a
// command would actually reach, not only its canonical dotted-quad.
package ipclass
