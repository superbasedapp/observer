// Package ipv6sock tells a test whether this host can open an IPv6 socket at
// all, so a test whose IPv6 case needs one can skip that case with a reason
// on a host without IPv6 instead of failing.
//
// The case that needs it: netguard (internal/netguard) checks an address in
// the dialer's Control hook, which runs after socket() and before
// connect(). On a kernel or VM with no IPv6 (no /proc/sys/net/ipv6;
// socket(AF_INET6) answers EAFNOSUPPORT, as on the Claude Code cloud boxes
// the v1.42.0 gate shards ran on) a dial of [fe80::1] fails at socket()
// before the check runs, so a test that wants a netguard refusal sees
// "address family not supported" instead. MustHave skips that case there;
// wherever IPv6 exists the refusal is still tested.
//
// TEST SUPPORT ONLY: no production command or package may import it
// (tests/invariant/vendormock_boundary_test.go).
package ipv6sock
