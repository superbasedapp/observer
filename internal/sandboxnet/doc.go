// Package sandboxnet holds the network pieces of the sandbox egress tier for
// B9 sandboxed terminals (docs/sandboxed-terminals.md, internal/sandbox).
//
// A sandboxed agent in the network tier runs in its own network namespace
// (bwrap --unshare-net). It cannot reach the host's loopback at all, so the
// two host-side services it is allowed to use are exposed to it ONLY through
// unix sockets bind-mounted into the sandbox:
//
//  1. The model-API proxy socket. Inside the namespace a process listens on
//     127.0.0.1:<proxy port> and pipes every TCP connection to the unix
//     socket; on the host a process accepts on that socket and dials the real
//     observer proxy on host TCP 127.0.0.1:<proxy port>. Both halves are
//     ServeForward with a different listener and dial func.
//  2. The egress gateway socket. On the host, Gateway (an HTTP forward proxy:
//     CONNECT plus absolute-form http) is served directly on a second unix
//     socket; inside the namespace 127.0.0.1:<gateway port> is piped to that
//     socket with ServeForward, and the agent's HTTP_PROXY / HTTPS_PROXY point
//     at it.
//
// The gateway lets the agent reach the internet, but it refuses every
// host-local and private destination (security ledger SR27-SBX-1): a
// sandboxed agent must not be able to reach the daemon's loopback control
// plane (the dashboard on 127.0.0.1:8081), the WSL2 NAT gateway (the Windows
// host), a Docker bridge container or any other host or LAN service. The
// policy is the pure, table-driven Policy.Check: loopback, unspecified, the
// IPv4 "this network" block, link-local (including the 169.254.169.254
// cloud metadata endpoint), multicast, limited broadcast and the host's own
// interface addresses are always refused; the RFC 1918 private ranges,
// 100.64.0.0/10 (carrier-grade NAT and tailnets) and IPv6 unique-local and
// site-local ranges are refused unless the operator allow-lists a CIDR under
// [terminal.sandbox].egress_allow_cidrs (ParseAllowCIDRs is the one owner of
// what may be listed). The gateway resolves a name once, filters the answers
// through the policy and dials the chosen address by IP, so a DNS-rebinding
// answer cannot change the destination between the check and the dial.
//
// This package is the ONLY network code of the sandbox egress tier. It does
// no process spawning, flag parsing or bwrap argv composition: spawning the
// in-sandbox and host-side forwarders lives in cmd/observer, and the bwrap
// planner lives in internal/sandbox. imports_test.go pins the package free of
// database/sql, os/exec, fsnotify and every observer-internal package.
package sandboxnet
