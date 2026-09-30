// Package mcpegress is the SSRF-safe egress client every outbound call the
// Agent Access control plane makes on behalf of an admin-supplied URL goes
// through (Agent Access implementation plan section 5, rulings R8.23.b and
// R9.11; audit item AA-6): upstream MCP discovery (tools/list), the registry
// import, and - in later waves - CIMD / JWKS / OAuth token fetches.
//
// Two layers with sharply different jobs:
//
//   - ValidateUpstreamBaseURL is the PRE-FLIGHT check run when a server row
//     is upserted (internal/mcpgw/regstore calls it from Validate). It gives
//     the admin an inline error and stops an obviously-doomed or
//     unconditionally-forbidden URL from ever reaching the table. It is NOT
//     the security boundary: a hostname it accepts can resolve anywhere, at
//     any time.
//
//   - the DialPolicy the same Options resolve to (internal/netpolicy) IS the
//     boundary. NewClient installs it as the net.Dialer.Control hook, so it
//     runs per connection attempt on the address the RESOLVER produced: a
//     DNS answer that flips between preflight and dial (rebinding) is caught
//     at the dial, and a name with several A records is checked per address.
//
// Default posture is deny: loopback, RFC 1918 / CGNAT / ULA, link-local and
// cloud metadata (169.254.169.254), multicast and the unspecified address
// are all refused. The org may unlock loopback + private ranges PER SERVER
// through the typed Options.AllowPrivateNetwork flag (the plan's
// "allowlisted per server"); link-local / metadata / multicast are never
// unlockable. Redirects are never followed (a 3xx is returned verbatim -
// Go would otherwise re-send an injected upstream credential to whatever
// host the upstream named, ENT-2). Connection pools are partitioned BY
// POLICY (one *http.Client per distinct DialPolicy) so a connection opened
// for a permissive server can never be reused by a strict one.
//
// Proxies (Sol fold 5 finding 1). A proxied request dials the PROXY, so the
// dial hook would check only the proxy's address and the proxy would decide
// where the request lands - a silent removal of the boundary. A guarded
// client therefore NEVER takes a proxy from the process environment: an
// ambient HTTPS_PROXY / HTTP_PROXY (and a Base transport's Proxy) is
// ignored, and the default is a direct, dial-checked connection. A proxy is
// only ever explicit:
//
//   - ClientConfig.WithExplicitProxy(u) is the org side's trusted egress
//     point ([agent_access].egress_proxy_url). Every request goes through
//     u and the destination decision MOVES TO THAT PROXY: this package then
//     checks only the dial to u itself (loopback / private admitted, link-
//     local / metadata / multicast still refused). The recommended explicit
//     proxy is observer-mcpgw's own egress CONNECT proxy (the `egress` role,
//     ConnectProxy below), which enforces the same netpolicy per resolved
//     address; a third-party proxy is trusted to enforce its own.
//   - ClientConfig.Proxy is a caller-chosen selector (the node relay passes
//     http.ProxyFromEnvironment on the developer's own machine). The dial
//     to the selected proxy is checked against the client's DialPolicy like
//     any direct dial (an RFC 1918 proxy is refused under the default
//     policy - fail closed), and the proxy decides where the request lands.
//
// Discovery (ListTools) speaks MCP streamable HTTP (2025-03-26+): initialize,
// notifications/initialized, then tools/list paginated to a bounded number
// of pages, with the session id carried and the session deleted at the end.
// Legacy SSE and OpenAPI upstreams are reported as ErrDiscoveryUnsupported in
// this wave (the poller records the error and never flips drift on it).
//
// The package imports net/http by nature (it IS the egress client) but never
// database/sql, fsnotify, or any internal/mcpgw / internal/orgserver package
// (imports_test.go pins it): stores and handlers depend on it, never the
// reverse.
package mcpegress
