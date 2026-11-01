// Package online is the install gate's public online client, the
// `security.online` egress lane (security pillar plan section 8.3, SECP-7;
// tests/invariant/egress_lanes_test.go): the OSV API, the public package
// registries of the ecosystem table, and the vendor's signed content feed.
//
// What it sends, exactly: to api.osv.dev the ecosystem, the package name
// and the pinned version of public-routable packages; to a registry the
// package name in the registry's own URL form; to the feed host a plain GET
// of a public file. Never a path, a repository, an org or user identifier,
// a credential or a private package name: the caller classifies every name
// first (internal/secfeed's classifier) and hands this client public names
// only, and the client refuses a name the classifier would not pass. The
// User-Agent is `superbased-observer`, with no version and no node id; no
// cookie, token or cache identifier is ever sent.
//
// Integrity: HTTPS only, to an exact host allow-list (no redirects, no
// plain-HTTP fallback), system roots, a size cap per response, strict
// decoding of the few fields read, and an answer is matched to the package
// asked about or dropped. A timeout, a 429 (with a per-host back-off), a
// DNS or TLS failure or a bad answer is OnlineFailed, which the gate turns
// into online_unknown (S-748); the offline verdict always stands.
//
// It is linked only into the daemon's security service: an import-graph
// pin keeps the watcher, the proxy, the store and the hook from reaching
// it, and on a managed node the service is never handed this client (the
// org relay in internal/orgclient answers instead).
package online
