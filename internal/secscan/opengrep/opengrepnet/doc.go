// Package opengrepnet is the code rules' one egress lane (lane id
// security.scan.opengrep.net in tests/invariant/egress_lanes_test.go;
// ledger SHR-3 and SECP-29): HTTPS only, to an exact host allow-list, a
// redirect followed only from one allow-listed host to another, every body
// capped.
//
//   - github.com, and the two hosts its release downloads redirect to
//     (release-assets.githubusercontent.com and
//     objects.githubusercontent.com): the pinned Opengrep release asset of
//     the guided install. Nothing about the project is sent; the URL names
//     the version and the platform's asset.
//   - superbased.app: the vendor's signed content feed, for the two kinds
//     the code rules read (security.rule_pack and security.engine), plain
//     GETs of public files. Every byte is verified through the signed
//     content channel (internal/contentchan) before it is used.
//
// The gate in front of it is the caller's (cmd/observer/
// security_opengrep_install.go and security_opengrep_daemon.go): the
// component security.scan.opengrep selected, an individual node (a managed
// node is never handed this client: its engine and pack come from the org
// mirror, case X19), and for the release download the developer's one-time
// size consent for the pin in force. It is linked only into the cmd layer,
// never into the watcher, proxy, store, hook or the driver itself
// (tests/invariant/security_opengrep_egress_test.go).
package opengrepnet
