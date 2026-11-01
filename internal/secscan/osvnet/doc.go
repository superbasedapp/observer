// Package osvnet is the dependency scanners' one egress lane (lane id
// security.scan.osv.db in tests/invariant/egress_lanes_test.go; ledger
// SHR-3 and SECP-8): HTTPS only, to an exact host allow-list, no
// redirects.
//
//   - osv-vulnerabilities.storage.googleapis.com: the per-ecosystem OSV
//     exports (<Ecosystem>/all.zip), metadata first and the body only when
//     its CRC32C changed (internal/secscan/osvdb owns the files). Nothing
//     about the project is sent: the request names only the ecosystem.
//   - api.osv.dev: online matching (SCALIBR's osvdev enricher gets this
//     package's client, never one of its own), which sends ecosystem,
//     public package name and version, as the security.deps first-run
//     disclosure says.
//
// The gate in front of it is the caller's (cmd/observer/security_scan.go):
// a selected scanner component, `[security.deps] online` on, the
// disclosure recorded, an individual node (a managed node is never handed
// this client; its databases come from the org mirror, section 8.3). It is
// linked only into the daemon's scan loop and the `observer security scan`
// command, never into the watcher, proxy, store or hook
// (tests/invariant/security_scan_egress_test.go).
package osvnet
