// Package osvnet is the dependency scanners' one egress lane (lane id
// security.scan.osv.db in tests/invariant/egress_lanes_test.go; ledger
// SHR-3 and SECP-8): HTTPS only, to an exact host allow-list, no
// redirects.
//
//   - superbased.app: SuperBased's signed mirror of the OSV exports, the
//     first source of an individual node's order (static feed mirroring
//     plan section 7, cmd/observer security_osv_source.go): the
//     security.osv_export kind's manifest (with If-None-Match, at most 2
//     MiB) and its artifacts (a base and a cumulative delta per ecosystem,
//     each streamed to exactly the size the signed manifest lists), under
//     /api/security/v1/content/. The request names only the kind and the
//     file; the caller verifies every byte through the signed content
//     channel (internal/contentchan) before using it.
//   - osv-vulnerabilities.storage.googleapis.com, the fallback source (or
//     the only one with [security.deps] db_source = "upstream"): the
//     per-ecosystem OSV exports (<Ecosystem>/all.zip), metadata first and
//     the body only when its CRC32C changed (internal/secscan/osvdb owns the files); and, for
//     incremental updates, the ecosystem's change listing
//     (<Ecosystem>/modified_id.csv, read with 64 KiB Range requests from
//     the start until a line older than the local watermark) and the
//     changed records (<Ecosystem>/<ID>.json, at most 4 MiB each). Nothing
//     about the project is sent: a request names only the ecosystem and,
//     for a record, its public OSV id (validated: letters, digits,
//     '-', '_', '.' and ':' only).
//   - api.osv.dev: online matching (SCALIBR's osvdev enricher gets this
//     package's client, never one of its own), which sends ecosystem,
//     public package name and version, as the security.deps first-run
//     disclosure says; and the git submodule check (QueryCommit, spike
//     CPP-0, ledger SECP-53), which sends only a pinned commit id per
//     query (and, for a further page, OSV's own page token), never a
//     submodule's url, path or name.
//
// The gate in front of it is the caller's (cmd/observer/security_scan.go):
// a selected scanner component on an individual node (a managed node is
// never handed this client; its databases come from the org mirror,
// section 8.3); for the databases, the developer's one-time accept and the
// source order; for online matching and the submodule check,
// `[security.deps] online` on and the disclosure recorded. It is
// linked only into the daemon's scan loop and the `observer security scan`
// command, never into the watcher, proxy, store or hook
// (tests/invariant/security_scan_egress_test.go).
package osvnet
