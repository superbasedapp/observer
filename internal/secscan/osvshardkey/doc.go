// Package osvshardkey is the ONE owner of the remote-matching shard key and
// wire format (OS and CI vulnerability scanning plan,
// docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md section 13,
// with the binding spike results of section 13.11; spike write-up
// docs/plans/spikes/RM-0-remote-shards-2026-11.md). The publisher
// (scripts/vendorsign osvshards, lane RM-1) and the node's lookup lane
// (internal/secscan/osvshard, lane RM-2) both import it, so the two can
// never hash a name differently or read a file the other did not write.
//
// # The key
//
//	key    = sha256(base || 0x00 || Canon(base, name))
//	prefix = the first bits bits of key, big-endian
//
// base is the OSV ecosystem with its ":suffix" dropped (Base: "Debian:12"
// is "Debian", "Ubuntu:24.04:LTS" is "Ubuntu"), spelled exactly as OSV
// spells it ("PyPI", "GitHub Actions", "Red Hat"). A shard SET is per
// export, and for an operating system per release, so "Debian:11" and
// "Debian:12" are two sets keyed the same way. Canon lower-cases the name,
// after PEP 503 folding ([-_.]+ to "-") for PyPI. It only ever merges
// names, never splits them, so any two names osvlocal treats as equal (it
// compares bytes) share a key; NameRules says which name each ecosystem
// hashes (dpkg and apk source names, the rpm binary name, Maven
// group:artifact, GitHub Actions owner/repo).
//
// The node hashes both the raw extractor name and its reproduction of
// SCALIBR's osvutil.ParsePackage, and fetches the union (Prefixes takes any
// number of names), so a later SCALIBR fix of the mixed-case Go module bug
// (ledger row SECP-43) needs no node change.
//
// # The objects
//
// Per set, three object types, all but the manifest content-addressed (the
// name is the sha256 of the bytes) and so immutable:
//
//	<Set>.set.json               the set descriptor (SetDescriptor), an
//	                             entry of the signed security.osv_shards
//	                             content manifest, served by the site worker
//	<Set>/index/<sha256>.json    one index file per first key byte
//	                             (IndexFile), from the public shard bucket
//	<Set>/obj/<sha256>.json.gz   one shard: gzip of a JSON array of the OSV
//	                             records whose affected names hash into one
//	                             prefix, from the public shard bucket
//
// The content manifest pins each descriptor by digest, a descriptor pins
// each index file by digest and size, and an index file pins each shard by
// digest and size, so one signature covers every byte.
//
// Strip mode (the only mode): a shard carries each record with only the
// affected entries whose names hash into its prefix, every other field and
// the field order kept. A node holding two shards with copies of one id
// merges them by the union of affected before writing its all.zip.
//
// The package is pure: no file, database, network or process access, which
// imports_test.go pins.
package osvshardkey
