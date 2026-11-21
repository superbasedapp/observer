// Package shardnet is the SuperBased package lookup's one egress lane (lane
// id security.scan.osv.shards in tests/invariant/egress_lanes_test.go;
// ledger SHR-3 and SECP-49; OS and CI vulnerability scanning plan sections
// 13.5 and 13.11, lane RM-2): HTTPS only, to exactly one host,
// shards.superbased.app (osvdb.RemoteShardHost), no redirects, every body
// capped at the size the verified index or descriptor lists for it.
//
// It GETs the advisory shards and their index files of the remote-matching
// shard sets, <Set>/index/<sha256>.json and <Set>/obj/<sha256>.json.gz. A
// path names a set (an ecosystem or distribution release, the same for
// everyone) and an object's digest; which digests a node asks for follows
// from the hash prefixes of its package names, so this lane sends
// project-derived data (unlike security.scan.osv.db), and never a name, a
// version, a path or code. The signed shard manifest and set descriptors
// are not fetched here: they come through the security.scan.osv.db lane's
// content feed client like every other content kind.
//
// The gate in front of it is the caller's (cmd/observer
// security_osv_remote.go): an individual node, the lookup mode remote or
// both ([security.deps] match), the developer's signed remote-lookup
// consent (osv-remote-consent.json, never an agent: R-165), a dependency
// scanner selected. It is linked only into the cmd layer, never into the
// watcher, proxy, store, hook or dashboard
// (tests/invariant/security_osvshards_egress_test.go).
package shardnet
