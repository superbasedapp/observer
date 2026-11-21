// Package osvshard is the node's walk over the remote-matching advisory
// shards (OS and CI vulnerability scanning plan section 13, mode M1, with
// the binding spike results of section 13.11; lane RM-2). Given a verified
// shard set descriptor and the package names a scan holds, it:
//
//   - computes each name's prefix (osvshardkey, the ONE key owner: the
//     node passes every spelling of a package, the raw extractor name and
//     its reproduction of ParsePackage, and fetches the union, 13.11 item
//     1), and only prefixes ever leave the node: no package name, version
//     or path is part of any request;
//   - fetches the index file of each distinct first key byte and then the
//     distinct shards it does not hold, at most InFlight at a time, through
//     the injected Fetcher (the network lane is
//     internal/secscan/osvshard/shardnet; this package opens no
//     connection);
//   - verifies every object strictly through the digest chain: the
//     descriptor (whose digest the signed manifest pins) pins each index
//     file's sha256 and size, and each index file pins each shard's;
//   - keeps verified objects in a node-local cache (Cache, by digest, so an
//     unchanged shard is never fetched again, capped and evicted least
//     recently used); a cached object is re-verified on every read;
//   - keeps the records whose affected names match one of the names asked
//     for (osvshardkey.Canon: it only ever merges names, so every name
//     osvlocal could match is kept) and merges the copies of one id that
//     several shards carry by the union of affected (strip mode, 13.11
//     item 3);
//   - writes them as an OSV export, <dir>/osv-scalibr/<Ecosystem>/all.zip,
//     one file per ecosystem even when no record matched (13.11 item 6),
//     which SCALIBR's own osvlocal reads unchanged.
//
// A shard or index file that fails to fetch or verify is not an error of
// the walk: every name under it is reported in Answer.Failed, so the caller
// turns those packages into gaps (the run is partial, never clean).
//
// The package touches only its cache directory and the run directory it is
// handed; it never imports a network package, the store or a sibling
// subsystem beyond the key and the OSV record rules
// (tests: imports_test.go).
package osvshard
