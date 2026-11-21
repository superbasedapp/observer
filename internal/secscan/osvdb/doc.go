// Package osvdb is Observer's local OSV database store (security pillar
// plan sections 8.2 and 8.5, spike JSP-9b "Answer: ADJUST"): Observer, not
// SCALIBR or osv-scanner, downloads the per-ecosystem OSV exports, so the
// engines never open a network connection and the database epoch is
// Observer's record.
//
// Layout under the store directory (default ~/.observer/security/osv):
//
//	osv-scalibr/<Ecosystem>/all.zip   what osvlocal reads (LocalPath = Dir)
//	osv-scanner/<Ecosystem>/all.zip   a hard link (or copy) for osv-scanner,
//	                                  which reads its own subdirectory
//	epochs.json                       one record per ecosystem
//
// An ecosystem's epoch is the export's object last-modified time plus its
// CRC32C (the bucket's x-goog-hash), recorded at download. A refresh asks
// for the object's metadata first and downloads only when the CRC32C
// differs; the body is streamed to a temporary file (never held in memory:
// the in-library download peaked at 1.1 GB), its CRC32C checked against
// the header, its zip directory opened, and only then renamed into place.
// A failed refresh keeps the last verified file (last-known-good) and
// records the failure. The network lives behind the injected Remote
// (production: internal/secscan/osvnet, the declared egress lane).
//
// Incremental updates (static feed mirroring plan section 4, Layer A):
// when the Remote is also a DeltaRemote, a full export installs with a
// watermark (the earlier of its Last-Modified and the newest line of the
// ecosystem's modified_id.csv, less WatermarkMargin), and later refreshes
// list only the records changed since it, fetch each record, and
// MergeExport them into a new export (unchanged entries copied raw, a
// record the source no longer holds dropped) that passes the same zip
// check and the same two renames. The full export is not even asked about
// then: its CRC32C changes upstream all day. The ordered rebaseRules table
// sends a refresh back to the full export (no watermark, a base or
// watermark older than seven days, MaxDeltaFailures consecutive failures),
// as does a change set larger than MaxDeltaRecords or a tenth of the
// export. The epoch keeps the base's Last-Modified and CRC32C and gains
// " delta=<watermark>" once records were applied, so a finding still names
// the exact data. A Remote that is a LocalRemote (the org mirror's
// installed artifacts) has its file hard-linked in rather than streamed,
// under the same checks.
//
// RecordReader reads single records out of the installed exports for a
// view (the dashboard's dependency-finding drawer): only the ecosystems
// Installed names, only valid record ids, at most MaxViewRecordBytes per
// record, never a network read. It caches one zip directory per
// ecosystem, re-read when the file changes, and never holds the file open
// between reads, so a refresh's rename is never blocked (Windows).
//
// MergeExport is pure (zip in, zip out through its arguments); the
// listing and the records arrive only through the injected DeltaRemote.
//
// It belongs to security.deps (OSV matching, section 4.2) and is compiled
// out with sbo_omit_security_deps.
package osvdb
