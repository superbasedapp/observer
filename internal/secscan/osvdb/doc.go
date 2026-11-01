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
// It belongs to security.deps (OSV matching, section 4.2) and is compiled
// out with sbo_omit_security_deps.
package osvdb
