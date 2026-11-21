// Package depscan is the pure core of the project dependency scanners
// (security pillar plan sections 4.4, 8.2 and 8.4, Phase D2): the two
// inventory drivers security.scan.scalibr (OSV-SCALIBR, linked, run in a
// child process) and security.scan.osv (the osv-scanner subprocess) both
// end here, so "scanned" and "clean" mean one thing for both.
//
// It holds, as data walked top-down (CLAUDE.md module rule 5):
//
//   - the child process protocol (ChildRequest, ChildResponse), versioned;
//   - the drop rules applied before matching (empty versions, locally
//     developed packages, the project's own root package, the Go stdlib
//     line);
//   - the per-ecosystem table: each ecosystem's canary, the self-test that
//     turns "the matcher ran" into "the database loaded and flags a known
//     advisory", and what reads it (OSVScanner: osv-scanner's required
//     databases and canary files are only the ecosystems it reads, never
//     GitHub Actions, which the SCALIBR driver matches from the workflows,
//     rule S-779; NativeRule names that rule for policy);
//   - the manifest table (a manifest with no lockfile is a gap) and the
//     dependency-file table with its unread-file rules (unread.go: a known
//     dependency file no linked extractor reads is a gap, so a project of
//     unread ecosystems never reads clean; the facade's coverage probe asks
//     its own extractor table what is read);
//   - the per-ecosystem outcome table and the run's coverage table: one
//     missing database makes only that ecosystem "not scanned", and a run
//     is "clean" only when every ecosystem it found was scanned and passed
//     its self-test (principle PR12, revision 2.4 [JSP-12]);
//   - grouping of advisories by aliases (GHSA, CVE, GO, PYSEC ids for the
//     same flaw become one finding); it never compares versions: matching
//     is SCALIBR's or osv-scanner's own (section 8.2), or, for GitHub
//     Actions, the facade's range walk over SCALIBR's comparator;
//   - the semantic adapter from grouped advisories to secfinding.Finding,
//     on the "osv" adapter row of internal/secscan;
//   - the two drivers' registry rows (secscan.DriverRow), including the
//     Windows "beta" label of D-764 Q25.
//
// The package is PURE: no database, HTTP, exec or file I/O (imports_test.go
// pins it). It belongs to security.deps, the owner of OSV matching (section
// 4.2), and is compiled out with sbo_omit_security_deps.
package depscan
