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
//   - the per-ecosystem canary table, the self-test that turns "the
//     matcher ran" into "the database loaded and flags a known advisory";
//   - the per-ecosystem outcome table and the run's coverage table: one
//     missing database makes only that ecosystem "not scanned", and a run
//     is "clean" only when every ecosystem it found was scanned and passed
//     its self-test (principle PR12, revision 2.4 [JSP-12]);
//   - grouping of advisories by aliases (GHSA, CVE, GO, PYSEC ids for the
//     same flaw become one finding); it never compares versions: matching
//     is SCALIBR's or osv-scanner's own (section 8.2);
//   - the semantic adapter from grouped advisories to secfinding.Finding,
//     on the "osv" adapter row of internal/secscan;
//   - the two drivers' registry rows (secscan.DriverRow), including the
//     Windows "beta" label of D-764 Q25.
//
// The package is PURE: no database, HTTP, exec or file I/O (imports_test.go
// pins it). It belongs to security.deps, the owner of OSV matching (section
// 4.2), and is compiled out with sbo_omit_security_deps.
package depscan
