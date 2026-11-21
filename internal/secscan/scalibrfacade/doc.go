// Package scalibrfacade is the only importer of OSV-SCALIBR
// (github.com/google/osv-scalibr, pinned at v0.5.3; security pillar plan
// docs/plans/security-pillar-plan-2026-10-19.md section 8.4, spike JSP-9b
// "Answer: ADJUST"). Nothing else in the module may import SCALIBR; a test
// in tests/invariant holds that.
//
// What it links, and what it never links:
//
//   - one lockfile or manifest extractor package at a time, from a closed
//     table (extractorTable), and the walker extractor/filesystem;
//   - in the same table, four build-artifact extractors (artifacts.go, OS
//     and CI vulnerability scanning plan section 14.6): language/golang/
//     gobinary, language/java/archive, language/python/wheelegg and
//     language/rust/cargoauditable (which brings go-rustaudit); an
//     executable is read only under an artifact directory and when its
//     header says it is one, and every artifact file is size-capped;
//   - with security.scan.os (osimage.go, compiled out with
//     sbo_omit_security_scan_os), the three OS package extractors
//     extractor/filesystem/os/{dpkg,apk,rpm} and osrelease, run over an
//     image root internal/secimage extracted (never artifact/image, which
//     reads container images itself);
//   - the two OSV matchers enricher/vulnmatch/osvlocal (the local database)
//     and enricher/vulnmatch/osvdev (the online API);
//   - never the top-level scalibr package (it imports artifact/image for
//     container scans) and never extractor/filesystem/list (it imports every
//     container, OS-package, disk-image and secret extractor).
//
// The walker itself still brings the disk-image readers (go-diskfs,
// go-ext4-filesystem, go-exfat, go-ntfs) through
// extractor/filesystem/embeddedfs/common, and go-git for .gitignore
// handling; a facade cannot drop them by choosing extractors (JSP-9b,
// disclosed in docs/dependency-scanning.md).
//
// Rules the spike made binding:
//
//   - filesystem.Config.Stats is always set (a nil collector panics on the
//     first file; only scalibr.Scan sets a default);
//   - SCALIBR's logger is replaced (it logs to stderr by default);
//   - osvlocal always runs with Download false: Observer owns the database
//     download (internal/secscan/osvdb), so SCALIBR never opens a network
//     connection for the local path;
//   - matching runs one ecosystem at a time (Match), because osvlocal fails
//     the whole call on the first missing database;
//   - npm lockfile entries under node_modules with no "resolved" field and
//     no link or file: marker are passed on as registry packages (an
//     extraction rule, not version logic; see npmlock.go), closing the
//     LOCAL false negative;
//   - Observer writes no version-ordering code: osvlocal decides "affected"
//     with SCALIBR's own semantic package, osvdev asks the OSV API. The one
//     deviation is an ecosystem SCALIBR's semantic package has no case for
//     (GitHub Actions: osvlocal would PANIC in semantic.MustParse), which
//     never reaches osvlocal: actionsmatch.go walks the OSV range events
//     itself and compares every version with SCALIBR's semver comparator;
//   - the actions a workflow uses are listed by internal/secciwf.ActionRefs
//     (actions.go, rule S-779), never by SCALIBR's githubactions extractor;
//   - what this build reads is answered from extractorTable itself
//     (coverage.go: Reads asks each lockfile and manifest extractor's own
//     FileRequired), and UnreadFiles turns every known dependency file it
//     does not read (depscan's dependency-file table) into a gap, so a
//     run that skipped a whole ecosystem's files is never clean.
//   - three more extraction rules, none of them version logic (lane 2 of
//     the 2026-11-06 coverage review): a .NET PackageReference with no
//     version takes it from the nearest Directory.Packages.props, and
//     project.assets.json yields only the packages NuGet restored
//     (dotnet.go); a declared NuGet or version catalog range, floating
//     version or MSBuild property is marked unpinned (versionshape.go);
//   - a version osvlocal's comparator rejects (semantic.MustParse panics on
//     a CRAN or Hackage version it cannot parse) fails that ecosystem's
//     match, recovered in enrichSafely, and never the scan child.
//
// No SCALIBR type crosses the facade: callers see Package, Status and Vuln
// only. The package is compiled out with sbo_omit_security_scan_scalibr;
// stub.go is the omitted build's API (Compiled false, every call answers
// ErrNotCompiled), and it imports nothing from SCALIBR.
//
// The facade runs inside the scan child process (`observer security
// scan-child`, started through internal/extrun), never in the daemon: the
// match peaks at about 600 MB and the runner's memory cap holds it.
package scalibrfacade
