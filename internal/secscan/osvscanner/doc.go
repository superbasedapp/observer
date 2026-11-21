// Package osvscanner is the osv-scanner subprocess driver
// (security.scan.osv, security pillar plan sections 4.2 and 4.4, spike
// JSP-8): the configurable alternative to the linked SCALIBR driver and the
// developer distro's planned default (D-766).
//
// It is never bundled. It resolves a separately installed osv-scanner
// through the injected shared runner (internal/extrun, toolresolve with the
// command-wrapping shim exclusion); when none is installed it starts no
// process and reports the project's dependencies "not scanned"
// (not_installed), never clean, and the caller offers the guided vendor
// install (InstallOffer); nothing is installed by this package.
//
// When installed it runs with the flags of OSVScannerFlags: always
// `scan source -r --offline --no-call-analysis=all --format json
// --all-packages --verbosity error` and Observer's own empty --config (a
// repository's osv-scanner.toml is ignored, section 4.4 ConfigInputs);
// never a database download (Observer's store supplies it through
// OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY) and never call analysis (it runs
// the scanned repository's own toolchain). It gets no PATH, its own HOME
// and cache, LC_ALL=C.UTF-8, a 1 GiB memory cap and 600 s. Exit codes
// (JSP-8): 0 clean, 1 vulnerabilities found (a result), 128 no packages,
// 127 every error.
//
// osv-scanner fails the whole run when any ecosystem's database is missing
// (exit 127, measured with v2.6.0), so the driver runs only when every
// ecosystem's database is installed and otherwise reports
// database_missing without starting a process. A project file of an
// ecosystem osv-scanner reads but Observer offers no database for (a
// pubspec.lock while Pub has none) still makes it log "could not find local
// databases for ecosystems" and exit 127 when it found nothing; such a run
// is read anyway, its other ecosystems keep their results, and the missing
// ecosystem's files become gaps (no_database_offered), so the run is
// partial, never clean, and not failed for the whole project. The canary
// project (depscan.CanaryFiles) is scanned in the same run; a canary that
// does not come back flagged marks its ecosystem "not scanned".
//
// The package holds no I/O of its own beyond the injected runner. It
// belongs to security.scan.osv and is compiled out with
// sbo_omit_security_scan_osv.
package osvscanner
