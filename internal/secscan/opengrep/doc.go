// Package opengrep is the Opengrep process driver (security.scan.opengrep,
// security pillar plan sections 4.4, 4.5.3 and 5.5, Phase G lane G1; spike
// JSP-8). It runs a separately installed Opengrep (LGPL-2.1, a separate
// process, never bundled or linked) with Observer's own rule pack
// (internal/secrulepack) and maps its SARIF onto findings.
//
// Every run goes through the shared runner (internal/extrun) with the
// measured Opengrep profile (extrun.OpengrepEngine: LC_ALL=C.UTF-8, its own
// HOME and XDG_CACHE_HOME inside an Observer-owned cache directory, the git
// hardening), a PATH holding only git, and the caps JSP-8 sized (memory
// 2 GiB, wall 600 s for a full scan and 60 s for a diff scope, output
// 32 MiB, children 64 scaling with -j). Before anything starts it:
//
//  1. resolves the binary through the runner's resolver (toolresolve with
//     the command-wrapping shim exclusion; a PATH shim is never resolved);
//  2. decides with internal/secengine whether the binary's digest is
//     pinned (the compiled pin or a verified engine manifest), refusing an
//     unverified engine on a managed node and labelling it on an individual
//     one, and refusing a platform whose pin is owed;
//  3. checks the companion tree Opengrep unpacked into its own cache
//     against the record of the first verified run (X9) and hands the
//     recorded digests to the runner, which refuses on a mismatch;
//  4. asks the version (1.30.1 is the tested version; another runs
//     labelled "untested engine version"; older is refused).
//
// The flags are fixed (FlagsAlways): --disable-version-check, --sarif, the
// pack's rules directory as the only --config, --no-rewrite-rule-ids,
// --disable-nosem and --x-ignore-semgrepignore-files (a repository's
// inline suppressions and .semgrepignore are untrusted input), and either
// --no-git-ignore with Observer's own targets (a full scan) or
// --baseline-commit with the git hardening (a diff scope). Never --config
// auto. A JSON copy of the output (--json-output, a local file in the run's
// output directory) supplies the files the run scanned and the files it
// could not parse; the SARIF supplies the results. One flag is the pack's to
// ask for: --taint-intrafile (intra-file inter-procedural taint analysis) is
// passed only when the running pack's manifest sets taint_intrafile
// (secrulepack.Pack.EngineFlags, PackFlags, ArgsForPack), in every mode the
// self-test included, so a pack measured without it never runs with it.
//
// Exit codes (JSP-8): 0 is a result, read from the SARIF, never from the
// code; 2 a crash; 7 a missing or invalid rule file. The canary rule of the
// pack must report the canary file: a full scan carries the canary as a
// second target, a diff scope relies on the self-test recorded for the same
// binary, tree and pack digests. Exit 0 with no canary hit is unknown,
// never clean; a refused or crashed run is failed and never closes a
// finding.
//
// The package holds no I/O of its own beyond what Env injects. It belongs
// to security.scan.opengrep and is compiled out with
// sbo_omit_security_scan_opengrep (its only importer is that driver's
// cmd file).
package opengrep
