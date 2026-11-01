// Package sectestpath holds the one closed test-path class table the
// security code reads: the Opengrep rule pack's per-rule test exclusion
// (internal/secrulepack re-exports it) and the diff observations' test-file
// check (internal/secdiffobs.IsTestPath). It is pure: string matching only,
// no file, process, database or network access.
package sectestpath
