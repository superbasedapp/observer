// Package seccustom is the pure core of the user-configured scanner driver
// (security pillar plan docs/plans/security-pillar-plan-2026-10-19.md
// section 8.6, Phase D3; component security.scan.custom, driver kind
// custom).
//
// A user-configured program that runs on every scan is a code execution
// and persistence surface, so the driver is a narrow, structured protocol
// whose only output is findings. This package owns, as data and pure
// functions:
//
//   - the manifest format (Manifest) and its strict reader (Parse): one
//     versioned JSON object, refused on duplicate keys, unknown keys, a
//     byte order mark, trailing data, invalid UTF-8, deep nesting, and any
//     control, format (a right-to-left override, a zero-width space) or
//     escape character in a displayed field (JSP-12, 45 hostile manifests);
//   - the closed option sets every picker offers (limit steps with their
//     per-OS units, inputs, outputs, cache, network, severity sources, the
//     environment table, the exit-code meanings), so nothing is typed into
//     a free text field (D-571);
//   - the executable checks as a rule table over facts the caller reads
//     (no symlink anywhere on the path, not writable by group or others,
//     not under a shared sticky directory);
//   - the built-in templates (gosec, Bandit, Semgrep) with their flags,
//     exit codes, severity sources, self-test fixtures and the stderr
//     patterns that mark a run unknown (JSP-8, JSP-12);
//   - the run request for the hardened runner internal/extrun (BuildRun),
//     the classification of a finished run ("scanned" is not "clean",
//     JSP-12), the strict SARIF adapter options, the self-test check, and
//     the org catalog decision (the node half; the server half is Phase E).
//
// The package is PURE (CLAUDE.md "Module Boundaries" rule 1): no os,
// os/exec, net, database/sql or fsnotify; imports_test.go pins it. The I/O
// side (reading the file, hashing, discovery through internal/toolresolve,
// the record store, the run itself) is internal/seccustomsvc.
//
// Compiled out with sbo_omit_security_scan_custom (and with the module
// root's sbo_omit_security).
package seccustom
