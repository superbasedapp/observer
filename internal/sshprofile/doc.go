// Package sshprofile is the pure-logic layer behind SSH remote-system
// terminals (docs/plans/ssh-remote-profiles-plan-2026-08-27.md).
//
// A Profile is one operator-authored remote system, read from the
// [[terminal.ssh.profiles]] blocks of ~/.observer/config.toml. It is NEVER
// client-supplied: the dashboard sends a profile NAME and the daemon resolves
// every connection parameter from its own config. That single property is what
// keeps a UI click from being able to nominate an arbitrary SSH destination.
//
// The package does two things and nothing else:
//
//   - Validate — closed-vocabulary validation of every field (Validate for the
//     pure syntax rules, ValidateWithFS when the key path should also be
//     stat-checked).
//   - Argv — compose the OpenSSH client argv for a validated profile.
//
// CREDENTIAL DISCIPLINE (operator requirement, plan §0 answer 2): a profile
// carries a key-file PATH and nothing more. This package never opens, reads,
// parses, copies, or transmits key material, and there is deliberately no
// password/passphrase field anywhere in the model — ssh-agent (or an
// interactive prompt in the PTY) owns that entirely.
//
// FLAG-INJECTION DISCIPLINE (plan §9.1): the OpenSSH client has NO "--"
// end-of-options separator, so a hostname beginning with '-' is parsed as a
// flag and there is no way to escape it. Rejecting a leading '-' on every
// field that reaches the argv is therefore not defence-in-depth, it is the
// only defence. The caller additionally must exec the returned []string
// directly (exec.Command with an argv slice) and never hand it to a shell.
//
// Module shape (CLAUDE.md "Module Boundaries" #1): pure. No database/sql, no
// net/http, no os/exec, no fsnotify, and no observer-internal imports — pinned
// by imports_test.go. The one filesystem touch is os.Stat behind
// ValidateWithFS, mirroring the allowance internal/sandbox makes for its
// readiness probe.
package sshprofile
