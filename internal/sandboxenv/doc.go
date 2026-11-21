// Package sandboxenv is the one table of environment variables a sandbox
// box may receive from the environment that launched it (WINFIX2 audit
// finding 1, ledger SBX-WIN-ENV-1).
//
// Before, every local backend built the box's environment from its parent's
// minus a short deny-list, so a GITHUB_TOKEN, an AWS_* key or the launching
// agent session's own CLAUDE_* variables reached a box that could talk to the
// internet. Every backend now builds it from an ALLOW-LIST instead:
//
//   - the operating system's own table (Base): PATH, HOME, TERM, the locale
//     and the time zone everywhere; TMPDIR, USER, LOGNAME and SHELL on POSIX;
//     the Windows system locations and the profile folders on Windows;
//   - the tool's own provider variables, the ProviderEnv list on its
//     integration row (a capability of the row, never a tool-name branch);
//   - the names the user lists in [terminal.sandbox].pass_env (local-only);
//   - the variables Observer itself sets for the run (its markers, the
//     trusted launcher channel), which the caller names.
//
// The provider and user names reach a box helper through one variable that
// carries NAMES only (EnvAllow), set by the daemon or the CLI launcher at the
// launch, never inherited. Observer still sets its own base-URL and
// config-home variables after the filter.
//
// The package is pure: no SQL, HTTP, exec or file access (imports_test.go).
package sandboxenv
