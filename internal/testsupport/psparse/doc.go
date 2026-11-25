// Package psparse is a test helper: a strict reader of the one command
// shape Observer writes for a host that runs a hook command string through
// `powershell.exe -NoProfile -Command "<command>"` (Codex on Windows,
// FU-162). It accepts a command PowerShell parses as ONE native command
// invocation and returns that invocation's argv; it refuses anything
// PowerShell would read differently from the literal text.
//
// Accepted: an optional leading call operator `&`; then words separated by
// spaces, each one bare (no character PowerShell treats specially), a
// single-quoted literal (” is a quote inside it), or a double-quoted string
// with no `$`, backtick or double quote inside. A command that starts with a
// quoted word and no call operator is refused: PowerShell reads it as a
// string expression, not a program to run.
package psparse
