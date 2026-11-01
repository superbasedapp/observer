// Package setup holds the decisions behind `observer setup`: the per-user
// install the Windows setup program (installer/windows/superbased-setup.nsi)
// drives, the user Path edit, start at sign-in, the check for another
// install on the same computer, and what the double-click launch prints.
//
// It is a pure-logic package per the CLAUDE.md module rules: string and
// list decisions only, no exec, no file I/O, no registry access, no
// database/sql, net/http or fsnotify (pinned by imports_test.go). The cmd
// layer (cmd/observer/setup*.go) reads the Path, the registry, the process
// lock and the filesystem, hands the facts in, and applies the result.
//
// The setup program stays a thin shell that copies files and calls these
// commands, so the install logic has one owner instead of a third copy
// beside scripts/install.sh and scripts/install.ps1.
package setup
