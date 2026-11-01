// Package termfilter removes, from a terminal output stream, the escape
// sequences a sandboxed tool must not send to the user's terminal (WINFIX4
// audit finding 2, ruling P-175): OSC 52, the clipboard set and query
// sequence. A sandbox that refuses the box the clipboard (the Windows box's
// job carries READCLIPBOARD and WRITECLIPBOARD) must not let the same write
// through the terminal, where Windows Terminal, xterm.js and most terminals
// honour it.
//
// It is pure: a byte-stream state machine with no I/O, fed one read at a
// time, so a sequence split across reads is still removed. The two seams
// that use it are the dashboard terminal's PTY pump
// (internal/termsession, for a sandboxed run) and the CLI host console's
// copy loop (cmd/observer sandbox_cli_console_windows.go).
package termfilter
