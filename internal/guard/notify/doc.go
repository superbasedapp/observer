// Package notify is the guard layer's alert dispatcher (guard spec
// §3.1): one owner for everything that leaves the process to get a
// human's attention. G5 ships the desktop channel (operator decision
// Q3: pure-Go, exec-based, NO notification library and NO CGO —
// PowerShell toast on Windows, osascript on macOS, notify-send on
// Linux, each degrading to a silent no-op when the helper binary is
// absent). The cloud-tier webhook dispatcher (§15.4) joins here in
// G15 so guard network I/O keeps a single owner.
package notify
