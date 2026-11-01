// Package protectedhome names the folders directly under a user's home that
// the operating system guards behind a privacy prompt, so a background home
// walk can step around them instead of blocking on a prompt nobody sees.
//
// On macOS, a LaunchAgent that opens ~/Desktop, ~/Documents or ~/Downloads
// (and the other TCC-protected folders) blocks until the user answers a
// privacy dialog. A daemon started by launchd has no visible window to
// answer from, so the open never returns (D-MU1). The decision is a table
// keyed by OS name, not a branch per platform, and the package is pure: it
// never touches the filesystem.
package protectedhome
