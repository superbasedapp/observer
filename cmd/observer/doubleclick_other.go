//go:build !windows

package main

// doubleClickDispatch is Windows-only (a double-click in Explorer); every
// other platform runs the CLI as usual.
func doubleClickDispatch(_ []string) (int, bool) { return 0, false }
