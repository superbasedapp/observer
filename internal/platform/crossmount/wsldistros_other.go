//go:build !windows

package crossmount

import "context"

// runWSLList is Windows-only: no other host runs wsl.exe to find distros
// (a WSL process reaches Windows over /mnt, wslWindowsHomes).
func runWSLList(context.Context, string) ([]byte, error) {
	return nil, errWSLListUnavailable
}

// wslExePath names no wsl.exe off Windows; runWSLList never runs it.
func wslExePath() string { return "" }
