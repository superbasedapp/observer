//go:build sbo_omit_security_scan_scalibr || sbo_omit_security_scan_os

package scalibrfacade

import "context"

// osimage_stub.go is the OS package API of a build without
// security.scan.os (or without SCALIBR): nothing here imports SCALIBR, and
// every call answers ErrNotCompiled, so an image reads "not scanned:
// not_compiled", never clean.

// OSCompiled reports whether the OS package extractors are linked.
const OSCompiled = false

// ExtractOS answers ErrNotCompiled.
func ExtractOS(context.Context, string, OSExtractOptions) (*Inventory, error) {
	return nil, ErrNotCompiled
}

// MatchOS answers ErrNotCompiled.
func MatchOS(context.Context, *Inventory, OSMatchRequest, MatchOptions) (MatchResult, error) {
	return MatchResult{}, ErrNotCompiled
}

// OSRelease answers nothing in this build.
func OSRelease(*Inventory) map[string]string { return nil }
