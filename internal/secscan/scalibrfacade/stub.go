//go:build sbo_omit_security_scan_scalibr

package scalibrfacade

import (
	"context"
	"io"
)

// stub.go is the omitted build's API: SCALIBR is not linked, nothing here
// imports it, and every call answers ErrNotCompiled, so the driver reports
// the project's dependencies as "not scanned", never clean.

// Compiled reports whether SCALIBR is linked into this binary.
const Compiled = false

// ExtractOptions tunes one extraction pass (unused in this build).
type ExtractOptions struct {
	SkipDirs    []string
	MaxInodes   int
	MaxFileSize int
	Log         io.Writer
}

// Extractors answers ErrNotCompiled.
func Extractors() ([]ExtractorInfo, error) { return nil, ErrNotCompiled }

// Extract answers ErrNotCompiled.
func Extract(context.Context, string, ExtractOptions) (*Inventory, error) {
	return nil, ErrNotCompiled
}

// Match answers ErrNotCompiled.
func Match(context.Context, *Inventory, MatchRequest, MatchOptions) (MatchResult, error) {
	return MatchResult{}, ErrNotCompiled
}

// NewInventory keeps the rows; Match refuses them in this build, where
// there are no SCALIBR packages to hold (impl stays nil).
func NewInventory(pkgs []Package) *Inventory {
	return &Inventory{Packages: append([]Package(nil), pkgs...), impl: nil}
}

// RegistryEntries answers nothing in this build.
func RegistryEntries([]byte) map[string]bool { return nil }
