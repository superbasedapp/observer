//go:build !linux

package intervention

import (
	"context"
	"fmt"
)

// BuildInstallManifest reports that installed process binding currently has
// no backend on this operating system.
func BuildInstallManifest(context.Context, []InstalledCandidate) (InstallManifest, error) {
	return InstallManifest{}, ErrBindingUnsupported
}

// ReadProcessEvidence reports that process evidence is unavailable.
func ReadProcessEvidence(context.Context, InstallManifest, int) (ProcessEvidence, error) {
	return ProcessEvidence{}, ErrBindingUnsupported
}

// AncestorPIDs reports that process ancestry is unavailable.
func AncestorPIDs(context.Context, int) ([]int, error) {
	return nil, ErrBindingUnsupported
}

// ScanInstalledProcesses reports that process scanning is unavailable.
func ScanInstalledProcesses(context.Context, InstallManifest, ScanOptions) (ScanResult, error) {
	return ScanResult{}, ErrBindingUnsupported
}

// RevalidateBinding reports that process binding is unavailable.
func RevalidateBinding(context.Context, InstallManifest, Identity, string, ScanOptions) (ProcessMatch, error) {
	return ProcessMatch{}, fmt.Errorf("intervention.RevalidateBinding: %w", ErrBindingUnsupported)
}
