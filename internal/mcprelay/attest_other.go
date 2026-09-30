//go:build !linux

package mcprelay

import "os"

// unsupportedAttestor is the honest platform result where no verified
// parent identity is implemented yet: every wrapper run is `configured`.
type unsupportedAttestor struct{}

func defaultAttestor() Attestor { return unsupportedAttestor{} }

// Attest implements Attestor.
func (unsupportedAttestor) Attest(ClientRegistry) ParentIdentity {
	return configured(os.Getppid(), "parent attestation is not implemented on this platform")
}
