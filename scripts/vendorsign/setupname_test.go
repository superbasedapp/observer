package main

import (
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/update"
)

// TestSetupProgramAndSumsSignatureAreNeverArtifacts pins T-920's naming
// contract: the Windows setup program, its .sig and SHA256SUMS.sig sit in the
// release directory beside the agent archives, and `vendorsign manifest` /
// `vendorsign index` walk that directory. Both skip a name only when it is
// UNRECOGNISED (an archive-type mismatch fails the release instead), so each
// of these must parse as unrecognised, never as an agent archive and never
// as a mis-typed one.
func TestSetupProgramAndSumsSignatureAreNeverArtifacts(t *testing.T) {
	for _, name := range []string{
		"superbased-observer-setup-v1.37.0-win32-x64.exe",
		"superbased-observer-setup-v1.37.0-rc.1-win32-x64.exe",
		"superbased-observer-setup-v1.37.0-win32-x64.exe.sig",
		"SHA256SUMS.sig",
	} {
		_, err := update.ParseDistroArtifactName(name)
		if err == nil {
			t.Errorf("%s parses as an agent archive; it would enter the update manifest or release index", name)
			continue
		}
		if errors.Is(err, update.ErrArchiveTypeMismatch) {
			t.Errorf("%s parses as a mis-typed archive, which fails the release: %v", name, err)
		}
		if !errors.Is(err, update.ErrUnrecognizedArtifact) {
			t.Errorf("%s: want ErrUnrecognizedArtifact, got %v", name, err)
		}
		if _, _, _, _, err := update.ParseArtifactName(name); err == nil {
			t.Errorf("%s parses as a v1 manifest artifact", name)
		}
	}
}
