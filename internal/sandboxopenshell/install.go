package sandboxopenshell

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// install.go binds an install's id to the real path of its state dir
// (ledger row OSH-42). The id names the install's private gateway (its
// unit, name, port and runtime dir, IdentityFor) and labels its boxes, so
// two installs that share one would share a gateway and reap each other's
// boxes. A second profile made by copying ~/.observer copies the id file
// with it; binding the file's name to the state dir's real path makes the
// copy mint its own id at its first use.
//
// The id lives in InstallIDFileFor(real path): "install-id-" and the first
// 16 hex digits of the path's sha256. LegacyInstallIDFile ("install-id",
// written by earlier builds and still written beside the bound file, so a
// downgrade reads the same id) is adopted once, by a state dir that holds
// no bound file at all, and only when the legacy id's gateway unit is not
// loaded or runs this state dir's own config (audit finding FU7-A3): that
// is an install from before the binding, at the path it ran from. A dir
// that holds a bound file for another path is a copy, and so is one whose
// legacy id's unit runs another dir's config: each mints a new id instead.
// Left: two copies made before the binding whose shared unit is not
// running when both first adopt (and every external-mode pair, which has
// no unit) still share the id; see ledger row OSH-42.

// LegacyInstallIDFile is the unbound id file earlier builds wrote.
const LegacyInstallIDFile = "install-id"

// installIDBoundPrefix starts every bound id file's name.
const installIDBoundPrefix = LegacyInstallIDFile + "-"

// InstallIDFileFor is the bound id file's name for a state dir's real
// (symlink-resolved, absolute, clean) path.
func InstallIDFileFor(realPath string) string {
	sum := sha256.Sum256([]byte(realPath))
	return installIDBoundPrefix + hex.EncodeToString(sum[:8])
}

// IsBoundInstallIDFile reports whether name is a bound id file's name
// (for any path).
func IsBoundInstallIDFile(name string) bool {
	rest, ok := strings.CutPrefix(name, installIDBoundPrefix)
	if !ok || len(rest) != 16 {
		return false
	}
	return strings.Trim(rest, "0123456789abcdef") == ""
}

// The install id sources (InstallIDSource), walked in this order.
const (
	// InstallIDBound: the bound file of this path holds the id.
	InstallIDBound = "bound"
	// InstallIDAdoptLegacy: no bound file at all, a valid legacy file:
	// adopt its id (an install from before the binding).
	InstallIDAdoptLegacy = "adopt_legacy"
	// InstallIDMint: mint a new id (a fresh install, or a copy: a bound
	// file of another path is present).
	InstallIDMint = "mint"
)

// InstallIDSource decides where this state dir's id comes from: bound
// (this path's bound file is valid), legacy (adoptable: no bound file of
// any path, a valid legacy id, and the legacy id's gateway unit not loaded
// or running this dir's config), or a new one. A bound file of this path
// that exists but does not hold an id is the caller's error, never a mint
// (it would never be replaced), and so is a legacy file that cannot be
// read or does not hold an id.
func InstallIDSource(boundValid, anyBound, legacyValid, legacyUnitOurs bool) string {
	switch {
	case boundValid:
		return InstallIDBound
	case !anyBound && legacyValid && legacyUnitOurs:
		return InstallIDAdoptLegacy
	}
	return InstallIDMint
}
