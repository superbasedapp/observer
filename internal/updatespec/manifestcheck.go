package updatespec

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// manifestcheck.go holds the small field checks the release manifest
// (internal/update) and the signed content channel (internal/update/content)
// share. They live here, in the neutral core package, because the content
// channel is a core package and may not import the org.update feature.

// HashBytes returns the lowercase hex sha256 of b. It is the one hash
// spelling the update manifests use, for manifests and for artifacts alike.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ValidBaseName rejects anything that is not a plain file name: an
// empty string, a path separator, a "." / ".." element, or a leading
// dash (which would read as a flag if the name ever reached a command
// line).
func ValidBaseName(name string) error {
	if name == "" {
		return errors.New("empty")
	}
	if strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("%q contains a path separator", name)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%q is a path element", name)
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("%q starts with a dash", name)
	}
	return nil
}

// IsHexSHA256 reports whether s is exactly 64 lowercase-or-uppercase
// hex characters.
func IsHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
