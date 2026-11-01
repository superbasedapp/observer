package content

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// The small helpers this package shares in spirit with internal/update's
// release manifest (the same spellings), kept here because internal/update
// belongs to the org.update component and a core package may not import it.

// HashBytes returns the lowercase hex sha256 of b.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// validBaseName rejects anything that is not a plain file name.
func validBaseName(name string) error {
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

// isHexSHA256 reports whether s is exactly 64 hex characters.
func isHexSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// parseRFC3339 parses a required RFC3339 timestamp.
func parseRFC3339(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}
