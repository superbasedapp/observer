package content

import (
	"errors"
	"time"

	"github.com/marmutapp/superbased-observer/internal/updatespec"
)

// The small helpers this package shares with internal/update's release
// manifest. The file-name and hash checks live in internal/updatespec, the
// neutral core package both use, because internal/update belongs to the
// org.update component and a core package may not import it.

// HashBytes returns the lowercase hex sha256 of b (updatespec.HashBytes).
func HashBytes(b []byte) string {
	return updatespec.HashBytes(b)
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
