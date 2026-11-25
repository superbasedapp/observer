package genout

import (
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile puts the bytes at path, creating the parent directory when the
// gate points it at a scratch location.
func WriteFile(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	//nolint:gosec // G306: a committed, publicly-distributed source artifact; world-readable is intended.
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
