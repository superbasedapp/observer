package filehash

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// SHA256 returns the lowercase hex SHA-256 of the file at path. An error
// from opening or reading the file is returned as is.
func SHA256(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: each caller passes a path it composed or read from its own config
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
