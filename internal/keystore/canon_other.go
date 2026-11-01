//go:build !windows

package keystore

import "path/filepath"

// resolveExisting is the path of an existing file or folder with every
// symbolic link resolved; ok is false when p does not exist.
func resolveExisting(p string) (string, bool) {
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", false
	}
	return r, true
}
