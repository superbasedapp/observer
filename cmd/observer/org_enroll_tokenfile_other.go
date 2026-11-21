//go:build !unix

package main

import "os"

// openEnrolTokenFile opens a --token-file path; the caller accepts only a
// regular file, checked on the open file (O5 audit finding O5-A7).
func openEnrolTokenFile(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G304: the path the user named on the command line
}
