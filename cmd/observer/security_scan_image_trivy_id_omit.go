//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_trivy && !sbo_omit_security_scan_image_trivy && (sbo_omit_security_scan_scalibr || sbo_omit_security_scan_os)

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// security_scan_image_trivy_id_omit.go is the Trivy image driver's identity
// of an image in a build without route A's layer reader (the developer
// distro): "sha256:" of the whole image file, capped at 16 GiB. Route A is
// not in such a build, so no other driver keys the same image differently.

const trivyImageMaxBytes = 16 << 30

// trivyImageDigest is the identity of the image at in, and the fixed
// reason when the image cannot be read.
func trivyImageDigest(in string, isDir bool, _ string) (digest, reason string) {
	if isDir {
		return trivyDirDigest(in), ""
	}
	f, err := os.Open(in) //nolint:gosec // G703: the image path the user named on the command line; only read
	if err != nil {
		return "", "engine_failed"
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, trivyImageMaxBytes+1))
	if err != nil {
		return "", "engine_failed"
	}
	if n > trivyImageMaxBytes {
		return "", "cap_exceeded"
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), ""
}
