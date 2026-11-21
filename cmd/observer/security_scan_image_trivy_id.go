//go:build !sbo_omit_security && !sbo_omit_security_deps && !sbo_omit_security_scan_trivy && !sbo_omit_security_scan_image_trivy && !sbo_omit_security_scan_scalibr && !sbo_omit_security_scan_os

package main

import (
	"os"

	"github.com/marmutapp/superbased-observer/internal/secimage"
)

// security_scan_image_trivy_id.go is the Trivy image driver's identity of
// an image where route A's layer reader (internal/secimage, component
// security.scan.os) is compiled: the same "sha256:" of the image manifest,
// so both drivers keep an image's findings under the same project key
// "image:<digest>". A build without it uses
// security_scan_image_trivy_id_omit.go.

// trivyImageDigest is the identity of the image at in, and the fixed
// reason when the image cannot be read (the run is then not scanned).
func trivyImageDigest(in string, isDir bool, scratch string) (digest, reason string) {
	if isDir {
		return trivyDirDigest(in), ""
	}
	if err := os.MkdirAll(scratch, 0o700); err != nil {
		return "", "engine_failed"
	}
	defer func() { _ = os.RemoveAll(scratch) }()
	sink, err := secimage.NewDirSink(scratch)
	if err != nil {
		return "", "engine_failed"
	}
	defer sink.Close()
	f, err := os.Open(in) //nolint:gosec // G703: the image path the user named on the command line; only read
	if err != nil {
		return "", "engine_failed"
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return "", "engine_failed"
	}
	res, err := secimage.Flatten(f, fi.Size(), sink, secimage.DefaultLimits())
	if err != nil && res.Digest == "" {
		return "", secimage.ReasonOf(err)
	}
	return res.Digest, ""
}
