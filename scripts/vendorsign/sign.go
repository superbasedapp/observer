package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
)

// SigSuffix is the sibling-file suffix for a vendor signature. It
// matches internal/orgserver/updateartifact's SigSuffix, which is what
// `observer-org update import` looks for beside each archive; the two
// are separate constants because this tool must not import the org
// server (it is stripped from the public tree).
const SigSuffix = ".sig"

// signArchive signs one archive's bytes and writes `<path>.sig`.
//
// The signature covers the WHOLE ARCHIVE, not a digest of it and not a
// container around it, because that is what the node verifies:
// verifyVendorSignature reads the downloaded archive and calls
// ed25519.Verify over those exact bytes. Signing anything else here
// would produce a release whose signatures fail on every node, and the
// failure would surface at a customer's first ring rather than in CI.
//
// The whole file is read into memory: Ed25519 has no streaming API in
// the standard library, and a release archive is tens of megabytes on a
// CI runner with gigabytes. If archives ever grow past that, the answer
// is ed25519ph over a streamed digest on BOTH sides in the same wave,
// never a quiet change on one.
func signArchive(path string, priv ed25519.PrivateKey) (string, error) {
	body, err := os.ReadFile(path) //nolint:gosec // a release-asset path this tool was pointed at
	if err != nil {
		return "", fmt.Errorf("vendorsign sign: read %s: %w", path, err)
	}
	sig := ed25519.Sign(priv, body)
	out := path + SigSuffix
	if err := os.WriteFile(out, sig, 0o644); err != nil { //nolint:gosec // a public release asset
		return "", fmt.Errorf("vendorsign sign: write %s: %w", out, err)
	}
	return out, nil
}

// readSignature reads a `<archive>.sig` and returns the raw signature.
// It refuses anything that is not exactly SignatureSize bytes: a
// signature file of another shape means a different producer signed
// this release, and recording it would build a manifest whose artifacts
// fail vendor verification on every node.
func readSignature(path string) ([]byte, error) {
	raw, err := os.ReadFile(path) //nolint:gosec // a release-asset path this tool composed
	if err != nil {
		return nil, fmt.Errorf("vendorsign: read %s: %w", path, err)
	}
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("vendorsign: %s is %d bytes, want %d raw Ed25519 signature bytes",
			path, len(raw), ed25519.SignatureSize)
	}
	return raw, nil
}
