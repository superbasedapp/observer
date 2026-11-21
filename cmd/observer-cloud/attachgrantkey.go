package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// attachgrantkey.go loads the one-step attach grant's signing key for
// `observer-cloud serve` (Getting started v2 lane 8; internal/attachgrant;
// docs/security.md ONB-8). The key is a hex Ed25519 seed (64 hex characters,
// 32 bytes) in a file the deploy kit generates once and mounts read-only
// (deploy/demo-box/cloud-state.sh attach_grant_key); the tenant hosts pin its
// public half (`cloud-app.sh attach-key-public` piped to `org-app.sh
// platform-key attach-grant`). Only the _FILE form exists: a private key
// never rides an environment value.

// envAttachGrantKeyFile names the key file.
const envAttachGrantKeyFile = "SBCI_ATTACH_GRANT_KEY_FILE"

// maxAttachGrantKeyFile bounds the read (a seed is 64 characters).
const maxAttachGrantKeyFile = 4096

// loadAttachGrantKey reads the seed at path. An empty path is "no key" (nil,
// nil); a path that is set but unreadable, oversized or not a 32-byte hex
// seed is an error, so a broken mount refuses to start instead of silently
// handing out no grants.
func loadAttachGrantKey(path string) (ed25519.PrivateKey, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	fi, err := os.Stat(path) //nolint:gosec // operator-named secret file
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envAttachGrantKeyFile, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxAttachGrantKeyFile {
		return nil, fmt.Errorf("%s: %s is not a small regular file", envAttachGrantKeyFile, path)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // operator-named secret file
	if err != nil {
		return nil, fmt.Errorf("%s: %w", envAttachGrantKeyFile, err)
	}
	return parseAttachGrantSeed(string(raw))
}

// parseAttachGrantSeed decodes a hex Ed25519 seed (surrounding whitespace
// ignored).
func parseAttachGrantSeed(text string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(strings.TrimSpace(text))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: the file is not a hex Ed25519 seed (64 hex characters)", envAttachGrantKeyFile)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// attachGrantKeyID is the key id the tenant hosts pin (the grant's kid).
func attachGrantKeyID(priv ed25519.PrivateKey) string {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return platformcontract.DocumentKeyID(pub)
}
