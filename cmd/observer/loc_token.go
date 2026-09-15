package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// Per-install credential for POST /api/loc/editor-change (docs/loc-tracking.md).
//
// The endpoint reports the developer's own saved line COUNTS from the VS
// Code extension. It is loopback-only and Origin-guarded, but any local
// process could still post to it; a per-install secret closes that by
// requiring the caller to first read a file only this user can open.
//
// This is where the credential's whole lifecycle lives: generate it on
// first daemon start, read it back on every later start, hand the VALUE to
// the dashboard package. internal/intelligence/dashboard never touches the
// filesystem for it.

// locEditorTokenEnv is the DEPRECATED environment override, honoured for
// one release. It was the original opt-in mechanism, before the token had a
// file of its own.
const locEditorTokenEnv = "OBSERVER_LOC_EDITOR_TOKEN" //nolint:gosec // G101: env-var NAME, not a credential

// locEditorTokenBytes is the generated secret's entropy. 32 bytes is the
// same width as every other random identifier the daemon mints, hex-encoded
// so the file is a single copy-pasteable line with no encoding questions.
const locEditorTokenBytes = 32

// resolveLocEditorToken returns the shared secret the LOC editor endpoint
// should verify against, creating it on first start.
//
// Resolution order, and why:
//
//  1. OBSERVER_LOC_EDITOR_TOKEN, when set. Deprecated, warned about once,
//     but it WINS: an operator who scripted it has a running setup, and
//     silently preferring a file they have never heard of would break it.
//  2. The contents of path, when the file already exists.
//  3. A freshly generated token, written to path 0600 (parent dir 0700).
//
// It NEVER fails the caller. A path that cannot be created or read yields
// an empty token and a logged warning: the endpoint then keeps the loopback
// + Origin posture it shipped with, which is a weaker endpoint but a
// working daemon. Blocking `observer start` on a hardening credential for
// one reporting endpoint would be the wrong trade.
//
// The token itself is never logged, at any level.
func resolveLocEditorToken(path string, log *slog.Logger) string {
	if log == nil {
		log = slog.Default()
	}
	if env := strings.TrimSpace(os.Getenv(locEditorTokenEnv)); env != "" {
		log.Warn("loc: " + locEditorTokenEnv + " is deprecated and will be removed in a " +
			"future release; the daemon now generates a per-install token in " +
			"[loc].editor_token_file (see docs/loc-tracking.md)")
		return env
	}
	if strings.TrimSpace(path) == "" {
		return ""
	}
	tok, err := readOrCreateLocEditorToken(path)
	if err != nil {
		// Fail OPEN, loudly. The path is safe to log; the contents are not.
		log.Warn("loc: editor token unavailable; POST /api/loc/editor-change "+
			"keeps its loopback-only posture and verifies no token",
			"path", path, "err", err)
		return ""
	}
	return tok
}

// readOrCreateLocEditorToken reads path, or mints and writes a new token
// when the file is absent. The write is atomic (temp file in the same
// directory + rename) so a daemon killed mid-write never leaves a truncated
// secret behind for the extension to read.
func readOrCreateLocEditorToken(path string) (string, error) {
	switch data, err := os.ReadFile(path); {
	case err == nil:
		if tok := strings.TrimSpace(string(data)); tok != "" {
			return tok, nil
		}
		// An empty or whitespace-only file is a half-finished write or a
		// hand-truncated file, not a decision to disable the token. Mint a
		// new one over it rather than running credential-less in silence.
	case !errors.Is(err, os.ErrNotExist):
		return "", fmt.Errorf("read loc editor token: %w", err)
	}

	buf := make([]byte, locEditorTokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate loc editor token: %w", err)
	}
	tok := hex.EncodeToString(buf)

	dir := filepath.Dir(path)
	// 0700: the token's whole value is that only this user can read it, so
	// the directory it lands in must not be group- or world-traversable
	// either. MkdirAll leaves an EXISTING directory's mode alone, so this
	// never tightens ~/.observer behind the operator's back.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("ensure loc editor token dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".loc-editor-token-*")
	if err != nil {
		return "", fmt.Errorf("create loc editor token temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	// CreateTemp already makes the file 0600; Chmod is belt-and-braces for
	// a umask-independent guarantee, and documents the intent at the write.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", fmt.Errorf("chmod loc editor token temp: %w", err)
	}
	if _, err := tmp.WriteString(tok + "\n"); err != nil {
		tmp.Close()
		return "", fmt.Errorf("write loc editor token temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close loc editor token temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("rename loc editor token: %w", err)
	}
	return tok, nil
}

// locEditorTokenPath resolves the configured token-file path, falling back
// to the packaged default when a config load failed or left it empty (the
// daemon's start path builds the dashboard even on a degraded config load).
func locEditorTokenPath(cfg config.Config) string {
	if p := strings.TrimSpace(cfg.Loc.EditorTokenFile); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".observer", "loc-editor-token")
}
