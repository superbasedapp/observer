package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// WriteToml saves cfg to path with a .bak fallback (Option A from the
// settings planning doc — comments lost on save, prior version
// preserved). This is THE config write owner: the dashboard settings
// seam and the `observer profile` / `observer config` CLI commands all
// funnel through it (plan §2.3.5 — one owner, two front doors), so
// backup semantics and atomicity can't drift between surfaces.
//
// Steps:
//  1. If path exists, copy it to path+".bak" so the user can recover
//     hand-written comments.
//  2. Marshal cfg to TOML in a temp file in the same directory (atomic
//     rename requires same filesystem).
//  3. os.Rename to path. If this fails, the .bak from step 1 is the
//     authoritative backup.
func WriteToml(path string, cfg Config) error {
	return writeTOMLAtomic(path, cfg)
}

// writeTOMLAtomic is the underlying generic writer for any marshalable
// document (the full Config for the global file; the allow-listed
// overlay doc for project files). It marshals to bytes then hands off
// to writeBytesAtomic for the .bak + temp-file + rename mechanics.
func writeTOMLAtomic(path string, doc any) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(doc); err != nil {
		return fmt.Errorf("marshal toml: %w", err)
	}
	return writeBytesAtomic(path, buf.Bytes())
}

// writeBytesAtomic is THE raw config write mechanism: ensure the dir,
// copy any existing file to path+".bak", write data to a temp file in
// the same directory, then atomically rename it over path. Shared by
// writeTOMLAtomic (struct marshal path) and MigrateFile (surgical
// text-rewrite path) so backup + atomicity semantics can't drift
// between the two (CLAUDE.md #4 — one write owner).
func writeBytesAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("ensure config dir: %w", err)
	}
	if existing, err := os.ReadFile(path); err == nil {
		// 0o600, NOT 0o644 (MHC-2, codebase audit 2026-09-16). The live
		// config.toml is written 0o600 (os.CreateTemp's own mode, preserved by
		// the rename below) and the schema marks several of its keys secret —
		// routing.key_pool, email.password, browser.listener.token. A backup is
		// a byte-for-byte copy of that file, so it must carry the same
		// owner-only mode; a world-readable .bak beside an owner-only original
		// is a credential disclosure to every local account.
		if err := os.WriteFile(path+".bak", existing, 0o600); err != nil {
			return fmt.Errorf("write .bak: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read current config: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.toml")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		// Best-effort cleanup if rename failed.
		if _, statErr := os.Stat(tmpName); statErr == nil {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename %s → %s: %w", tmpName, path, err)
	}
	return nil
}
