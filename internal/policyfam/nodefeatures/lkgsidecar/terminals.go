package lkgsidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// terminals.go is the SIBLING file that carries the org's node.features
// terminals rule to a short-lived launcher (OSH-R-003). It is a separate
// file, not a field of File, because Decode refuses unknown fields: a
// binary from before the rule existed would read a File carrying it as
// malformed and stop enforcing the org's tools.disallow list (audit
// follow-up F2). The disallow sidecar's bytes therefore stay exactly what
// older binaries expect, and only a build that knows this file reads it.

// TerminalsFilename is the sibling file's name, beside the disallow
// sidecar.
const TerminalsFilename = "features-terminals.json"

// MaxTerminalsSchema is the highest terminals-file schema this build
// understands.
const MaxTerminalsSchema = 1

// Terminals is the governed terminals rule a launcher needs: whether
// terminals are enabled and whether a terminal must run in a sandbox.
type Terminals struct {
	Enabled         bool `json:"enabled"`
	SandboxRequired bool `json:"sandbox_required"`
}

// TerminalsFile is the sibling file's wire shape. Terminals is nil while
// the org does not govern terminals (every launch allowed by this rule).
type TerminalsFile struct {
	Schema        int        `json:"schema"`
	WriterVersion string     `json:"writer_version,omitempty"`
	WrittenAt     string     `json:"written_at,omitempty"`
	Terminals     *Terminals `json:"terminals"`
}

// TerminalsPath is the sibling file's path for the disallow sidecar at
// sidecarPath ("" when there is none).
func TerminalsPath(sidecarPath string) string {
	if sidecarPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(sidecarPath), TerminalsFilename)
}

// NewTerminalsFile builds the file for a terminals rule (nil: not governed).
func NewTerminalsFile(writerVersion string, t *Terminals, now time.Time) TerminalsFile {
	return TerminalsFile{Schema: MaxTerminalsSchema, WriterVersion: writerVersion, WrittenAt: now.UTC().Format(time.RFC3339), Terminals: t}
}

// EncodeTerminals renders the file canonically.
func EncodeTerminals(f TerminalsFile) ([]byte, error) {
	if f.Schema == 0 {
		f.Schema = MaxTerminalsSchema
	}
	out, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("lkgsidecar.EncodeTerminals: %w", err)
	}
	return out, nil
}

// DecodeTerminals strictly parses the file (unknown fields refused).
func DecodeTerminals(raw []byte) (TerminalsFile, error) {
	if len(raw) > MaxBytes {
		return TerminalsFile{}, fmt.Errorf("lkgsidecar.DecodeTerminals: %d bytes exceeds the %d-byte cap", len(raw), MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f TerminalsFile
	if err := dec.Decode(&f); err != nil {
		return TerminalsFile{}, fmt.Errorf("lkgsidecar.DecodeTerminals: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return TerminalsFile{}, errors.New("lkgsidecar.DecodeTerminals: trailing bytes after the document")
	}
	return f, nil
}

// ReadTerminals loads the file at path with the same never-error failure
// table as Read: a nil file and a Reason* value name why nothing was read.
// The caller decides what an unreadable file means (a managed node refuses).
func ReadTerminals(path string) (*TerminalsFile, string) {
	if path == "" {
		return nil, ReasonAbsent
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ReasonAbsent
	case err != nil, err == nil && info.IsDir():
		return nil, ReasonUnreadable
	case info.Size() > MaxBytes:
		return nil, ReasonOversize
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is resolved from the node's own config, never from input
	if err != nil {
		return nil, ReasonUnreadable
	}
	f, err := DecodeTerminals(raw)
	if err != nil {
		return nil, ReasonMalformed
	}
	if f.Schema < 1 || f.Schema > MaxTerminalsSchema {
		return nil, ReasonSchemaTooNew
	}
	return &f, ReasonNone
}
