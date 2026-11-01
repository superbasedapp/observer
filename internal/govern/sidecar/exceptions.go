package sidecar

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

// ExceptionsFilename is the feature-access exceptions file's basename. It
// sits BESIDE the governance sidecar (ExceptionsPath) and is a SEPARATE file
// on purpose: the governance sidecar body stays byte-compatible with every
// released reader (whose strict decoder refuses an unknown field and would
// otherwise run ungoverned after an update rollback), while only binaries
// that know this file write it or read it. An older binary never opens it,
// so on a rollback every pin applies again: the stricter reading.
const ExceptionsFilename = "governance-exceptions.json"

// ExceptionsMaxSchema is the highest exceptions-file schema this build
// understands. Independent of MaxSchema.
const ExceptionsMaxSchema = 1

// ReasonStale names an exceptions file bound to a different governance
// posture than the sidecar it sits beside (or to none). Its exceptions lift
// nothing until the daemon rewrites it for the posture in force.
const ReasonStale = "stale"

// Exception is one feature-access grant lifting one pin (request-grants G8).
type Exception struct {
	GrantID int64 `json:"grant_id"`
	// Until is the RFC3339 instant the grant stops being honoured if
	// nothing changes (accessgrant.HonouredUntilNs). An unreadable value is
	// no exception.
	Until string `json:"until"`
}

// ExceptionsFile is the on-disk shape of the exceptions file. The daemon
// (the one writer of the governance sidecar) writes it after re-verifying
// the org's signed grant document, with the same atomic write and
// read-back verification as the sidecar, and only while at least one
// exception is in force; otherwise the file is removed.
type ExceptionsFile struct {
	// Schema is the exceptions-file schema (see ExceptionsMaxSchema).
	Schema int `json:"schema"`
	// WriterVersion and WrittenAt are diagnostics only, never a gate.
	WriterVersion string `json:"writer_version,omitempty"`
	WrittenAt     string `json:"written_at,omitempty"`
	// EffectiveHash binds the file to ONE governance posture: the
	// effective_hash of the sidecar it was written beside. A reader honours
	// the exceptions only while the sidecar carries the same hash, so a file
	// left behind by an earlier posture (or a write that landed between the
	// two files) lifts nothing.
	EffectiveHash string `json:"effective_hash"`
	// Exceptions are keyed like File.Pinned. An exception REMOVES a pin and
	// never sets a value; one for a key that is not pinned does nothing.
	Exceptions map[string]Exception `json:"exceptions"`
}

// ExceptionsPath returns the exceptions file that pairs with the governance
// sidecar at sidecarPath ("" when there is no sidecar path).
func ExceptionsPath(sidecarPath string) string {
	if sidecarPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(sidecarPath), ExceptionsFilename)
}

// EncodeExceptions renders the file canonically (json.Marshal sorts map
// keys), so the writer's change detection and read-back check are exact.
func EncodeExceptions(f ExceptionsFile) ([]byte, error) {
	if f.Schema == 0 {
		f.Schema = ExceptionsMaxSchema
	}
	out, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("govern/sidecar.EncodeExceptions: %w", err)
	}
	return out, nil
}

// DecodeExceptions strictly parses exceptions-file bytes, with the same
// size cap, unknown-field and trailing-bytes rules as Decode.
func DecodeExceptions(raw []byte) (ExceptionsFile, error) {
	if len(raw) > MaxBytes {
		return ExceptionsFile{}, fmt.Errorf("govern/sidecar.DecodeExceptions: %d bytes exceeds the %d-byte cap", len(raw), MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f ExceptionsFile
	if err := dec.Decode(&f); err != nil {
		return ExceptionsFile{}, fmt.Errorf("govern/sidecar.DecodeExceptions: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ExceptionsFile{}, errors.New("govern/sidecar.DecodeExceptions: trailing bytes after the document")
	}
	return f, nil
}

// ReadExceptions loads the exceptions file at path for the governance
// posture effectiveHash. Like Read it NEVER errors and never writes to
// stderr (it runs inside config.Load on the hook path): every failure is no
// exceptions, which leaves every pin in force. A non-empty reason names why.
func ReadExceptions(path, effectiveHash string) (map[string]Exception, string) {
	if path == "" {
		return nil, ReasonAbsent
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ReasonAbsent
	case err != nil, info.IsDir():
		return nil, ReasonUnreadable
	case info.Size() > MaxBytes:
		return nil, ReasonOversize
	}
	raw, err := os.ReadFile(path) //nolint:gosec // the path is derived from the node's own sidecar path, never from input
	if err != nil {
		return nil, ReasonUnreadable
	}
	return ReadExceptionsBytes(raw, effectiveHash)
}

// ReadExceptionsBytes applies ReadExceptions' rules to exceptions-file bytes
// the caller already holds (the daemon's last verified copy, T-845). Empty
// bytes are ReasonAbsent: no exception, every pin in force.
func ReadExceptionsBytes(raw []byte, effectiveHash string) (map[string]Exception, string) {
	if len(raw) == 0 {
		return nil, ReasonAbsent
	}
	if len(raw) > MaxBytes {
		return nil, ReasonOversize
	}
	f, err := DecodeExceptions(raw)
	if err != nil {
		return nil, ReasonMalformed
	}
	if f.Schema < 1 || f.Schema > ExceptionsMaxSchema {
		return nil, ReasonSchemaTooNew
	}
	if effectiveHash == "" || f.EffectiveHash != effectiveHash {
		return nil, ReasonStale
	}
	return f.Exceptions, ReasonNone
}

// PinsInForce returns pinned with every key an exception lifts at now
// removed, and the lifted keys mapped onto their grant ids. An exception for
// a key that is not pinned lifts nothing (it never sets a value); one whose
// Until has passed, or cannot be read, or that names no grant, lifts
// nothing. pinned is never modified.
func PinsInForce(pinned map[string]any, exceptions map[string]Exception, now time.Time) (map[string]any, map[string]int64) {
	if len(exceptions) == 0 || len(pinned) == 0 {
		return pinned, nil
	}
	out := make(map[string]any, len(pinned))
	var lifted map[string]int64
	for k, v := range pinned {
		if ex, ok := exceptions[k]; ok && ex.GrantID > 0 {
			if until, ok := ParseTime(ex.Until); ok && now.Before(until) {
				if lifted == nil {
					lifted = map[string]int64{}
				}
				lifted[k] = ex.GrantID
				continue
			}
		}
		out[k] = v
	}
	return out, lifted
}
