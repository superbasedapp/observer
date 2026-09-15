// Package lkgsidecar is the node-local last-known-good materialization of the
// node.features tools.disallow list (P7 gateway-arc / tracker P5b→P6 item 5).
//
// The daemon holds the live node.features policy in memory
// (cmd/observer's nodeFeaturesHandle), but a BARE CLI launcher
// (`observer claude`, `observer codex`, `observer gemini`, …) and
// `observer adapters` run as SHORT-LIVED processes that never touch that
// in-memory handle. This file is how they see the live disallow state: the
// daemon writes the resolved disallow list here beside the DB, and the
// short-lived reader loads it with a fail-open failure table.
//
// It mirrors internal/govern/sidecar (the governance posture materialization)
// deliberately — same closed-decoder, same MaxBytes latency guard, same
// never-error/never-stderr Read contract, same grant-expiry offboarding
// guarantee — but is a SEPARATE package so internal/policyfam/nodefeatures
// stays a pure compiler/decision package (no os/file I/O; imports_test-pinned).
package lkgsidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// MaxSchema is the highest sidecar schema this build understands. A file
// declaring a higher schema is ignored (fail-open — no disallow gating), the
// answer a downgraded launcher needs.
const MaxSchema = 1

// MaxBytes bounds the file. A larger file is ignored rather than parsed: the
// reader runs on the launcher path where an unbounded read is a latency
// hazard, and a disallow list has no legitimate reason to be large.
const MaxBytes = 64 << 10

// Reason values name why a read produced no live disallow list. They are
// diagnostics only — never behaviour, never stderr, never an error return.
const (
	ReasonNone         = ""               // a live sidecar was returned
	ReasonAbsent       = "absent"         // no file (solo / never-governed)
	ReasonUnreadable   = "unreadable"     // perms, EISDIR, I/O
	ReasonOversize     = "oversize"       // larger than MaxBytes
	ReasonMalformed    = "malformed"      // bad JSON / unknown field / trailing bytes
	ReasonSchemaTooNew = "schema_too_new" // written by a newer build
	ReasonGrantExpired = "grant_expired"  // now > grant_expires_at
)

// File is the on-disk wire shape. Times are RFC3339 STRINGS so "no TTL" is
// representable as the empty string (a zero time.Time would marshal to a real
// past instant and expire every sidecar).
type File struct {
	// Schema is the sidecar schema (see MaxSchema).
	Schema int `json:"schema"`
	// WriterVersion is the observer build that wrote the file. Diagnostics
	// only — never a gate.
	WriterVersion string `json:"writer_version,omitempty"`
	// WrittenAt is when the daemon last wrote it. INFORMATIONAL.
	WrittenAt string `json:"written_at,omitempty"`
	// GrantExpiresAt is the hard clock copied from the resolved grant. Empty
	// means "no TTL". A reader past this instant ignores the file whole, so an
	// org that stops authorizing a node stops gating its launchers even if the
	// daemon is dead — the short-lived-process offboarding guarantee.
	GrantExpiresAt string `json:"grant_expires_at,omitempty"`
	// Disallow is the resolved, lower-cased, sorted set of integration-registry
	// tool names the org has disallowed. Present-and-empty is a positive
	// "nothing disallowed" assertion (distinct from absence).
	Disallow []string `json:"disallow"`
}

// Disallowed reports whether tool is on the disallow list (case-insensitive,
// trimmed). A nil File allows everything (fail-open).
func (f *File) Disallowed(tool string) bool {
	if f == nil {
		return false
	}
	tool = strings.ToLower(strings.TrimSpace(tool))
	if tool == "" {
		return false
	}
	for _, d := range f.Disallow {
		if strings.ToLower(strings.TrimSpace(d)) == tool {
			return true
		}
	}
	return false
}

// Encode renders the file canonically (json.Marshal sorts keys, so the
// writer's change detection is exact). Disallow is normalized+sorted by the
// caller (NewFile) so two semantically-equal lists produce identical bytes.
func Encode(f File) ([]byte, error) {
	if f.Schema == 0 {
		f.Schema = MaxSchema
	}
	out, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("lkgsidecar.Encode: %w", err)
	}
	return out, nil
}

// Decode strictly parses sidecar bytes. Unknown fields are rejected so a file
// written by a NEWER build is refused whole rather than partially honoured.
func Decode(raw []byte) (File, error) {
	if len(raw) > MaxBytes {
		return File{}, fmt.Errorf("lkgsidecar.Decode: %d bytes exceeds the %d-byte cap", len(raw), MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return File{}, fmt.Errorf("lkgsidecar.Decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return File{}, errors.New("lkgsidecar.Decode: trailing bytes after the document")
	}
	return f, nil
}

// Read loads the sidecar at path and applies the fail-open failure table. It
// NEVER returns an error and never writes to stderr: a launcher gate that could
// crash on a malformed governance artifact would be a self-inflicted outage.
// A non-empty reason with a nil file names WHY nothing gates. now owns the
// clock so expiry is testable without sleeping.
func Read(path string, now time.Time) (*File, string) {
	if path == "" {
		return nil, ReasonAbsent
	}
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, ReasonAbsent
	case err != nil:
		return nil, ReasonUnreadable
	case info.IsDir():
		return nil, ReasonUnreadable
	case info.Size() > MaxBytes:
		return nil, ReasonOversize
	}
	raw, err := os.ReadFile(path) //nolint:gosec // path is resolved from the node's own config, never from input
	if err != nil {
		return nil, ReasonUnreadable
	}
	f, err := Decode(raw)
	if err != nil {
		return nil, ReasonMalformed
	}
	if f.Schema < 1 || f.Schema > MaxSchema {
		return nil, ReasonSchemaTooNew
	}
	if exp, ok := parseTime(f.GrantExpiresAt); ok && now.After(exp) {
		return nil, ReasonGrantExpired
	}
	return &f, ReasonNone
}

// NewFile builds a canonical File from a raw disallow set and an optional grant
// expiry, normalizing (lower-case, trim, de-dupe, sort) the tool names so the
// on-disk bytes are stable for a given logical list.
func NewFile(writerVersion string, disallow []string, grantExpiresAt time.Time, now time.Time) File {
	seen := make(map[string]struct{}, len(disallow))
	norm := make([]string, 0, len(disallow))
	for _, d := range disallow {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		norm = append(norm, d)
	}
	sortStrings(norm)
	f := File{
		Schema:        MaxSchema,
		WriterVersion: writerVersion,
		WrittenAt:     now.UTC().Format(time.RFC3339),
		Disallow:      norm,
	}
	if !grantExpiresAt.IsZero() {
		f.GrantExpiresAt = grantExpiresAt.UTC().Format(time.RFC3339)
	}
	return f
}

// parseTime parses an RFC3339 instant; ok is false for empty/unparseable
// (treated as "no TTL").
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// sortStrings is a tiny insertion sort to avoid importing sort for a handful of
// short tool names (keeps the package dependency-light like govern/sidecar).
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
