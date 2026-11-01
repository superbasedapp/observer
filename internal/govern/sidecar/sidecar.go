package sidecar

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// MaxSchema is the highest sidecar schema this build understands. It is
// INDEPENDENT of the node.governance body schema: the body is an org-wire
// contract, this file is a node-local materialization of the RESOLVED
// posture, and the two version for different reasons.
//
// A sidecar declaring a higher schema is ignored (nil overlay), which is the
// fail-open answer a downgraded daemon needs.
const MaxSchema = 1

// MaxBytes bounds the file. A larger file is ignored rather than parsed: the
// reader runs on the hook path, where an unbounded read is a latency
// hazard, and a governance file has no legitimate reason to be large.
const MaxBytes = 64 << 10

// The govern.State literals this file may carry. They are duplicated rather
// than imported for the same dependency reason the package doc gives:
// internal/govern imports THIS package, never the reverse.
const (
	// StateApplied is the ONLY state whose directives a reader applies.
	StateApplied = "applied"
)

// Reason values name why a read produced no overlay. They are diagnostics
// for `observer doctor governance` and `observer org grant show` — never
// behaviour, never stderr, and never an error return.
const (
	ReasonNone         = ""               // a live sidecar was returned
	ReasonAbsent       = "absent"         // no file (the solo-node case)
	ReasonUnreadable   = "unreadable"     // perms, EISDIR, I/O
	ReasonOversize     = "oversize"       // larger than MaxBytes
	ReasonMalformed    = "malformed"      // bad JSON / unknown field / trailing bytes
	ReasonSchemaTooNew = "schema_too_new" // written by a newer build
	ReasonGrantExpired = "grant_expired"  // now > grant_expires_at
	ReasonNotApplied   = "not_applied"    // the daemon last resolved dormant/inert
)

// File is the on-disk wire shape.
//
// Times are RFC3339 STRINGS rather than time.Time so "absent" is
// representable and canonical: a zero time.Time marshals to
// "0001-01-01T00:00:00Z", which reads as a real (long past) instant and
// would expire every sidecar the moment the field was accidentally omitted.
type File struct {
	// Schema is the sidecar schema (see MaxSchema).
	Schema int `json:"schema"`
	// WriterVersion is the observer build that wrote the file. Diagnostics
	// only — never a gate.
	WriterVersion string `json:"writer_version,omitempty"`
	// WrittenAt is when the daemon last wrote it. INFORMATIONAL: it drives
	// the disclosure surfaces and a doctor warning, never a behavioural
	// decision (§1.5).
	WrittenAt string `json:"written_at,omitempty"`
	// State is govern.State verbatim, carried for the DISCLOSURE surfaces
	// (`observer org grant show`, doctor). It does NOT gate the overlay:
	// govern.Resolve materializes "inert" for any PARTIAL application
	// (e.g. pins applied while the always-present sections class dropped
	// for missing dashboard.visibility authority), so gating on
	// state=="applied" would discard pins the daemon reports as live —
	// the exact writer/reader split the 2026-08-15 hook smoke caught.
	// Dormancy is decided by the directive maps instead; see Dormant.
	State string `json:"state"`

	OrgKey        string `json:"org_key,omitempty"`
	Generation    int64  `json:"generation,omitempty"`
	OrgName       string `json:"org_name,omitempty"`
	FamilyVersion int64  `json:"family_version,omitempty"`
	// EffectiveHash is govern.Effective.Hash — the content address of the
	// RUNNING posture, which is what the daemon compares its startup config
	// against to decide pending_restart (§1.6).
	EffectiveHash string `json:"effective_hash,omitempty"`

	// GrantExpiresAt is THE hard clock, copied verbatim from the resolved
	// grant. An EMPTY value means "no TTL", matching govern.Resolve's
	// treatment of a zero ExpiresAt.
	GrantExpiresAt string `json:"grant_expires_at,omitempty"`

	// Pinned is the flat dotted-key → typed-value map, in exactly the shape
	// config's overlay wants, so the reader does no translation.
	Pinned map[string]any `json:"pinned,omitempty"`
	// Share is the resolved (already lowering-merged) share posture.
	Share map[string]any `json:"share,omitempty"`
	// Features is the display-only mirror (§3): the developer's Enrolment
	// page says "your organization requires the guard to be on" rather than
	// "guard.enabled = true".
	Features map[string]bool `json:"features,omitempty"`

	// NO FIELD MAY BE ADDED HERE without a schema bump and a reader-compat
	// plan. Decode is strict, and every released observer reads this file
	// with its own copy of this struct: a field a released reader does not
	// know makes that reader refuse the WHOLE file and run ungoverned (the
	// D-234 class), which an enterprise update rollback (an older binary
	// next to a newer file) hits for real. A new directive class goes in
	// its OWN sidecar file that only the binaries knowing it write and read,
	// the way the feature-access exceptions do (exceptions.go). Pinned by
	// TestFileShapeIsTheReleasedShape against testdata/released-v1-fields.json.
}

// Dormant reports whether this file records a node that is NOT governed.
//
// A dormant posture is WRITTEN, not deleted: presence-with-empty is
// unambiguous, whereas absence is indistinguishable from "the daemon never
// ran" (§1.4). "Empty" is judged on the directive maps, not on State: the
// daemon's resolver only materializes maps it actually applied (authority
// already intersected, unauthorized classes already dropped), so a file
// with a non-empty map is a live posture even when State is "inert" —
// inert records that SOMETHING was refused, not that nothing applied.
func (f File) Dormant() bool {
	return len(f.Pinned) == 0 && len(f.Share) == 0 && len(f.Features) == 0
}

// Encode renders the file canonically. json.Marshal sorts map keys, so two
// semantically-equal postures produce identical bytes and the writer's
// change detection is exact.
func Encode(f File) ([]byte, error) {
	if f.Schema == 0 {
		f.Schema = MaxSchema
	}
	out, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("govern/sidecar.Encode: %w", err)
	}
	return out, nil
}

// Decode strictly parses sidecar bytes. Unknown fields are rejected, so a
// file written by a NEWER build that added a directive class is refused
// whole rather than partially honoured — the same loud-failure posture the
// org-wire body decoder takes.
func Decode(raw []byte) (File, error) {
	if len(raw) > MaxBytes {
		return File{}, fmt.Errorf("govern/sidecar.Decode: %d bytes exceeds the %d-byte cap", len(raw), MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f File
	if err := dec.Decode(&f); err != nil {
		return File{}, fmt.Errorf("govern/sidecar.Decode: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return File{}, errors.New("govern/sidecar.Decode: trailing bytes after the document")
	}
	return f, nil
}

// Read loads the sidecar at path and applies the §1.3 failure table. It
// NEVER returns an error and never writes to stderr: the caller is
// config.Load, which runs on the hook path, and a governance file that could
// make a hook fail would be a fleet-wide self-inflicted outage.
//
// A non-empty reason with a nil file names WHY nothing applies, for the
// disclosure surfaces only.
//
// now decides expiry — the caller owns the clock, so the rule is testable
// without sleeping.
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
	raw, err := os.ReadFile(path) //nolint:gosec // the path is resolved from the node's own config, never from input
	if err != nil {
		return nil, ReasonUnreadable
	}
	return ReadBytes(raw, now)
}

// ReadBytes applies Read's failure table to sidecar bytes the caller already
// holds: the daemon's last verified copy (the MAC'd org lock, T-845), which a
// reader uses instead of an on-disk file that no longer matches it. Empty
// bytes are ReasonAbsent.
func ReadBytes(raw []byte, now time.Time) (*File, string) {
	if len(raw) == 0 {
		return nil, ReasonAbsent
	}
	if len(raw) > MaxBytes {
		return nil, ReasonOversize
	}
	f, err := Decode(raw)
	if err != nil {
		return nil, ReasonMalformed
	}
	if f.Schema < 1 || f.Schema > MaxSchema {
		return nil, ReasonSchemaTooNew
	}
	// THE offboarding guarantee for short-lived processes: a reader honours
	// the grant's own expiry even when the daemon is dead, removed, or
	// downgraded, so an org that stops authorizing a node stops governing it
	// without needing the node's daemon to cooperate.
	if exp, ok := ParseTime(f.GrantExpiresAt); ok && now.After(exp) {
		return nil, ReasonGrantExpired
	}
	if f.Dormant() {
		return nil, ReasonNotApplied
	}
	return &f, ReasonNone
}

// ParseTime parses one of this file's RFC3339 stamps. An empty or
// unparseable value is reported as ABSENT (ok=false) rather than as the zero
// instant, because the zero instant would read as "expired long ago" and
// silently ungovern a node on a hand-edit typo.
func ParseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// FormatTime renders a stamp, mapping the zero time onto the absent form.
func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
