package cloudcontract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// The two-digest protocol (plan §6 CI-P1 / Sol SC1)
// ================================================
//
// An envelope carries two SHA-256 digests, computed over two DISTINCT,
// DEFINED, and NON-SELF-REFERENTIAL preimages:
//
//  1. EvidenceContentDigest — over the CANONICAL preimage: the envelope
//     marshaled with BOTH digest fields absent (EvidenceContentDigest forced
//     empty so its `omitempty` tag drops it; UploadDigest never serialized at
//     all, tagged `json:"-"`). It pins the meaning of the evidence
//     independent of how the bytes are later framed, and is itself carried
//     inside the upload bytes.
//
//  2. UploadDigest — over the FINAL exact serialized bytes: the very bytes a
//     node would preview and upload, i.e. the envelope marshaled WITH
//     EvidenceContentDigest present (and UploadDigest still absent). Because
//     UploadDigest is never part of the serialization, it cannot cover
//     itself.
//
// Canonical serialization is deterministic Go encoding/json struct-order
// output: fields in declaration order, HTML escaping disabled (so scrubbed
// excerpts read literally in the preview), two-space indentation for a
// human-readable preview, trailing newline trimmed. The envelope contains no
// Go maps, so struct-order marshaling is fully deterministic — two
// structurally-equal envelopes produce byte-identical output and therefore
// equal digests; any field change changes the bytes and the digest.
//
// The node-side literal-preview serializer (internal/cloudevidence.Serialize)
// is the ONE function that produces both preview and upload bytes; it calls
// the primitives here so preview and upload can never diverge.

const digestPrefix = "sha256:"

// marshalCanonical produces the deterministic canonical serialization used by
// both digest preimages and the final upload bytes. Determinism relies on the
// envelope carrying no Go maps (struct fields marshal in declaration order).
func marshalCanonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// digest returns the "sha256:<hex>" digest of b.
func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return digestPrefix + hex.EncodeToString(sum[:])
}

// EvidencePreimage returns the canonical preimage the EvidenceContentDigest is
// computed over: e marshaled with BOTH digest fields absent. e is taken by
// value, so forcing the digest fields empty here never mutates the caller's
// envelope. This preimage is a public, testable definition — callers and
// tests can assert it contains neither digest field.
func EvidencePreimage(e Envelope) ([]byte, error) {
	e.EvidenceContentDigest = ""
	e.UploadDigest = ""
	b, err := marshalCanonical(e)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.EvidencePreimage: %w", err)
	}
	return b, nil
}

// EvidenceContentDigest returns the "sha256:<hex>" digest over EvidencePreimage(e).
// It is stable across framing changes and never covers itself (the preimage
// omits both digest fields).
func EvidenceContentDigest(e Envelope) (string, error) {
	pre, err := EvidencePreimage(e)
	if err != nil {
		return "", fmt.Errorf("cloudcontract.EvidenceContentDigest: %w", err)
	}
	return digest(pre), nil
}

// UploadBytes returns the final exact serialized bytes for e: the canonical
// serialization with EvidenceContentDigest as currently set on e and
// UploadDigest excluded (json:"-"). These are the bytes previewed and
// uploaded. e is taken by value; the returned bytes never contain an upload
// digest, so UploadDigest(UploadBytes(e)) is not self-referential.
func UploadBytes(e Envelope) ([]byte, error) {
	e.UploadDigest = "" // belt-and-braces; the field is json:"-" regardless.
	b, err := marshalCanonical(e)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.UploadBytes: %w", err)
	}
	return b, nil
}

// UploadDigest returns the "sha256:<hex>" digest over the final serialized
// bytes (the output of UploadBytes). It never covers itself because the
// UploadDigest field is never serialized.
func UploadDigest(finalBytes []byte) string {
	return digest(finalBytes)
}

// Digests carries the pair produced for one envelope serialization.
type Digests struct {
	// EvidenceContent is the digest over the canonical evidence preimage.
	EvidenceContent string
	// Upload is the digest over the final serialized (preview == upload) bytes.
	Upload string
}

// The project-digest job kind (W5, cloud-intelligence value-upgrade plan
// 2026-09-15 §4). A project digest is a weekly, server-side rollup over a
// project's already-uploaded session_enrichment results — no new content ever
// leaves a node for it. DigestSchemaVersion identifies the RESULT the job
// produces; ResultKindSessionEnrichment/ResultKindProjectDigest are the
// analysis_results.kind discriminator values (migration 0037) the store and
// the wire both use to classify a result row. They are duplicated (not
// imported) into internal/cloudserver/store as plain string constants of the
// same value — the store package deliberately never imports cloudcontract
// (CLAUDE.md #1: a domain package stays free of a validation layer it does not
// need), so the two sides agree on the literal, not on a shared symbol.
const (
	// DigestSchemaVersion identifies the project-digest RESULT schema
	// (analysis_results.result for a kind='project_digest' row).
	DigestSchemaVersion = "project_digest.v1"
	// DigestEvidenceSchemaVersion identifies the project-digest EVIDENCE
	// schema — a server-internal artifact built entirely from data the server
	// already holds (never uploaded by a node, never digested against a
	// consent receipt: it never crosses the two-digest protocol above).
	DigestEvidenceSchemaVersion = "project_digest_evidence.v1"
	// ResultKindSessionEnrichment is the default analysis_results.kind for
	// every session-enrichment row (migration 0037's column default, so every
	// pre-existing row classifies itself unchanged).
	ResultKindSessionEnrichment = "session_enrichment"
	// ResultKindProjectDigest marks a weekly project-digest result row.
	ResultKindProjectDigest = "project_digest"
)

// Project-digest result bounds (mirroring limits.go's discipline: one place
// per bound, read by Normalize).
const (
	// MaxDigestHeadlineBytes bounds the digest headline.
	MaxDigestHeadlineBytes = 160
	// MaxDigestListItemBytes bounds one theme/error-class/unfinished-thread
	// entry.
	MaxDigestListItemBytes = 200
	// MaxDigestNextSessionBytes bounds the suggested-next-session field.
	MaxDigestNextSessionBytes = 400
	// MaxDigestCostTrendBytes bounds the cost-trend sentence.
	MaxDigestCostTrendBytes = 200
	// MaxDigestThemes caps the themes list.
	MaxDigestThemes = 5
	// MaxDigestErrorClasses caps the recurring-error-classes list.
	MaxDigestErrorClasses = 5
	// MaxDigestUnfinishedThreads caps the unfinished-threads list.
	MaxDigestUnfinishedThreads = 5
	// MaxDigestSessions bounds the evidence session list a digest is built
	// from (W5: "bounded 40 sessions").
	MaxDigestSessions = 40
)

// DigestResult is the strict object a project-digest job returns — the
// weekly rollup over one project's enriched sessions: themes, cost trend,
// recurring error classes, unfinished threads, and a suggested next session.
// Model output is untrusted data; Normalize enforces enums, lengths, and
// counts exactly as Result.Normalize does.
type DigestResult struct {
	// Headline names the single most important thing that happened this week.
	Headline string `json:"headline"`
	// Themes lists up to MaxDigestThemes short phrases naming what the
	// sessions were about.
	Themes []string `json:"themes"`
	// CostTrend is one short sentence about token/cost direction, or empty
	// when the evidence does not support one.
	CostTrend string `json:"cost_trend"`
	// RecurringErrorClasses lists up to MaxDigestErrorClasses short labels for
	// failure classes that recurred across sessions.
	RecurringErrorClasses []string `json:"recurring_error_classes"`
	// UnfinishedThreads lists up to MaxDigestUnfinishedThreads short
	// descriptions of work that appears unfinished.
	UnfinishedThreads []string `json:"unfinished_threads"`
	// SuggestedNextSession is one short, concrete suggestion for what to work
	// on next, or empty when nothing is clear.
	SuggestedNextSession string `json:"suggested_next_session"`
	// SessionCount is the number of sessions the digest was built from. It is
	// SERVER-STAMPED (from the evidence, never trusted from the model), like
	// Result.SchemaVersion.
	SessionCount int `json:"session_count"`
	// PeriodStart / PeriodEnd are the digest's ISO week bounds ("YYYY-MM-DD"),
	// both server-stamped.
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	// Confidence is one of ConfidenceLow/Medium/High.
	Confidence Confidence `json:"confidence"`
	// Limitations enumerates what the digest could not observe (e.g. "titles
	// and tags only, no descriptions" for a run of title-only sessions).
	Limitations []string `json:"limitations"`
	// SchemaVersion is always DigestSchemaVersion.
	SchemaVersion string `json:"schema_version"`
}

// NormalizedDigestResult is the VALIDATED, normalized representation of a
// DigestResult (FE1), mirroring NormalizedResult's opaque-SafeText discipline.
type NormalizedDigestResult struct {
	Headline              SafeText   `json:"headline"`
	Themes                []SafeText `json:"themes"`
	CostTrend             SafeText   `json:"cost_trend"`
	RecurringErrorClasses []SafeText `json:"recurring_error_classes"`
	UnfinishedThreads     []SafeText `json:"unfinished_threads"`
	SuggestedNextSession  SafeText   `json:"suggested_next_session"`
	SessionCount          int        `json:"session_count"`
	PeriodStart           string     `json:"period_start"`
	PeriodEnd             string     `json:"period_end"`
	Confidence            Confidence `json:"confidence"`
	Limitations           []SafeText `json:"limitations"`
	SchemaVersion         string     `json:"schema_version"`
}

// isISODate reports whether s parses as a bare "YYYY-MM-DD" date.
func isISODate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// Normalize enforces every DigestResult bound and NFC-normalizes every text
// field (mirrors Result.Normalize). It does NOT perform output scrubbing
// (secret masking) — that is the executor's separate downstream contract.
func (r DigestResult) Normalize() (NormalizedDigestResult, error) {
	var out NormalizedDigestResult
	if r.SchemaVersion != DigestSchemaVersion {
		return out, fmt.Errorf("cloudcontract.DigestResult.Normalize: schema_version %q, want %q", r.SchemaVersion, DigestSchemaVersion)
	}
	out.SchemaVersion = r.SchemaVersion
	var err error
	if out.Headline, err = NormalizeText("headline", r.Headline, MaxDigestHeadlineBytes, true); err != nil {
		return NormalizedDigestResult{}, err
	}
	if out.CostTrend, err = NormalizeText("cost_trend", r.CostTrend, MaxDigestCostTrendBytes, false); err != nil {
		return NormalizedDigestResult{}, err
	}
	if out.SuggestedNextSession, err = NormalizeText("suggested_next_session", r.SuggestedNextSession, MaxDigestNextSessionBytes, false); err != nil {
		return NormalizedDigestResult{}, err
	}
	if !r.Confidence.Valid() {
		return NormalizedDigestResult{}, fmt.Errorf("cloudcontract.DigestResult.Normalize: unknown confidence %q", r.Confidence)
	}
	out.Confidence = r.Confidence
	if out.Themes, err = normalizeStringList("themes", r.Themes, MaxDigestThemes, MaxDigestListItemBytes); err != nil {
		return NormalizedDigestResult{}, err
	}
	if out.RecurringErrorClasses, err = normalizeStringList("recurring_error_classes", r.RecurringErrorClasses, MaxDigestErrorClasses, MaxDigestListItemBytes); err != nil {
		return NormalizedDigestResult{}, err
	}
	if out.UnfinishedThreads, err = normalizeStringList("unfinished_threads", r.UnfinishedThreads, MaxDigestUnfinishedThreads, MaxDigestListItemBytes); err != nil {
		return NormalizedDigestResult{}, err
	}
	if out.Limitations, err = normalizeStringList("limitations", r.Limitations, MaxLimitations, MaxLimitationBytes); err != nil {
		return NormalizedDigestResult{}, err
	}
	if !isISODate(r.PeriodStart) || !isISODate(r.PeriodEnd) {
		return NormalizedDigestResult{}, fmt.Errorf("cloudcontract.DigestResult.Normalize: period_start/period_end must be YYYY-MM-DD, got %q/%q", r.PeriodStart, r.PeriodEnd)
	}
	out.PeriodStart, out.PeriodEnd = r.PeriodStart, r.PeriodEnd
	if r.SessionCount < 0 {
		return NormalizedDigestResult{}, fmt.Errorf("cloudcontract.DigestResult.Normalize: session_count %d is negative", r.SessionCount)
	}
	out.SessionCount = r.SessionCount
	return out, nil
}

// Validate is Normalize with the normalized value discarded.
func (r DigestResult) Validate() error {
	_, err := r.Normalize()
	return err
}

// DigestSessionFact is one enriched session folded into project-digest
// evidence — built entirely from data the server already holds (the stored
// session_enrichment result + the content-free cloud_sessions.metrics
// snapshot), never a fresh node upload.
type DigestSessionFact struct {
	// CloudSessionID is the session pseudonym.
	CloudSessionID string `json:"cloud_session_id"`
	// CreatedAt is when the session's enrichment result was stored (RFC3339).
	CreatedAt string `json:"created_at"`
	// Title / Description / TaxonomyTags / Limitations are copied from the
	// session's stored (already scrubbed, already normalized)
	// session_enrichment result.
	Title        string   `json:"title"`
	Description  string   `json:"description,omitempty"`
	TaxonomyTags []string `json:"taxonomy_tags,omitempty"`
	Limitations  []string `json:"limitations,omitempty"`
	// Metrics is the session's content-free cloud_sessions.metrics snapshot
	// (migration 0037), carried through verbatim as an opaque map.
	Metrics map[string]any `json:"metrics,omitempty"`
}

// DigestEvidence is the server-internal input handed to the digest executor.
// It is built by the scheduler from data the server already holds and is
// NEVER uploaded by a node and NEVER digested against a consent receipt — it
// carries no relationship to the two-digest protocol above, because nothing
// new ever left the node to produce it.
type DigestEvidence struct {
	// SchemaVersion is always DigestEvidenceSchemaVersion.
	SchemaVersion string `json:"schema_version"`
	// ProjectPseudonym is the cloud_project_id this digest covers.
	ProjectPseudonym string `json:"project_pseudonym"`
	// PeriodStart / PeriodEnd are the ISO week bounds ("YYYY-MM-DD").
	PeriodStart string `json:"period_start"`
	PeriodEnd   string `json:"period_end"`
	// Sessions is the bounded (<= MaxDigestSessions), newest-first list of
	// enriched sessions the digest is built from.
	Sessions []DigestSessionFact `json:"sessions"`
}

// Serialize returns e's deterministic canonical bytes (the same two-space
// indented, HTML-unescaped, trailing-newline-trimmed encoding marshalCanonical
// produces for the two-digest protocol), truncating Sessions to
// MaxDigestSessions as a belt-and-suspenders bound. There is no digest pair to
// compute here — DigestEvidence never leaves the server — so this is a plain
// deterministic serializer, kept in the same style for one reason: an
// evidence-shaped payload should always serialize the same way in this
// package.
func (e DigestEvidence) Serialize() ([]byte, error) {
	if len(e.Sessions) > MaxDigestSessions {
		e.Sessions = e.Sessions[:MaxDigestSessions]
	}
	b, err := marshalCanonical(e)
	if err != nil {
		return nil, fmt.Errorf("cloudcontract.DigestEvidence.Serialize: %w", err)
	}
	return b, nil
}
