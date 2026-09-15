package cloudcontract

import (
	"fmt"
	"strings"
)

// ResultCorrection is the "session_enrichment.correction.v1-candidate" body of
// PATCH /v1/results/{id}/correction (divergence-remediation plan §3 W6c;
// operator ruling R6). It is a PARTIAL result: only the fields the user changed
// are present (a nil pointer / absent list = "leave this field as it is"), so a
// correction that only fixes the title carries only Title. At least one field
// must be present — an empty correction is rejected.
//
// The distinction between an ABSENT field and a present-but-empty one is
// deliberate and carried by the pointer/`omitempty` shape: a nil Title means
// "do not touch the title"; a present Title must be a non-empty SafeText (you
// correct a title TO something, you do not blank it). Description may be present
// and empty (clearing a description is a legitimate correction); tag lists may
// be present and empty (the user cleared their tags).
type ResultCorrection struct {
	// Title, when non-nil, replaces the effective title. A present title must be
	// non-empty.
	Title *string `json:"title,omitempty"`
	// Description, when non-nil, replaces the effective description. May be empty.
	Description *string `json:"description,omitempty"`
	// TaxonomyTags, when non-nil, replaces the taxonomy-tag list (empty clears).
	TaxonomyTags *[]string `json:"taxonomy_tags,omitempty"`
	// SuggestedTags, when non-nil, replaces the suggested-tag list (empty clears).
	SuggestedTags *[]string `json:"suggested_tags,omitempty"`
}

// NormalizedCorrection is the VALIDATED correction: every present text field is
// an opaque SafeText (so no downstream holder can substitute un-normalized
// bytes), and it marshals wire-identically to ResultCorrection (absent fields
// stay absent, SafeText emits a plain JSON string). The server stores THIS —
// the normalized form — as the revision body, never the raw request bytes.
type NormalizedCorrection struct {
	Title         *SafeText   `json:"title,omitempty"`
	Description   *SafeText   `json:"description,omitempty"`
	TaxonomyTags  *[]SafeText `json:"taxonomy_tags,omitempty"`
	SuggestedTags *[]SafeText `json:"suggested_tags,omitempty"`
}

// HasAny reports whether the correction touches at least one field.
func (c ResultCorrection) HasAny() bool {
	return c.Title != nil || c.Description != nil || c.TaxonomyTags != nil || c.SuggestedTags != nil
}

// Normalize validates and normalizes every PRESENT field (Sol SC7 / FE1: reject
// C0/C1/ANSI/OSC controls, bidi controls, invalid UTF-8; enforce NFC-normalized
// byte/rune bounds and the same list caps a full Result uses), returning the
// normalized value with opaque SafeText fields. An empty correction (no field
// present) is an error — a correction must change something. It does NOT scrub
// (secret masking) — the correction is user-authored text on the write path,
// scrubbing is the model-output contract; the same NormalizeText wall that
// guards a model result guards a user edit here.
func (c ResultCorrection) Normalize() (NormalizedCorrection, error) {
	var out NormalizedCorrection
	if !c.HasAny() {
		return out, fmt.Errorf("cloudcontract.ResultCorrection.Normalize: empty correction (no field present)")
	}
	if c.Title != nil {
		st, err := NormalizeText("title", *c.Title, MaxTitleBytes, true)
		if err != nil {
			return NormalizedCorrection{}, err
		}
		out.Title = &st
	}
	if c.Description != nil {
		st, err := NormalizeText("description", *c.Description, MaxDescriptionBytes, false)
		if err != nil {
			return NormalizedCorrection{}, err
		}
		out.Description = &st
	}
	if c.TaxonomyTags != nil {
		list, err := normalizeStringList("taxonomy_tags", *c.TaxonomyTags, MaxTaxonomyTags, MaxTagBytes)
		if err != nil {
			return NormalizedCorrection{}, err
		}
		if list == nil {
			list = []SafeText{}
		}
		out.TaxonomyTags = &list
	}
	if c.SuggestedTags != nil {
		list, err := normalizeStringList("suggested_tags", *c.SuggestedTags, MaxSuggestedTags, MaxTagBytes)
		if err != nil {
			return NormalizedCorrection{}, err
		}
		if list == nil {
			list = []SafeText{}
		}
		out.SuggestedTags = &list
	}
	return out, nil
}

// Validate reports whether c satisfies every bound; it is Normalize with the
// value discarded.
func (c ResultCorrection) Validate() error {
	_, err := c.Normalize()
	return err
}

// ResultETag is the strong HTTP entity-tag for a result at a given correction
// sequence: `"<result_id>.<correction_seq>"`. correction_seq is 0 for the
// pristine AI original and bumps by one on every accepted correction, so the
// ETag changes iff the effective result changed — which is exactly what
// If-Match needs to make a correction fail-closed against a concurrent editor.
func ResultETag(resultID string, correctionSeq int64) string {
	return fmt.Sprintf("%q", resultID+"."+fmt.Sprintf("%d", correctionSeq)) //nolint:gocritic // strconv is off the cloudcontract import allowlist; fmt renders the ETag.
}

// ParseResultETag parses a strong ResultETag back into its result id and
// correction sequence. It accepts the exact quoted form ResultETag emits;
// a weak validator (`W/"..."`), a missing sequence, or a non-numeric sequence
// is rejected (ok=false). It does not accept `*` — a caller wanting the
// wildcard-If-Match semantics handles that before calling.
func ParseResultETag(etag string) (resultID string, correctionSeq int64, ok bool) {
	s := strings.TrimSpace(etag)
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", 0, false
	}
	inner := s[1 : len(s)-1]
	dot := strings.LastIndexByte(inner, '.')
	if dot <= 0 || dot == len(inner)-1 {
		return "", 0, false
	}
	seq, ok := parseNonNegInt64(inner[dot+1:])
	if !ok {
		return "", 0, false
	}
	return inner[:dot], seq, true
}

// parseNonNegInt64 parses a non-negative decimal without strconv (off the
// cloudcontract import allowlist). The <=18-digit bound keeps the accumulation
// well inside int64 with no overflow check needed.
func parseNonNegInt64(s string) (int64, bool) {
	if s == "" || len(s) > 18 {
		return 0, false
	}
	var v int64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + int64(c-'0')
	}
	return v, true
}
