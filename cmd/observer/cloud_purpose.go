//go:build !sbo_omit_cloud_intelligence

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
)

// --- helpers: purposes, field classes, the feature set -----------------------

func parseCloudPurpose(p string) (cloudcontract.Purpose, error) {
	if strings.TrimSpace(p) == "" {
		return "", errors.New("--purpose is required (one of: " + cloudPurposeList() + ")")
	}
	purpose := cloudcontract.Purpose(strings.TrimSpace(p))
	if !purpose.Valid() {
		return "", fmt.Errorf("unknown purpose %q (one of: %s)", p, cloudPurposeList())
	}
	return purpose, nil
}

func cloudPurposeList() string {
	all := cloudcontract.AllPurposes()
	parts := make([]string, len(all))
	for i, p := range all {
		parts[i] = string(p)
	}
	return strings.Join(parts, ", ")
}

// cloudPurposeSet is the single table-driven source of truth for which
// consent purposes a session-evidence build under `purpose` discloses under
// AND must be granted for. structural_activity_insights is the BASE every
// session-evidence upload rides on (identity, structural metrics, paths —
// fields every envelope carries regardless of purpose); bounded_context_
// enrichment is ADDITIVE on top of it, unlocking the `context` excerpts, never
// a replacement for it.
//
// Every call site that used to pass a single literal purpose through to
// GrantedPurposes / a receipt's disclosed-purposes list / a pre-send grant
// check now goes through here instead, so the three can never drift apart
// again the way they did in the live bug this closes: `observer cloud consent
// --purpose bounded_context_enrichment` recorded (and disclosed under) ONLY
// bounded_context_enrichment, so `observer cloud sync` reached the server with
// an envelope carrying structural fields it had never declared a purpose for
// — a 403 out_of_purpose naming the missing structural_activity_insights,
// parking the outbox item terminal.
//
// An unsupported purpose (anything outside the two below) is rejected with an
// honest error rather than silently building an under-declared envelope —
// exactly the failure mode this function exists to close off.
func cloudPurposeSet(purpose cloudcontract.Purpose) ([]cloudcontract.Purpose, error) {
	switch purpose {
	case cloudcontract.PurposeStructuralInsights:
		return []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights}, nil
	case cloudcontract.PurposeContextEnrichment:
		return []cloudcontract.Purpose{
			cloudcontract.PurposeStructuralInsights,
			cloudcontract.PurposeContextEnrichment,
		}, nil
	default:
		return nil, fmt.Errorf(
			"purpose %q cannot build a session-evidence envelope - supported purposes are %q (structural only) "+
				"and %q (structural plus bounded excerpts, which implies and always includes the structural purpose)",
			string(purpose), string(cloudcontract.PurposeStructuralInsights), string(cloudcontract.PurposeContextEnrichment),
		)
	}
}

// cloudPurposeSetUploadable verifies every purpose in a disclosure set is one
// whose rule row actually permits a session-evidence upload
// (cloudgateway.EvidenceUploadable). FeatureSend already makes this check for
// the ONE purpose it dispatches under; a bounded upload's set carries a SECOND
// purpose (structural_activity_insights) that never went through that gate on
// its own, so this closes the same gap for every purpose cloudPurposeSet adds
// — a live grant is necessary but not sufficient if the implied purpose itself
// cannot authorize an evidence body.
func cloudPurposeSetUploadable(set []cloudcontract.Purpose) error {
	for _, p := range set {
		if ok, reason := cloudgateway.EvidenceUploadable(p); !ok {
			return fmt.Errorf("purpose %q (implied by this upload) does not authorize a session-evidence upload: %s", string(p), reason)
		}
	}
	return nil
}

// cloudPurposeStrings renders a purpose set as plain strings, in the order
// cloudPurposeSet produced them, for a wire payload that wants []string.
func cloudPurposeStrings(set []cloudcontract.Purpose) []string {
	out := make([]string, len(set))
	for i, p := range set {
		out[i] = string(p)
	}
	return out
}

// perUploadFieldClasses is the closed purpose → field-class table for a
// PER-UPLOAD receipt: exactly which preview groupings a session-evidence
// envelope built under that purpose actually contains.
//
// It fixes the same defect the standing path already fixed (see
// cloudStandingFieldClassesJSON): this used to record the PURPOSE NAME in the
// field-class slot, which is not a member of cloudcontract's closed FieldClass
// vocabulary at all — so a receipt claimed a class that does not exist and the
// consent surface could not say what the upload contained.
//
// Structural envelopes carry identity, structural metrics, per-action
// path-derived categories AND (since 2026-09-16) the narrowed first-user-prompt
// class - the single first_user_prompt excerpt every "Title only" consent
// screen names ("a structural summary and your first prompt, nothing else").
// A bounded-context envelope additionally carries the post-scrub excerpt set.
// Nothing here binds user feedback (not built on this path).
var perUploadFieldClasses = map[cloudcontract.Purpose][]string{
	cloudcontract.PurposeStructuralInsights: {
		string(cloudcontract.FieldClassIdentityLinkage),
		string(cloudcontract.FieldClassStructuralMetrics),
		string(cloudcontract.FieldClassPaths),
		string(cloudcontract.FieldClassFirstUserPrompt),
	},
	cloudcontract.PurposeContextEnrichment: {
		string(cloudcontract.FieldClassIdentityLinkage),
		string(cloudcontract.FieldClassStructuralMetrics),
		string(cloudcontract.FieldClassPaths),
		string(cloudcontract.FieldClassFirstUserPrompt),
		string(cloudcontract.FieldClassContentExcerpts),
	},
}

// cloudFieldClasses returns the field classes a per-upload receipt binds for
// a purpose (a copy of the table row; nil for a purpose with no row).
func cloudFieldClasses(p cloudcontract.Purpose) []string {
	return append([]string(nil), perUploadFieldClasses[p]...)
}

// cloudFieldClassesJSON records the field classes a per-upload receipt binds.
// A purpose with no row returns "[]" — saying nothing beats fabricating a class
// or reusing another purpose's.
func cloudFieldClassesJSON(p cloudcontract.Purpose) string {
	classes, ok := perUploadFieldClasses[p]
	if !ok {
		return "[]"
	}
	b, _ := json.Marshal(classes)
	return string(b)
}

// cloudReceiptFieldClasses decodes a receipt's field_classes_json column. A
// column that is not a JSON array (a pre-vocabulary receipt) decodes to nil,
// which every consumer reads as "no class granted" - the fail-closed reading.
func cloudReceiptFieldClasses(raw string) []string {
	var classes []string
	if err := json.Unmarshal([]byte(raw), &classes); err != nil {
		return nil
	}
	return classes
}

// cloudClassesInclude reports whether c is among the granted classes.
func cloudClassesInclude(classes []cloudcontract.FieldClass, c cloudcontract.FieldClass) bool {
	for _, g := range classes {
		if g == c {
			return true
		}
	}
	return false
}

func cloudFeatureSetJSON() string {
	b, _ := json.Marshal([]string{cloudFeatureSessionEnrichment})
	return string(b)
}
