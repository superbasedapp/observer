package personalmig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// ResultKindSessionEnrichment is the analysis_results kind a session result
// carries (cloud 0037); a project digest is a rollup over sessions and has no
// session to land on.
const ResultKindSessionEnrichment = cloudcontract.ResultKindSessionEnrichment

// Revision is one result_revisions row: a partial correction.
type Revision struct {
	Seq        int
	Correction []byte
}

// ResultFacts is one analysis_results row with its corrections, read by the
// store.
type ResultFacts struct {
	ID   string
	Kind string
	// CloudSessionID is the node-minted pseudonym of the result's session,
	// empty when the result has none.
	CloudSessionID string
	CreatedAt      time.Time
	Superseded     bool
	// Tombstoned is true when the body is the deletion tombstone marker.
	Tombstoned bool
	// Result is the stored AI original (analysis_results.result).
	Result    []byte
	Revisions []Revision
}

// Skip reasons of the result table.
const (
	ResultSkipKind       = "not_session_enrichment"
	ResultSkipTombstoned = "tombstoned"
	ResultSkipSuperseded = "superseded"
	ResultSkipNoSession  = "no_session"
	ResultSkipInvalid    = "invalid"
)

// resultRule is one row of the result table: the result is not exported,
// for the reason, when skip is true.
type resultRule struct {
	reason string
	skip   func(ResultFacts) bool
}

// resultRules is walked top-down; a result no row skips is exported (if its
// effective result is valid).
var resultRules = []resultRule{
	{ResultSkipKind, func(r ResultFacts) bool { return r.Kind != ResultKindSessionEnrichment }},
	{ResultSkipTombstoned, func(r ResultFacts) bool { return r.Tombstoned }},
	{ResultSkipSuperseded, func(r ResultFacts) bool { return r.Superseded }},
	{ResultSkipNoSession, func(r ResultFacts) bool { return strings.TrimSpace(r.CloudSessionID) == "" }},
}

// Export is the outcome of BuildExport.
type Export struct {
	Records []cloudcontract.PersonalImportRecord
	// Total is the number of results considered.
	Total int
	// Skipped counts results not exported, by reason.
	Skipped map[string]int
}

// SkippedTotal is the number of results not exported.
func (e Export) SkippedTotal() int {
	n := 0
	for _, c := range e.Skipped {
		n += c
	}
	return n
}

// BuildExport turns an account's results into bundle records: each result
// the table keeps, with its effective result, in (created_at, id) order so
// the bundle's bytes (and so its digest) are the same on every run over the
// same data. A result whose effective result does not validate is counted as
// invalid, never exported.
func BuildExport(rows []ResultFacts) (Export, error) {
	if len(rows) > cloudcontract.MaxPersonalImportRecords {
		return Export{}, fmt.Errorf("personalmig.BuildExport: %d results exceeds the bundle bound %d", len(rows), cloudcontract.MaxPersonalImportRecords)
	}
	sorted := append([]ResultFacts(nil), rows...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
		}
		return sorted[i].ID < sorted[j].ID
	})
	out := Export{Total: len(sorted), Skipped: map[string]int{}}
	for _, r := range sorted {
		if why := skipReason(r); why != "" {
			out.Skipped[why]++
			continue
		}
		eff, corrected, err := EffectiveResult(r.Result, r.Revisions)
		if err != nil {
			out.Skipped[ResultSkipInvalid]++
			continue
		}
		rec := cloudcontract.PersonalImportRecord{
			ImportRef:      cloudcontract.PersonalImportRefPrefix + r.ID,
			CloudSessionID: r.CloudSessionID,
			CreatedAt:      r.CreatedAt.UTC().Format(time.RFC3339),
			Corrected:      corrected,
			Result:         eff,
		}
		if err := rec.Validate(); err != nil {
			out.Skipped[ResultSkipInvalid]++
			continue
		}
		out.Records = append(out.Records, rec)
	}
	return out, nil
}

func skipReason(r ResultFacts) string {
	for _, rule := range resultRules {
		if rule.skip(r) {
			return rule.reason
		}
	}
	return ""
}

// EffectiveResult is the AI original with every user correction applied in
// revision order: a correction is partial, so each present field replaces the
// effective value and an absent one leaves it (the latest explicit user act
// wins, operator ruling R6). corrected reports whether any revision applied.
func EffectiveResult(original []byte, revisions []Revision) (cloudcontract.Result, bool, error) {
	var res cloudcontract.Result
	if err := json.Unmarshal(original, &res); err != nil {
		return cloudcontract.Result{}, false, fmt.Errorf("personalmig.EffectiveResult: original: %w", err)
	}
	revs := append([]Revision(nil), revisions...)
	sort.SliceStable(revs, func(i, j int) bool { return revs[i].Seq < revs[j].Seq })
	corrected := false
	for _, rv := range revs {
		var c cloudcontract.ResultCorrection
		dec := json.NewDecoder(bytes.NewReader(rv.Correction))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return cloudcontract.Result{}, false, fmt.Errorf("personalmig.EffectiveResult: revision %d: %w", rv.Seq, err)
		}
		if !c.HasAny() {
			continue
		}
		applyCorrection(&res, c)
		corrected = true
	}
	return res, corrected, nil
}

// applyCorrection writes c's present fields over r.
func applyCorrection(r *cloudcontract.Result, c cloudcontract.ResultCorrection) {
	if c.Title != nil {
		r.Title = *c.Title
	}
	if c.Description != nil {
		r.Description = *c.Description
	}
	if c.TaxonomyTags != nil {
		r.TaxonomyTags = append([]string{}, (*c.TaxonomyTags)...)
	}
	if c.SuggestedTags != nil {
		r.SuggestedTags = append([]string{}, (*c.SuggestedTags)...)
	}
}

// NewManifest is the manifest of a bundle whose records encode to sha with
// count lines.
func NewManifest(accountID string, org PersonalOrg, ownerSubject string, count int, sha string, now time.Time) cloudcontract.PersonalImportManifest {
	return cloudcontract.PersonalImportManifest{
		Format:        cloudcontract.PersonalImportFormat,
		AccountID:     accountID,
		OrgID:         org.OrgID,
		OrgSlug:       org.Slug,
		OwnerSubject:  ownerSubject,
		RecordCount:   count,
		RecordsSHA256: sha,
		CreatedAt:     now.UTC().Format(time.RFC3339),
	}
}

// BundleAction is what to do with a bundle directory.
type BundleAction string

// The bundle actions.
const (
	// BundleWrite writes the bundle (none there, or a --replace).
	BundleWrite BundleAction = "write"
	// BundleKeep leaves the bundle there: it is the same bundle.
	BundleKeep BundleAction = "keep"
	// BundleRefuse refuses: a different bundle is there and no --replace.
	BundleRefuse BundleAction = "refuse"
)

// ExistingBundle is what the command found in an org's bundle directory.
type ExistingBundle struct {
	// Found is true when a manifest.json was there.
	Found bool
	// Manifest is the manifest found (zero when Found is false).
	Manifest cloudcontract.PersonalImportManifest
	// RecordsSHA256 is the digest of the results.ndjson found, "" when it is
	// missing.
	RecordsSHA256 string
}

// bundleRule is one row of the bundle table.
type bundleRule struct {
	match  func(e ExistingBundle, org, sha string, replace bool) bool
	action BundleAction
}

// sameBundle: the manifest names the same org and digest, and the records
// file there has that digest.
func sameBundle(e ExistingBundle, org, sha string) bool {
	return strings.EqualFold(e.Manifest.RecordsSHA256, sha) && e.Manifest.OrgID == org &&
		strings.EqualFold(e.RecordsSHA256, sha)
}

// bundleRules is walked top-down; the first matching row decides.
var bundleRules = []bundleRule{
	{func(e ExistingBundle, _, _ string, _ bool) bool { return !e.Found }, BundleWrite},
	{func(e ExistingBundle, org, sha string, _ bool) bool { return sameBundle(e, org, sha) }, BundleKeep},
	{func(_ ExistingBundle, _, _ string, replace bool) bool { return replace }, BundleWrite},
	{func(ExistingBundle, string, string, bool) bool { return true }, BundleRefuse},
}

// DecideBundle returns what to do with org's bundle directory for records
// digesting to sha: write when none is there, keep the same bundle (a rerun
// is a no-op), and refuse a different one unless replace.
func DecideBundle(e ExistingBundle, org, sha string, replace bool) BundleAction {
	for _, r := range bundleRules {
		if r.match(e, org, sha, replace) {
			return r.action
		}
	}
	return BundleRefuse
}

// receiptRule is one row of the receipt table: the receipt does not prove the
// bundle is on the tenant, for the reason, when gap is true.
type receiptRule struct {
	reason string
	gap    func(m cloudcontract.PersonalImportManifest, r cloudcontract.PersonalImportReceipt) bool
}

var receiptRules = []receiptRule{
	{"receipt format is not " + cloudcontract.PersonalImportFormat, func(_ cloudcontract.PersonalImportManifest, r cloudcontract.PersonalImportReceipt) bool {
		return r.Format != cloudcontract.PersonalImportFormat
	}},
	{"receipt names another org", func(m cloudcontract.PersonalImportManifest, r cloudcontract.PersonalImportReceipt) bool {
		return r.OrgID != m.OrgID
	}},
	{"receipt names another bundle digest", func(m cloudcontract.PersonalImportManifest, r cloudcontract.PersonalImportReceipt) bool {
		return !strings.EqualFold(r.RecordsSHA256, m.RecordsSHA256)
	}},
	{"receipt record count differs from the manifest", func(m cloudcontract.PersonalImportManifest, r cloudcontract.PersonalImportReceipt) bool {
		return r.RecordCount != m.RecordCount
	}},
	{"not every record is present on the tenant", func(m cloudcontract.PersonalImportManifest, r cloudcontract.PersonalImportReceipt) bool {
		return r.Present != m.RecordCount
	}},
}

// ReceiptGap returns why r does not prove m's bundle is on the tenant, or ""
// when it does (exactly when r.Complete(m)).
func ReceiptGap(m cloudcontract.PersonalImportManifest, r cloudcontract.PersonalImportReceipt) string {
	for _, rule := range receiptRules {
		if rule.gap(m, r) {
			return rule.reason
		}
	}
	return ""
}
