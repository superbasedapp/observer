//go:build !sbo_omit_cloud_intelligence

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/tagtaxonomy"
)

// --- result pull and association ---------------------------------------------

// cloudPullResults pulls result pages until the cursor stops advancing,
// persisting the cursor after each page. It returns (associated,
// unassociated) counts, exactly as before the W5 value-upgrade wave added
// project digests — a thin wrapper over cloudPullResultsAndDigests that
// discards the digest count, kept so existing call sites need not know
// about digests.
func cloudPullResults(ctx context.Context, st *store.Store, host string, sess cloudgateway.ReadSession, w io.Writer) (associated, unassociated int, err error) {
	associated, unassociated, _, err = cloudPullResultsAndDigests(ctx, st, host, sess, w)
	return associated, unassociated, err
}

// cloudPullResultsAndDigests pulls result pages until the cursor stops
// advancing, persisting the cursor after each page. Bounded to avoid an
// unbounded loop. It returns (associated, unassociated, digests) counts:
// associated session-enrichment results landed a local cloud_results row;
// unassociated ones carried a cloud_session_id this device never minted
// (e.g. a result for a session enrolled elsewhere) — that is routine,
// honestly reported, and never an error; digests is every project-digest
// record stored (whether or not its project pseudonym resolved locally — a
// digest is stored regardless, see cloudAssociateDigestResult).
func cloudPullResultsAndDigests(ctx context.Context, st *store.Store, host string, sess cloudgateway.ReadSession, w io.Writer) (associated, unassociated, digests int, err error) {
	cursor, err := st.LoadCloudResultCursor(ctx, host)
	if err != nil {
		return 0, 0, 0, err
	}
	for page := 0; page < 100; page++ {
		res, err := sess.Results(ctx, cursor)
		if err != nil {
			return associated, unassociated, digests, err
		}
		for _, rec := range res.Results {
			// FE6: a deletion tombstone (or any schema-invalid record) is NOT a
			// valid enrichment. Skip it — never persist it, and never let a
			// title-less zero-value record supersede a real local result.
			if cloudResultIsTombstone(rec) {
				fmt.Fprintf(w, "  result %s: tombstone/invalid record - skipped (not stored)\n", rec.ResultID)
				continue
			}
			switch rec.Kind {
			case cloudcontract.ResultKindProjectDigest:
				ok, aerr := cloudAssociateDigestResultFromHost(ctx, st, rec, host)
				if aerr != nil {
					return associated, unassociated, digests, aerr
				}
				digests++
				if !ok {
					fmt.Fprintf(w, "  digest %s: stored, but its project is not on this device (cloud_project_id %s)\n", rec.ResultID, rec.CloudProjectID)
				}
			case "", cloudcontract.ResultKindSessionEnrichment:
				ok, aerr := cloudAssociateResult(ctx, st, rec)
				if aerr != nil {
					return associated, unassociated, digests, aerr
				}
				if ok {
					associated++
				} else {
					unassociated++
					fmt.Fprintf(w, "  result %s: no local session for this device (cloud_session_id %s)\n", rec.ResultID, rec.CloudSessionID)
				}
			default:
				// W5: a forward-compat kind this build does not understand.
				// Store nothing; a bounded, honest log line rather than
				// silently dropping it or misclassifying it as a tombstone.
				fmt.Fprintf(w, "  result %s: unknown kind %q - skipped (not stored)\n", rec.ResultID, rec.Kind)
			}
		}
		if res.NextCursor == "" || res.NextCursor == cursor {
			break
		}
		cursor = res.NextCursor
		if err := st.SaveCloudResultCursor(ctx, host, cursor); err != nil {
			return associated, unassociated, digests, err
		}
		if len(res.Results) == 0 {
			break
		}
	}
	return associated, unassociated, digests, nil
}

// cloudResultProvenanceExt carries the wire ResultProvenance fields that have
// no dedicated cloud_results column (route/prompt version, price snapshot
// version, retry count — the store keeps only model_route/prompt_hash/tokens/
// cost_usd). Per the CI-P5 mapping, these ride inside CloudResult.ResultJSON
// — the one JSON blob the store already persists per result (documented
// "allowed content, node-local") — under a reserved key, rather than adding a
// migration. cloudcontract.Result is embedded verbatim in
// cloudStoredResult so every existing consumer (the dashboard's
// json.RawMessage passthrough) still sees the unchanged product fields
// (title/taxonomy_tags/description/...) at the top level.
type cloudResultProvenanceExt struct {
	RouteVersion  int64  `json:"route_version,omitempty"`
	PromptVersion int64  `json:"prompt_version,omitempty"`
	PriceVersion  string `json:"price_version,omitempty"`
	RetryCount    int    `json:"retry_count,omitempty"`
}

// cloudStoredResult is the shape persisted in CloudResult.ResultJSON.
type cloudStoredResult struct {
	cloudcontract.Result
	CloudProvenanceExt cloudResultProvenanceExt `json:"cloud_provenance_ext"`
}

// cloudResultIsTombstone reports whether a pulled ResultRecord is a deletion
// tombstone or otherwise not a valid enrichment (FE6). The server may emit
// `{"tombstoned":true}` for a deleted result, which decodes into a zero-value
// ResultRecord (no ResultID, empty Result). A record with no server result id,
// or whose body fails its kind's cloudcontract schema Validate, must never be
// persisted or supersede a real local result. Validate is the same boundary
// the server applies before storage, so a real result always passes it.
//
// Kind-dispatched (W5, value-upgrade plan §4): a project-digest record's
// payload lives in DigestResult, not Result, so it is validated against
// DigestResult.Validate — checking Result on a digest record would always
// fail (an empty session-enrichment body) and misclassify every digest as a
// tombstone. An UNKNOWN kind is deliberately NOT a tombstone: it is a
// forward-compat record this build does not understand yet, and
// cloudPullResultsAndDigests logs and skips it explicitly (a distinct
// "unknown kind" line) rather than folding it into this bucket.
func cloudResultIsTombstone(rec cloudcontract.ResultRecord) bool {
	// FE6: the typed tombstone flag is authoritative and checked FIRST, before
	// any body inspection. A server that emits `{"tombstoned":true}` — even with
	// a nonempty ResultID and a schema-valid but stale residual `result` body —
	// must never resurrect a deleted enrichment as a live local result.
	if rec.Tombstoned {
		return true
	}
	if strings.TrimSpace(rec.ResultID) == "" {
		return true
	}
	switch rec.Kind {
	case cloudcontract.ResultKindProjectDigest:
		if rec.DigestResult == nil {
			return true
		}
		return rec.DigestResult.Validate() != nil
	case "", cloudcontract.ResultKindSessionEnrichment:
		return rec.Result.Validate() != nil
	default:
		return false
	}
}

// cloudAssociateResult dispatches a pulled ResultRecord on its Kind (W5,
// value-upgrade plan §4): "" / "session_enrichment" through the existing
// session-result path unchanged; "project_digest" through the digest path.
// Any other kind stores nothing and reports unassociated — the caller
// (cloudPullResultsAndDigests) filters an unknown kind out before ever
// reaching here in practice (it logs a distinct bounded line instead), but
// this dispatch stays complete so a direct call is never silently wrong.
func cloudAssociateResult(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord) (bool, error) {
	switch rec.Kind {
	case cloudcontract.ResultKindProjectDigest:
		return cloudAssociateDigestResult(ctx, st, rec)
	case "", cloudcontract.ResultKindSessionEnrichment:
		return cloudAssociateSessionResult(ctx, st, rec)
	default:
		return false, nil
	}
}

// cloudAssociateDigestResult resolves the local project a pulled project-
// digest record's cloud_project_id maps to, if any, and stores the digest
// regardless — a digest is small and worth keeping even when the project
// pseudonym is not (yet) recognized on this device (e.g. resolvable later
// after an identity merge). ok reports whether the local project resolved;
// it is never an error when it did not.
func cloudAssociateDigestResult(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord) (bool, error) {
	return cloudAssociateDigestResultFromHost(ctx, st, rec, "")
}

func cloudAssociateDigestResultFromHost(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord, host string) (bool, error) {
	if rec.DigestResult == nil {
		return false, fmt.Errorf("cloudAssociateResult: digest result %s carries no digest body", rec.ResultID)
	}
	if err := rec.DigestResult.Validate(); err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}
	localProjectID, ok, err := st.LookupLocalProjectByCloudPseudonym(ctx, rec.CloudProjectID)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}
	resultJSON, err := json.Marshal(rec.DigestResult)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: marshal digest: %w", err)
	}
	// The global result cursor is monotonic across accounts within one estate.
	// AccountCursor is deliberately not used: its values are incomparable
	// across accounts. Empty host (legacy direct callers) uses server time.
	stream := ""
	if host != "" {
		stream = strings.ToLower(host) + "/global-v1"
	}
	if uerr := st.UpsertCloudDigest(ctx, store.CloudDigest{
		ID:             rec.ResultID,
		ServerSequence: rec.Cursor,
		ServerStream:   stream,
		CloudProjectID: rec.CloudProjectID,
		LocalProjectID: localProjectID,
		PeriodStart:    rec.PeriodStart,
		PeriodEnd:      rec.PeriodEnd,
		SchemaVersion:  rec.SchemaVersion,
		ResultJSON:     string(resultJSON),
		ReceivedAt:     rec.ReceivedAt,
	}); uerr != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", uerr)
	}
	return ok, nil
}

// cloudAssociateSessionResult reverse-looks-up the local session a pulled
// ResultRecord's cloud_session_id maps to and, on a hit, upserts it as a
// local CloudResult. It uses the wire's ResultID as the stored row's id so a
// re-pull of the same result (the cursor didn't advance past it, or a retry)
// updates the same row in place rather than opening a new supersede chain.
// ok=false (a pseudonym this device never minted) is routine and not an
// error; the caller counts and reports it.
func cloudAssociateSessionResult(ctx context.Context, st *store.Store, rec cloudcontract.ResultRecord) (bool, error) {
	localSessionID, ok, err := st.LookupLocalSessionByCloudPseudonym(ctx, rec.CloudSessionID)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}
	if !ok {
		return false, nil
	}

	stored := cloudStoredResult{
		Result: rec.Result,
		CloudProvenanceExt: cloudResultProvenanceExt{
			RouteVersion:  rec.Provenance.RouteVersion,
			PromptVersion: rec.Provenance.PromptVersion,
			PriceVersion:  rec.Provenance.PriceVersion,
			RetryCount:    rec.Provenance.RetryCount,
		},
	}
	resultJSON, err := json.Marshal(stored)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: marshal result: %w", err)
	}

	// A result already stored is a re-pull (the cursor is reset at sign-in and
	// sign-out): refresh the row in place but do not re-merge its tags, which
	// the user may have removed since the first pull.
	repull, err := st.HasCloudResult(ctx, rec.ResultID)
	if err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}

	if _, err := st.UpsertCloudResult(ctx, store.CloudResult{
		ID:            rec.ResultID,
		SessionID:     localSessionID,
		SchemaVersion: rec.SchemaVersion,
		ResultJSON:    string(resultJSON),
		Provenance: store.CloudResultProvenance{
			ModelRoute: rec.Provenance.ModelRouteID,
			PromptHash: rec.Provenance.PromptHash,
			Tokens:     int(rec.Provenance.TokensIn + rec.Provenance.TokensOut),
			CostUSD:    rec.Provenance.CostUSD,
		},
		ReceivedAt: rec.ReceivedAt,
	}); err != nil {
		return false, fmt.Errorf("cloudAssociateResult: %w", err)
	}

	// Best-effort auto-merge of the enrichment's controlled-vocabulary
	// taxonomy tags into the session's own user-facing tag set
	// (session_tags, migration 075). This is a convenience layer over
	// user-owned classification data, not part of result association: a
	// merge failure must never fail this call (which would incorrectly
	// report the pulled result as unassociated) or abort the wider pull.
	// store.ErrTooManyTags (the session already carries a full tag set) is
	// the routine, expected rejection; any other MutateSessionTags error is
	// equally non-fatal here — both are swallowed rather than propagated.
	//
	// Only STANDARD slugs merge. taxonomy_tags is constrained server-side by a
	// strict json_schema enum built from tagtaxonomy.Slugs(), but a wire value
	// is still untrusted input on this side of the boundary: an older server, a
	// vocabulary that has since shrunk, or a schema bypass could hand us a slug
	// that is not in the curated set, and quietly writing it into the user's own
	// session_tags would corrupt their tag space with an unexplained label. Off
	// vocabulary slugs are DROPPED here — they remain visible on the result
	// itself, which is where an un-vocabularized suggestion belongs.
	if merged := cloudStandardTaxonomyTags(rec.Result.TaxonomyTags); !repull && len(merged) > 0 {
		if mErr := st.MutateSessionTags(ctx, localSessionID, merged, nil); mErr != nil {
			_ = mErr // best-effort: see comment above.
		}
	}
	return true, nil
}

// cloudStandardTaxonomyTags filters a pulled result's taxonomy tags down to the
// curated vocabulary, preserving order and dropping duplicates. It is separated
// from cloudAssociateResult so the rule is unit-testable without a database.
func cloudStandardTaxonomyTags(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, tag := range in {
		slug := strings.TrimSpace(tag)
		if slug == "" || seen[slug] || !tagtaxonomy.IsStandard(slug) {
			continue
		}
		seen[slug] = true
		out = append(out, slug)
	}
	return out
}
