package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// intelcache.go is the ONE store seam over the node-local org_intel_cache table
// (agent migration 112, org-served-cloud-intelligence plan §1.3/§2.4/§3.5, W3).
//
// It caches the ORG server's own derived per-session enrichment results as the
// node last pulled them over GET /api/agent/intel/results — the org's product
// coming BACK, not node data going out. The node dashboard renders from here.
//
// NODE-LOCAL by table name: org_intel_cache never enters the org-push wire.
// Its name is in the forbidden set walked by tests/invariant/privacy_test.go
// (INV-3), so internal/store/orgpush.go must never reference it. This file is
// deliberately the only place the table name appears in internal/store.

// OrgIntelResult is the node-local mirror of one org-derived enrichment result.
// The list fields (TaxonomyTags / SuggestedTags / Limitations) are stored as
// JSON-encoded TEXT. FetchedAt is the node's own pull time.
type OrgIntelResult struct {
	// OrgID binds the row to the enrolment it was pulled under (finding 6). The
	// node drops foreign-org rows on an identity change; an empty value is a
	// pre-114 / unbound row and is treated as foreign.
	OrgID         string
	SessionID     string
	JobID         string
	Title         string
	TaxonomyTags  []string
	SuggestedTags []string
	Description   string
	Confidence    string
	Limitations   []string
	// The five NARRATIVE lists the org rail derives (agent migration 124): what
	// the session did, whether the stated plans landed, what issues were found,
	// what failed, what to do next. Stored one JSON array per NULLABLE column;
	// an empty list is stored as NULL, so a row cached before 124 and a result
	// that carried no narrative read back the same way — as absence.
	WorkDone         []string
	PlansImplemented []string
	IssuesFound      []string
	Failures         []string
	NextSteps        []string
	SchemaVersion    string
	FetchedAt        time.Time
}

// ErrOrgIntelResultUnsafe is returned by UpsertOrgIntelResult when a text field
// of an incoming result fails the SafeText rule (a control, bidi, ANSI, or
// invalid-UTF-8 sequence, or over a field cap). The whole ROW is rejected
// (never silently truncated, INV-6) so the caller can hold the pull cursor back
// and log the reason; the server is the authority that should never emit such a
// row, so this is a defence-in-depth backstop, not a normal path.
var ErrOrgIntelResultUnsafe = errors.New("store.UpsertOrgIntelResult: result text failed the SafeText rule")

// validateIntelText runs one text field through the SAME SafeText rule the org
// server enforces on write (cloudcontract.NormalizeText: UTF-8 / control / bidi
// / ANSI / NFC + the field byte cap), wrapping any violation as
// ErrOrgIntelResultUnsafe. Empty is allowed (results carry optional fields).
func validateIntelText(field, s string, maxBytes int) error {
	if _, err := cloudcontract.NormalizeText(field, s, maxBytes, false); err != nil {
		return fmt.Errorf("%w: %w", ErrOrgIntelResultUnsafe, err)
	}
	return nil
}

// validateIntelList runs every element of a list field through the SafeText
// rule, rejecting the whole row on the first violation.
func validateIntelList(field string, list []string, maxBytes int) error {
	for i, v := range list {
		if err := validateIntelText(fmt.Sprintf("%s[%d]", field, i), v, maxBytes); err != nil {
			return err
		}
	}
	return nil
}

// validateIntelResult runs every prose/list/enum field of an incoming result
// through the SafeText rule before persistence (INV-6 on the NODE writer too,
// finding 8). It is the node-side mirror of intelstore.WriteResult's Normalize
// pass; consistent with the server it REJECTS the row rather than truncating.
func validateIntelResult(r OrgIntelResult) error {
	if err := validateIntelText("title", r.Title, cloudcontract.MaxTitleBytes); err != nil {
		return err
	}
	if err := validateIntelText("description", r.Description, cloudcontract.MaxDescriptionBytes); err != nil {
		return err
	}
	// confidence and schema_version are short controlled strings; a modest cap
	// still runs them through the control/bidi/ANSI rejection.
	if err := validateIntelText("confidence", r.Confidence, cloudcontract.MaxTagBytes); err != nil {
		return err
	}
	if err := validateIntelText("schema_version", r.SchemaVersion, cloudcontract.MaxTagBytes); err != nil {
		return err
	}
	if err := validateIntelList("taxonomy_tags", r.TaxonomyTags, cloudcontract.MaxTagBytes); err != nil {
		return err
	}
	if err := validateIntelList("suggested_tags", r.SuggestedTags, cloudcontract.MaxTagBytes); err != nil {
		return err
	}
	if err := validateIntelList("limitations", r.Limitations, cloudcontract.MaxLimitationBytes); err != nil {
		return err
	}
	// The five narrative lists follow the SAME rule as every other prose field:
	// each item through NormalizeText at the narrative byte cap, and the whole
	// ROW rejected on the first violation rather than truncated (INV-6).
	for _, n := range []struct {
		field string
		list  []string
	}{
		{"work_done", r.WorkDone},
		{"plans_implemented", r.PlansImplemented},
		{"issues_found", r.IssuesFound},
		{"failures", r.Failures},
		{"next_steps", r.NextSteps},
	} {
		if err := validateIntelList(n.field, n.list, cloudcontract.MaxNarrativeItemBytes); err != nil {
			return err
		}
	}
	return nil
}

// UpsertOrgIntelResult stores (or replaces) one result, keyed on
// (session_id, job_id). A later pull of the same job overwrites the row in
// place — the server is the authority on the result's content, and re-pulling
// is idempotent (which is what lets the node re-page from the start after a
// restart without duplicating rows). FetchedAt defaults to now when zero.
func (s *Store) UpsertOrgIntelResult(ctx context.Context, r OrgIntelResult) error {
	if r.SessionID == "" {
		return errors.New("store.UpsertOrgIntelResult: session id is required")
	}
	if r.JobID == "" {
		return errors.New("store.UpsertOrgIntelResult: job id is required")
	}
	// INV-6 on the node writer (finding 8): reject a hostile result before any
	// SQL. The server already SafeText-normalizes on write, so a rejection here
	// is a defence-in-depth backstop against a compromised/buggy server.
	if err := validateIntelResult(r); err != nil {
		return err
	}
	if r.FetchedAt.IsZero() {
		r.FetchedAt = time.Now().UTC()
	}
	taxonomy, err := marshalIntelList(r.TaxonomyTags)
	if err != nil {
		return fmt.Errorf("store.UpsertOrgIntelResult: taxonomy_tags: %w", err)
	}
	suggested, err := marshalIntelList(r.SuggestedTags)
	if err != nil {
		return fmt.Errorf("store.UpsertOrgIntelResult: suggested_tags: %w", err)
	}
	limitations, err := marshalIntelList(r.Limitations)
	if err != nil {
		return fmt.Errorf("store.UpsertOrgIntelResult: limitations: %w", err)
	}
	// The five narrative columns are NULLABLE and store NULL for an empty list
	// (agent migration 124), so a row the org sent with no narrative and a row
	// cached before 124 are indistinguishable — both are absence.
	narrative := make([]any, 0, 5)
	for _, n := range []struct {
		field string
		list  []string
	}{
		{"work_done", r.WorkDone},
		{"plans_implemented", r.PlansImplemented},
		{"issues_found", r.IssuesFound},
		{"failures", r.Failures},
		{"next_steps", r.NextSteps},
	} {
		v, merr := marshalIntelNarrative(n.list)
		if merr != nil {
			return fmt.Errorf("store.UpsertOrgIntelResult: %s: %w", n.field, merr)
		}
		narrative = append(narrative, v)
	}
	args := []any{
		r.OrgID, r.SessionID, r.JobID, r.Title, taxonomy, suggested, r.Description,
		r.Confidence, limitations, r.SchemaVersion, cloudFormatTime(r.FetchedAt),
	}
	args = append(args, narrative...)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO org_intel_cache
		  (org_id, session_id, job_id, title, taxonomy_tags, suggested_tags, description,
		   confidence, limitations, schema_version, fetched_at,
		   work_done, plans_implemented, issues_found, failures, next_steps)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id, job_id) DO UPDATE SET
		  org_id            = excluded.org_id,
		  title             = excluded.title,
		  taxonomy_tags     = excluded.taxonomy_tags,
		  suggested_tags    = excluded.suggested_tags,
		  description       = excluded.description,
		  confidence        = excluded.confidence,
		  limitations       = excluded.limitations,
		  schema_version    = excluded.schema_version,
		  fetched_at        = excluded.fetched_at,
		  work_done         = excluded.work_done,
		  plans_implemented = excluded.plans_implemented,
		  issues_found      = excluded.issues_found,
		  failures          = excluded.failures,
		  next_steps        = excluded.next_steps`, args...)
	if err != nil {
		return fmt.Errorf("store.UpsertOrgIntelResult: %w", err)
	}
	return nil
}

// OrgIntelResultsForSession returns every cached result for one session bound
// to the node's CURRENT enrolment org (finding 7), newest pull first. A session
// with no results returns an empty slice, never an error — absence is the
// ordinary state.
//
// The org filter is defence in depth against a foreign-org row lingering past
// an identity change: when the node IS enrolled, only rows stamped with the live
// enrolment's org id render; when it is NOT enrolled (the org_enrolment
// subquery is NULL — including every unit test that seeds cache rows without an
// enrolment), the COALESCE falls back to the row's own org_id, so the filter is
// a no-op and every cached row still reads back. A de-enrolled node has no cache
// rows anyway (DeleteEnrolment clears the table), so "not enrolled" never
// discloses a departed org's intel.
func (s *Store) OrgIntelResultsForSession(ctx context.Context, sessionID string) ([]OrgIntelResult, error) {
	// The five narrative columns are NULLABLE (agent migration 124); COALESCE
	// resolves a pre-124 row to the canonical empty array at the boundary so
	// nothing below branches on NULL.
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, job_id, title, taxonomy_tags, suggested_tags, description,
		       confidence, limitations, schema_version, fetched_at,
		       COALESCE(work_done,'[]'), COALESCE(plans_implemented,'[]'),
		       COALESCE(issues_found,'[]'), COALESCE(failures,'[]'), COALESCE(next_steps,'[]')
		  FROM org_intel_cache
		 WHERE session_id = ?
		   AND org_id = COALESCE((SELECT org_id FROM org_enrolment WHERE id = 1), org_id)
		 ORDER BY fetched_at DESC, job_id DESC`, sessionID)
	if err != nil {
		return nil, fmt.Errorf("store.OrgIntelResultsForSession: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []OrgIntelResult
	for rows.Next() {
		var (
			taxonomy, suggested, limitations string
			fetched                          string
			workDone, plans, issues          string
			failures, nextSteps              string
		)
		res := OrgIntelResult{}
		if err := rows.Scan(&res.SessionID, &res.JobID, &res.Title, &taxonomy,
			&suggested, &res.Description, &res.Confidence, &limitations,
			&res.SchemaVersion, &fetched,
			&workDone, &plans, &issues, &failures, &nextSteps); err != nil {
			return nil, fmt.Errorf("store.OrgIntelResultsForSession: scan: %w", err)
		}
		res.TaxonomyTags = unmarshalIntelList(taxonomy)
		res.SuggestedTags = unmarshalIntelList(suggested)
		res.Limitations = unmarshalIntelList(limitations)
		res.WorkDone = unmarshalIntelList(workDone)
		res.PlansImplemented = unmarshalIntelList(plans)
		res.IssuesFound = unmarshalIntelList(issues)
		res.Failures = unmarshalIntelList(failures)
		res.NextSteps = unmarshalIntelList(nextSteps)
		if t, perr := time.Parse(time.RFC3339Nano, fetched); perr == nil {
			res.FetchedAt = t
		}
		out = append(out, res)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.OrgIntelResultsForSession: rows: %w", err)
	}
	return out, nil
}

// DeleteForeignOrgIntelResults removes every cached result NOT bound to keepOrgID
// (finding 6). The node calls it when the live enrolment's org id no longer
// matches the one the in-memory cursor belongs to — a re-enrol, possibly to a
// different org — so org A's results can never render under org B. A pre-114
// row (org_id = ”) is foreign to any non-empty keepOrgID and is dropped.
func (s *Store) DeleteForeignOrgIntelResults(ctx context.Context, keepOrgID string) error {
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM org_intel_cache WHERE org_id IS NULL OR org_id <> ?`, keepOrgID); err != nil {
		return fmt.Errorf("store.DeleteForeignOrgIntelResults: %w", err)
	}
	return nil
}

// ClearOrgIntelCache removes every cached result. DeleteEnrolment calls it so a
// departed org's derived intel does not outlive the enrolment that produced it
// (finding 6), matching the announcement/routing-policy caches it clears beside.
func (s *Store) ClearOrgIntelCache(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM org_intel_cache`); err != nil {
		return fmt.Errorf("store.ClearOrgIntelCache: %w", err)
	}
	return nil
}

// PruneOrgIntelCache sweeps the node-local result cache (finding 7). It removes:
//
//   - ORPHANS: rows whose session is no longer present locally. The migration's
//     AFTER DELETE trigger covers an explicit single-session delete, but a bulk
//     retention pass on `sessions`, a foreign import, or a result pulled for a
//     session the node never held locally can all leave an orphan the trigger
//     never saw.
//   - AGED rows: when retentionDays > 0, rows older than the window
//     (fetched_at < now-retentionDays), so a stale AI summary does not outlive
//     the local retention horizon. retentionDays <= 0 means keep-forever and
//     prunes orphans only.
//
// It is wired into the existing daemon retention pass (cmd/observer/prune.go::
// runRetention), NOT a second scheduler. A repeated pull does not resurrect a
// pruned row: the pull cursor has advanced past the aged rows' production time,
// and an orphan's session is gone so nothing re-references it.
func (s *Store) PruneOrgIntelCache(ctx context.Context, retentionDays int, now time.Time) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM org_intel_cache
		  WHERE session_id NOT IN (SELECT id FROM sessions)`)
	if err != nil {
		return 0, fmt.Errorf("store.PruneOrgIntelCache: orphans: %w", err)
	}
	orphans, _ := res.RowsAffected()
	var aged int64
	if retentionDays > 0 {
		cutoff := now.UTC().AddDate(0, 0, -retentionDays)
		ares, aerr := s.db.ExecContext(ctx,
			`DELETE FROM org_intel_cache WHERE fetched_at < ?`, cloudFormatTime(cutoff))
		if aerr != nil {
			return int(orphans), fmt.Errorf("store.PruneOrgIntelCache: aged: %w", aerr)
		}
		aged, _ = ares.RowsAffected()
	}
	return int(orphans + aged), nil
}

// marshalIntelList JSON-encodes a string list for the TEXT columns. A nil/empty
// list encodes as "[]" so the column default and a round-trip agree.
func marshalIntelList(v []string) (string, error) {
	if len(v) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// marshalIntelNarrative encodes one narrative list for its NULLABLE column
// (agent migration 124). An empty or nil list stores SQL NULL — returned as an
// untyped nil — rather than the "[]" the four older list columns use, so a row
// with no narrative and a row cached before 124 have the same representation.
func marshalIntelNarrative(v []string) (any, error) {
	if len(v) == 0 {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return string(b), nil
}

// unmarshalIntelList decodes a JSON string list, returning nil on empty or
// malformed content (a cached result should never render worse than "no tags"
// because one column decoded oddly).
func unmarshalIntelList(s string) []string {
	if s == "" || s == "[]" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil
	}
	return out
}
