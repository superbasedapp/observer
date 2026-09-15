package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

func intelTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "intel.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return New(database)
}

func TestUpsertAndGetOrgIntelResult(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)

	in := OrgIntelResult{
		SessionID:     "sess-1",
		JobID:         "job-1",
		Title:         "Fix the cursor bug",
		TaxonomyTags:  []string{"bugfix", "org-server"},
		SuggestedTags: []string{"cas"},
		Description:   "Diagnosed a blind save.",
		Confidence:    "high",
		Limitations:   []string{"no test observed"},
		SchemaVersion: "session_enrichment.v2-candidate",
		FetchedAt:     time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC),
	}
	if err := s.UpsertOrgIntelResult(ctx, in); err != nil {
		t.Fatalf("UpsertOrgIntelResult: %v", err)
	}

	got, err := s.OrgIntelResultsForSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("OrgIntelResultsForSession: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows=%d, want 1", len(got))
	}
	r := got[0]
	if r.Title != in.Title || r.Confidence != "high" || r.Description != in.Description {
		t.Fatalf("scalar round-trip mismatch: %+v", r)
	}
	if len(r.TaxonomyTags) != 2 || r.TaxonomyTags[0] != "bugfix" {
		t.Fatalf("taxonomy round-trip: %+v", r.TaxonomyTags)
	}
	if len(r.SuggestedTags) != 1 || len(r.Limitations) != 1 {
		t.Fatalf("list round-trip: suggested=%+v limitations=%+v", r.SuggestedTags, r.Limitations)
	}
	if !r.FetchedAt.Equal(in.FetchedAt) {
		t.Fatalf("fetched_at=%v, want %v", r.FetchedAt, in.FetchedAt)
	}
}

// UNIQUE(session_id, job_id): a second upsert of the same key REPLACES in place.
func TestUpsertOrgIntelResultReplacesInPlace(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)

	base := OrgIntelResult{SessionID: "s", JobID: "j", Title: "old", Confidence: "low"}
	if err := s.UpsertOrgIntelResult(ctx, base); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	base.Title = "new"
	base.Confidence = "high"
	base.TaxonomyTags = []string{"added"}
	if err := s.UpsertOrgIntelResult(ctx, base); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	got, err := s.OrgIntelResultsForSession(ctx, "s")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("rows=%d, want 1 (upsert must replace, not append)", len(got))
	}
	if got[0].Title != "new" || got[0].Confidence != "high" || len(got[0].TaxonomyTags) != 1 {
		t.Fatalf("replace did not take: %+v", got[0])
	}
}

func TestUpsertOrgIntelResultDefaultsFetchedAt(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{SessionID: "s", JobID: "j"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, _ := s.OrgIntelResultsForSession(ctx, "s")
	if len(got) != 1 || got[0].FetchedAt.IsZero() {
		t.Fatalf("fetched_at not defaulted: %+v", got)
	}
}

func TestUpsertOrgIntelResultRequiresKeys(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{JobID: "j"}); err == nil {
		t.Fatal("missing session id must error")
	}
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{SessionID: "s"}); err == nil {
		t.Fatal("missing job id must error")
	}
}

func TestOrgIntelResultsForSessionEmpty(t *testing.T) {
	got, err := intelTestStore(t).OrgIntelResultsForSession(context.Background(), "nope")
	if err != nil {
		t.Fatalf("empty lookup errored: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("rows=%d, want 0", len(got))
	}
}

// TestUpsertOrgIntelResultRejectsHostileText pins INV-6 on the NODE writer
// (finding 8): a result text field carrying a control / ANSI / bidi sequence is
// rejected before any SQL, the WHOLE row is refused (never truncated), and the
// error matches ErrOrgIntelResultUnsafe so the pull loop can hold the cursor.
func TestUpsertOrgIntelResultRejectsHostileText(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)

	hostile := []OrgIntelResult{
		{SessionID: "s", JobID: "j", Title: "ansi \x1b[31mred\x1b[0m"},        // ANSI/ESC
		{SessionID: "s", JobID: "j", Description: "bidi \u202eoverride"},      // bidi control (RLO)
		{SessionID: "s", JobID: "j", TaxonomyTags: []string{"tab\tinjected"}}, // C0 control in a list
		{SessionID: "s", JobID: "j", Limitations: []string{"nul\x00byte"}},    // NUL in a list
		{SessionID: "s", JobID: "j", Confidence: "high\x07bell"},              // control in the enum
	}
	for i, r := range hostile {
		if err := s.UpsertOrgIntelResult(ctx, r); !errors.Is(err, ErrOrgIntelResultUnsafe) {
			t.Errorf("case %d: err=%v, want ErrOrgIntelResultUnsafe", i, err)
		}
	}
	// And nothing was persisted — the rows were rejected, not truncated.
	got, err := s.OrgIntelResultsForSession(ctx, "s")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("a hostile row was persisted anyway: %+v", got)
	}

	// A benign row on the same keys still stores fine.
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{SessionID: "s", JobID: "j", Title: "clean"}); err != nil {
		t.Fatalf("benign upsert after rejections: %v", err)
	}
}

// TestDeleteForeignOrgIntelResults pins finding 6: on an identity change the
// node drops cached rows NOT bound to the current org (including pre-114 rows
// with an empty org_id), keeping the current org's rows.
func TestDeleteForeignOrgIntelResults(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)

	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{OrgID: "org-A", SessionID: "a", JobID: "1", Title: "keep"}); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{OrgID: "org-B", SessionID: "b", JobID: "1", Title: "drop"}); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	// A pre-114-style unbound row (empty org_id) is foreign to any real org.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO org_intel_cache (org_id, session_id, job_id, fetched_at) VALUES ('', 'legacy', '1', ?)`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	if err := s.DeleteForeignOrgIntelResults(ctx, "org-A"); err != nil {
		t.Fatalf("DeleteForeignOrgIntelResults: %v", err)
	}
	if got, _ := s.OrgIntelResultsForSession(ctx, "a"); len(got) != 1 {
		t.Fatalf("org-A row was dropped; want kept")
	}
	if got, _ := s.OrgIntelResultsForSession(ctx, "b"); len(got) != 0 {
		t.Fatalf("org-B (foreign) row survived; want dropped")
	}
	if got, _ := s.OrgIntelResultsForSession(ctx, "legacy"); len(got) != 0 {
		t.Fatalf("legacy unbound row survived; want dropped")
	}
}

// TestOrgIntelResultsScopedToEnrolmentOrg pins finding 7: when the node IS
// enrolled, OrgIntelResultsForSession returns ONLY rows bound to the live
// enrolment's org — a foreign-org row lingering past an identity change is not
// rendered. Without an enrolment the filter is a no-op (covered by the other
// tests, which seed cache rows and read them back with no enrolment).
func TestOrgIntelResultsScopedToEnrolmentOrg(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)

	// Enrol the node into org-A.
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO org_enrolment (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id, tenancy)
		 VALUES (1, 'org-A', 'A', 'https://a.example', 'u', 'u@a', ?, 'k', 'individual')`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed enrolment: %v", err)
	}
	// A current-org row and a foreign-org row for the same session.
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{OrgID: "org-A", SessionID: "sess", JobID: "own", Title: "mine"}); err != nil {
		t.Fatalf("seed own: %v", err)
	}
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{OrgID: "org-B", SessionID: "sess", JobID: "foreign", Title: "theirs"}); err != nil {
		t.Fatalf("seed foreign: %v", err)
	}

	got, err := s.OrgIntelResultsForSession(ctx, "sess")
	if err != nil {
		t.Fatalf("OrgIntelResultsForSession: %v", err)
	}
	if len(got) != 1 || got[0].JobID != "own" {
		t.Fatalf("enrolled read = %+v, want only the org-A row", got)
	}
}

// TestDeleteEnrolmentClearsOrgIntelCache pins finding 6: leaving an org drops
// its derived intel so it does not outlive the enrolment.
func TestDeleteEnrolmentClearsOrgIntelCache(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{OrgID: "org-A", SessionID: "a", JobID: "1", Title: "t"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := s.DeleteEnrolment(ctx); err != nil {
		t.Fatalf("DeleteEnrolment: %v", err)
	}
	if got, _ := s.OrgIntelResultsForSession(ctx, "a"); len(got) != 0 {
		t.Fatalf("DeleteEnrolment left %d intel rows; want the cache cleared", len(got))
	}
}

// TestPruneOrgIntelCacheOrphansAndAged pins finding 7: the retention sweep drops
// rows whose session is gone (always) and rows past the local window (when
// retentionDays > 0), and a repeated prune does not resurrect anything.
func TestPruneOrgIntelCacheOrphansAndAged(t *testing.T) {
	ctx := context.Background()
	s := intelTestStore(t)
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)

	// A present session with a fresh result (kept) and an aged result (pruned by
	// age). A second result for a session that does not exist (orphan).
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/proj', ?)`,
		now.Format(time.RFC3339)); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('present', 1, 'claude-code', ?)`,
		now.Format(time.RFC3339)); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	fresh := OrgIntelResult{OrgID: "o", SessionID: "present", JobID: "fresh", Title: "fresh", FetchedAt: now}
	aged := OrgIntelResult{OrgID: "o", SessionID: "present", JobID: "aged", Title: "aged", FetchedAt: now.AddDate(0, 0, -40)}
	orphan := OrgIntelResult{OrgID: "o", SessionID: "gone", JobID: "orphan", Title: "orphan", FetchedAt: now}
	for _, r := range []OrgIntelResult{fresh, aged, orphan} {
		if err := s.UpsertOrgIntelResult(ctx, r); err != nil {
			t.Fatalf("seed %s: %v", r.JobID, err)
		}
	}

	// retentionDays = 30: orphan ('gone') + aged (40d old) go; fresh stays.
	n, err := s.PruneOrgIntelCache(ctx, 30, now)
	if err != nil {
		t.Fatalf("PruneOrgIntelCache: %v", err)
	}
	if n != 2 {
		t.Fatalf("pruned %d, want 2 (orphan + aged)", n)
	}
	if got, _ := s.OrgIntelResultsForSession(ctx, "present"); len(got) != 1 || got[0].JobID != "fresh" {
		t.Fatalf("present session rows=%+v, want just [fresh]", got)
	}
	if got, _ := s.OrgIntelResultsForSession(ctx, "gone"); len(got) != 0 {
		t.Fatalf("orphan survived: %+v", got)
	}

	// A repeated prune removes nothing (nothing resurrected) and is a no-op.
	n2, err := s.PruneOrgIntelCache(ctx, 30, now)
	if err != nil || n2 != 0 {
		t.Fatalf("repeat prune removed %d (err=%v), want 0 — nothing resurrected", n2, err)
	}

	// retentionDays <= 0 means keep-forever for age: only orphans are swept.
	if err := s.UpsertOrgIntelResult(ctx, OrgIntelResult{OrgID: "o", SessionID: "present", JobID: "old2", Title: "old", FetchedAt: now.AddDate(0, 0, -400)}); err != nil {
		t.Fatalf("seed old2: %v", err)
	}
	n3, err := s.PruneOrgIntelCache(ctx, 0, now)
	if err != nil || n3 != 0 {
		t.Fatalf("keep-forever prune removed %d (err=%v), want 0 (no orphans, age disabled)", n3, err)
	}
}
