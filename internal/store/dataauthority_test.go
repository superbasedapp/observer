package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dataauthority"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// authorityTestStore opens a real store on a fresh migrated DB (reaching the
// current schema version, incl. migration 096). Enrolment state is flipped by
// mutating the org_enrolment singleton directly, mirroring stamp_test.go.
func authorityTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "authority.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return New(database), database
}

// enrol seeds the org_enrolment singleton so resolveEnrolment reads Enrolled.
func enrol(t *testing.T, database *sql.DB) {
	t.Helper()
	_, err := database.ExecContext(context.Background(),
		`INSERT INTO org_enrolment (id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id)
		 VALUES (1, 'org-x', 'X', 'https://x', 'u1', 'dev@x', '2026-08-30T00:00:00Z', 'kc')
		 ON CONFLICT(id) DO UPDATE SET org_id = excluded.org_id`)
	if err != nil {
		t.Fatalf("enrol: %v", err)
	}
}

// unenrol clears the org_enrolment singleton so resolveEnrolment reads the
// DEFINITIVELY-unenrolled state (ErrNoRows -> Enrolled:false, determinable).
func unenrol(t *testing.T, database *sql.DB) {
	t.Helper()
	if _, err := database.ExecContext(context.Background(),
		`DELETE FROM org_enrolment WHERE id = 1`); err != nil {
		t.Fatalf("unenrol: %v", err)
	}
}

// rawAuthority reads the stored columns directly (bypassing the read API) so a
// NULL is observable as sql.NullString{Valid:false}.
func rawAuthority(t *testing.T, database *sql.DB, id string) (sql.NullString, sql.NullInt64) {
	t.Helper()
	var a sql.NullString
	var v sql.NullInt64
	err := database.QueryRowContext(context.Background(),
		`SELECT authority, authority_classifier_version FROM sessions WHERE id = ?`, id).Scan(&a, &v)
	if err != nil {
		t.Fatalf("rawAuthority(%s): %v", id, err)
	}
	return a, v
}

// TestSessionAuthority_LegacyRowIsUnknown proves a session row created without
// an authority stamp (pre-096 legacy shape, simulated by a direct INSERT that
// leaves the columns NULL) reads back as UNKNOWN/ineligible — no backfill, no
// inference from present-day enrolment.
func TestSessionAuthority_LegacyRowIsUnknown(t *testing.T) {
	s, database := authorityTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/inv/p", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	// Direct INSERT leaving authority columns NULL == a pre-096 legacy row.
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('legacy', ?, 'claude-code', '2026-01-01T00:00:00Z')`,
		pid); err != nil {
		t.Fatalf("insert legacy: %v", err)
	}
	// Even with the node enrolled RIGHT NOW, the legacy row must stay unknown.
	enrol(t, database)

	c, found, err := s.SessionAuthority(ctx, "legacy")
	if err != nil {
		t.Fatalf("SessionAuthority: %v", err)
	}
	if found {
		t.Fatalf("legacy row must be UNKNOWN (found=false), got %+v", c)
	}
	elig, err := s.EligibleForPersonalCloud(ctx, "legacy")
	if err != nil {
		t.Fatalf("EligibleForPersonalCloud: %v", err)
	}
	if elig {
		t.Fatal("legacy/unknown row must be ineligible")
	}
}

// TestSessionAuthority_MissingSessionUnknown proves the read API reports a
// non-existent session as unknown/ineligible rather than erroring.
func TestSessionAuthority_MissingSessionUnknown(t *testing.T) {
	s, _ := authorityTestStore(t)
	ctx := context.Background()
	if _, found, err := s.SessionAuthority(ctx, "nope"); err != nil || found {
		t.Fatalf("missing session: want (found=false,nil), got found=%v err=%v", found, err)
	}
	if elig, err := s.EligibleForPersonalCloud(ctx, "nope"); err != nil || elig {
		t.Fatalf("missing session eligibility: want (false,nil), got %v %v", elig, err)
	}
}

// TestUpsertAuthorityRuleMatrix exercises the full first-capture x later-write
// rule matrix. Each case drives real UpsertSession calls (through the same
// atomic ON CONFLICT statement the ingest paths use) and asserts the stored
// authority + eligibility.
func TestUpsertAuthorityRuleMatrix(t *testing.T) {
	const V = dataauthority.Version
	// state: "enrol" | "unenrol" | "error". error is simulated by dropping the
	// org_enrolment table so the resolver's read fails (not ErrNoRows) ->
	// undeterminable -> UNKNOWN.
	type step struct {
		state string
	}
	cases := []struct {
		name     string
		steps    []step
		wantAuth string // "" == NULL/unknown
		wantVer  int64  // ignored when wantAuth == ""
		wantElig bool
	}{
		{"first-capture-unenrolled->personal", []step{{"unenrol"}}, "personal", V, true},
		{"first-capture-enrolled->org", []step{{"enrol"}}, "org", V, false},
		{"first-capture-error->unknown", []step{{"error"}}, "", 0, false},
		{"personal-then-enrol->org-upgrade", []step{{"unenrol"}, {"enrol"}}, "org", V, false},
		{"org-then-unenrol->org-sticky", []step{{"enrol"}, {"unenrol"}}, "org", V, false},
		{"org-then-error->org-sticky", []step{{"enrol"}, {"error"}}, "org", V, false},
		{"personal-then-unenrol->stays-personal", []step{{"unenrol"}, {"unenrol"}}, "personal", V, true},
		{"personal-then-error->stays-personal", []step{{"unenrol"}, {"error"}}, "personal", V, true},
		{"unknown-then-unenrol->stays-unknown", []step{{"error"}, {"unenrol"}}, "", 0, false},
		{"unknown-then-enrol->org", []step{{"error"}, {"enrol"}}, "org", V, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, database := authorityTestStore(t)
			ctx := context.Background()
			pid, err := s.UpsertProject(ctx, "/inv/p", "")
			if err != nil {
				t.Fatalf("UpsertProject: %v", err)
			}
			const id = "s1"
			for i, st := range tc.steps {
				switch st.state {
				case "enrol":
					enrol(t, database)
				case "unenrol":
					unenrol(t, database)
				case "error":
					// Drop the singleton table so resolveEnrolment's read errors
					// (undeterminable), then recreate it after this write so a
					// later step can enrol/unenrol again.
					if _, err := database.ExecContext(ctx, `ALTER TABLE org_enrolment RENAME TO org_enrolment_hidden`); err != nil {
						t.Fatalf("hide table: %v", err)
					}
				}
				if err := s.UpsertSession(ctx, models.Session{
					ID: id, ProjectID: pid, Tool: "claude-code", StartedAt: time.Now().UTC(),
				}); err != nil {
					t.Fatalf("step %d UpsertSession: %v", i, err)
				}
				if st.state == "error" {
					if _, err := database.ExecContext(ctx, `ALTER TABLE org_enrolment_hidden RENAME TO org_enrolment`); err != nil {
						t.Fatalf("restore table: %v", err)
					}
				}
			}
			a, v := rawAuthority(t, database, id)
			if tc.wantAuth == "" {
				if a.Valid {
					t.Fatalf("want NULL authority, got %q", a.String)
				}
			} else {
				if !a.Valid || a.String != tc.wantAuth {
					t.Fatalf("authority: want %q, got valid=%v %q", tc.wantAuth, a.Valid, a.String)
				}
				if v.Int64 != tc.wantVer {
					t.Fatalf("version: want %d, got %d", tc.wantVer, v.Int64)
				}
			}
			elig, err := s.EligibleForPersonalCloud(ctx, id)
			if err != nil {
				t.Fatalf("EligibleForPersonalCloud: %v", err)
			}
			if elig != tc.wantElig {
				t.Fatalf("eligibility: want %v, got %v", tc.wantElig, elig)
			}
		})
	}
}

// TestUpsertAuthorityMatchesCombine pins the SQL ON CONFLICT stamp against the
// pure dataauthority.Combine oracle for every (prior, current-state) cell
// Combine covers — so the atomic SQL rule can never drift from the contract.
// (The unknown-prior and resolver-error cells, which Combine intentionally
// does not model, are covered by TestUpsertAuthorityRuleMatrix.)
func TestUpsertAuthorityMatchesCombine(t *testing.T) {
	priors := []dataauthority.Authority{dataauthority.AuthorityPersonal, dataauthority.AuthorityOrg}
	states := []bool{true, false}
	for _, prior := range priors {
		for _, nowEnrolled := range states {
			name := string(prior) + "_then_enrolled=" + boolStr(nowEnrolled)
			t.Run(name, func(t *testing.T) {
				s, database := authorityTestStore(t)
				ctx := context.Background()
				pid, err := s.UpsertProject(ctx, "/inv/p", "")
				if err != nil {
					t.Fatalf("UpsertProject: %v", err)
				}
				const id = "s1"
				// First capture establishes the prior authority.
				if prior == dataauthority.AuthorityOrg {
					enrol(t, database)
				} else {
					unenrol(t, database)
				}
				if err := s.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: "t", StartedAt: time.Now().UTC()}); err != nil {
					t.Fatalf("first UpsertSession: %v", err)
				}
				// Second write under the current state.
				if nowEnrolled {
					enrol(t, database)
				} else {
					unenrol(t, database)
				}
				if err := s.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: "t", StartedAt: time.Now().UTC()}); err != nil {
					t.Fatalf("second UpsertSession: %v", err)
				}

				priorC := dataauthority.Classification{Authority: prior, Version: dataauthority.Version}
				want := dataauthority.Combine(&priorC, dataauthority.EnrolmentState{Enrolled: nowEnrolled})

				got, found, err := s.SessionAuthority(ctx, id)
				if err != nil {
					t.Fatalf("SessionAuthority: %v", err)
				}
				if !found || got.Authority != want.Authority || got.Version != want.Version {
					t.Fatalf("SQL stamp %+v (found=%v) != Combine oracle %+v", got, found, want)
				}
			})
		}
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// TestResolveEnrolmentLiveReflectsChange proves the resolver reads enrolment
// LIVE — a change to the org_enrolment singleton is visible on the very next
// resolve WITHOUT reconstructing the Store (the cautionary-precedent
// divergence from identity.Stamper's construction-time snapshot).
func TestResolveEnrolmentLiveReflectsChange(t *testing.T) {
	s, database := authorityTestStore(t)
	ctx := context.Background()

	unenrol(t, database)
	if state, det := s.resolveEnrolment(ctx); !det || state.Enrolled {
		t.Fatalf("initial: want determinable&unenrolled, got det=%v enrolled=%v", det, state.Enrolled)
	}
	enrol(t, database) // flip the underlying signal on the SAME store
	if state, det := s.resolveEnrolment(ctx); !det || !state.Enrolled {
		t.Fatalf("after enrol: want determinable&enrolled, got det=%v enrolled=%v", det, state.Enrolled)
	}
	unenrol(t, database) // and back
	if state, det := s.resolveEnrolment(ctx); !det || state.Enrolled {
		t.Fatalf("after unenrol: want determinable&unenrolled, got det=%v enrolled=%v", det, state.Enrolled)
	}
}

// TestResolveEnrolmentErrorIsUndeterminable proves a read error (table absent)
// resolves to undeterminable (never personal) — fail-closed.
func TestResolveEnrolmentErrorIsUndeterminable(t *testing.T) {
	s, database := authorityTestStore(t)
	ctx := context.Background()
	if _, err := database.ExecContext(ctx, `ALTER TABLE org_enrolment RENAME TO gone`); err != nil {
		t.Fatalf("hide table: %v", err)
	}
	state, det := s.resolveEnrolment(ctx)
	if det {
		t.Fatalf("read error must be undeterminable, got determinable (enrolled=%v)", state.Enrolled)
	}
}

// TestUpsertAuthorityConcurrent proves two concurrent ingest writes of the
// SAME session (while enrolled) do not corrupt the stamp — the atomic ON
// CONFLICT statement serializes under the store's write lock and the sticky
// rule holds. Mirrors the store's real UpsertSession path.
func TestUpsertAuthorityConcurrent(t *testing.T) {
	s, database := authorityTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/inv/p", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	enrol(t, database)
	const id = "concurrent"
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.UpsertSession(ctx, models.Session{
				ID: id, ProjectID: pid, Tool: "claude-code", StartedAt: time.Now().UTC(),
			}); e != nil {
				errs <- e
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("concurrent UpsertSession: %v", e)
	}
	a, v := rawAuthority(t, database, id)
	if !a.Valid || a.String != "org" || v.Int64 != int64(dataauthority.Version) {
		t.Fatalf("concurrent stamp corrupted: authority valid=%v %q version=%d", a.Valid, a.String, v.Int64)
	}
}

// TestUpsertAuthorityPersonalVersionUpgrade is the FD5 regression: a personal
// session carrying an OLD classifier version, rewritten while still
// unenrolled, must upgrade its stored version to the current contract version
// — matching dataauthority.Combine(personal/old, unenrolled) = personal/
// current. Before the personal-upgrade CASE branch, the ELSE preserved the
// stale version and this test's final assertion failed.
func TestUpsertAuthorityPersonalVersionUpgrade(t *testing.T) {
	s, database := authorityTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/inv/p", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	const id = "personal-old-v"
	unenrol(t, database)
	if err := s.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: "t", StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("first UpsertSession: %v", err)
	}
	// Force a stale personal classifier version (a pre-bump personal prior).
	oldVer := dataauthority.Version - 1
	if _, err := database.ExecContext(ctx,
		`UPDATE sessions SET authority_classifier_version = ? WHERE id = ?`, oldVer, id); err != nil {
		t.Fatalf("force old version: %v", err)
	}
	// Rewrite while STILL unenrolled: authority stays personal, version must
	// upgrade to the current contract version (the FD5 fix).
	if err := s.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: "t", StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("second UpsertSession: %v", err)
	}
	a, v := rawAuthority(t, database, id)
	if !a.Valid || a.String != "personal" {
		t.Fatalf("authority: want personal, got valid=%v %q", a.Valid, a.String)
	}
	// Oracle: Combine(personal/old, unenrolled) always carries the current Version.
	priorC := dataauthority.Classification{Authority: dataauthority.AuthorityPersonal, Version: oldVer}
	want := dataauthority.Combine(&priorC, dataauthority.EnrolmentState{Enrolled: false})
	if int(v.Int64) != want.Version {
		t.Fatalf("stale personal version not upgraded: got %d, want %d (Combine oracle)", v.Int64, want.Version)
	}
}

// TestUpsertSessionAuthorityAtomicWithEnrolment is the FD2 barrier regression.
// It proves the enrolment read and the session UPSERT are ONE atomic unit: a
// concurrent WriteEnrolment launched between them cannot commit while the
// UpsertSession transaction holds the write lock. Before the fix (enrolment
// read via autocommit, then a separate autocommit UPSERT), the concurrent
// enrolment DID commit inside the window and the pre-computed 'personal' stamp
// landed AFTER a durable enrolment — the personal-after-enrol race.
func TestUpsertSessionAuthorityAtomicWithEnrolment(t *testing.T) {
	s, database := authorityTestStore(t)
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/inv/p", "")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	unenrol(t, database)

	committedDuringWindow := make(chan bool, 1)
	done := make(chan struct{})
	origHook := upsertSessionMidTxHook
	upsertSessionMidTxHook = func() {
		// We are between the in-tx enrolment read and the session write.
		go func() {
			// This write (a fresh pooled connection) must block on the write
			// lock the UpsertSession tx holds; it may only commit AFTER commit.
			_ = s.WriteEnrolment(ctx, Enrolment{OrgID: "org-x", OrgName: "X", OrgServerURL: "https://x", UserID: "u1", UserEmail: "dev@x"})
			close(done)
		}()
		select {
		case <-done:
			committedDuringWindow <- true // enrolment landed inside the window
		case <-time.After(400 * time.Millisecond):
			committedDuringWindow <- false // blocked → the read+write are atomic
		}
	}
	t.Cleanup(func() { upsertSessionMidTxHook = origHook })

	if err := s.UpsertSession(ctx, models.Session{ID: "fd2", ProjectID: pid, Tool: "t", StartedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	<-done // let the deferred enrolment finish so the goroutine never leaks

	if <-committedDuringWindow {
		t.Fatal("a concurrent WriteEnrolment committed between the enrolment read and the session write — capture-time authority is NOT atomic with the session write (FD2)")
	}
}
