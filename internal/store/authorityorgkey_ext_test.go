package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestAuthorityOrgKeyMatchesOrgclient pins the store's copy of the enrolment
// identity key to orgclient.OrgKey (the store cannot import orgclient): a
// session captured while enrolled is stamped with exactly the key the org
// client derives for that enrolment, whatever spelling of the server URL the
// enrolment recorded.
func TestAuthorityOrgKeyMatchesOrgclient(t *testing.T) {
	t.Parallel()
	for _, url := range []string{"https://org.example", "https://org.example/", "  https://org.example//  "} {
		t.Run(url, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = database.Close() })
			st := store.New(database)
			if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: "org-1", OrgName: "O", OrgServerURL: url, UserID: "u"}); err != nil {
				t.Fatal(err)
			}
			pid, err := st.UpsertProject(ctx, "/tmp/k", "")
			if err != nil {
				t.Fatal(err)
			}
			if err := st.UpsertSession(ctx, models.Session{ID: "s", ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
				t.Fatal(err)
			}
			var got string
			if err := database.QueryRow(`SELECT authority_org_key FROM sessions WHERE id = 's'`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if want := orgclient.OrgKey(url, "org-1"); got != want {
				t.Fatalf("authority_org_key = %q, want orgclient.OrgKey %q", got, want)
			}
		})
	}
}

// TestPersonalSessionsAreClaimedByTheFirstOrgOnly pins the operator answer of
// 2026-11-13 (M8.1 follow-up): a session captured with no enrolment in force
// ('personal') is claimed by the first organization the machine selects rows
// for while enrolled, and never by a later one. A session captured under an
// org is never claimed by another.
func TestPersonalSessionsAreClaimedByTheFirstOrgOnly(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	st := store.New(database)
	pid, err := st.UpsertProject(ctx, "/tmp/claim", "")
	if err != nil {
		t.Fatal(err)
	}
	capture := func(id string) {
		t.Helper()
		if err := st.UpsertSession(ctx, models.Session{ID: id, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	keyOf := func(id string) string {
		t.Helper()
		var k string
		if err := database.QueryRow(`SELECT authority_org_key FROM sessions WHERE id = ?`, id).Scan(&k); err != nil {
			t.Fatal(err)
		}
		return k
	}
	enrol := func(org string) {
		t.Helper()
		if err := st.WriteEnrolment(ctx, store.Enrolment{OrgID: org, OrgName: org, OrgServerURL: "https://" + org + ".example", UserID: "u"}); err != nil {
			t.Fatal(err)
		}
		// Any org-bound selection claims; the counts are the cheapest one.
		if _, err := st.PushEligibleCounts(ctx, store.PushCursor{}); err != nil {
			t.Fatal(err)
		}
	}
	keyA, keyB := orgclient.OrgKey("https://a.example", "a"), orgclient.OrgKey("https://b.example", "b")

	capture("pre-enrolment")
	if got := keyOf("pre-enrolment"); got != store.AuthorityOrgKeyPersonal {
		t.Fatalf("unenrolled capture key = %q, want personal", got)
	}

	enrol("a")
	capture("under-a")
	if got := keyOf("pre-enrolment"); got != keyA {
		t.Fatalf("pre-enrolment session after enrolling in A = %q, want A's key (claimed)", got)
	}
	if got := keyOf("under-a"); got != keyA {
		t.Fatalf("session captured under A = %q, want A's key", got)
	}

	if err := st.DeleteEnrolment(ctx); err != nil {
		t.Fatal(err)
	}
	capture("between-orgs")

	enrol("b")
	for id, want := range map[string]string{"pre-enrolment": keyA, "under-a": keyA, "between-orgs": keyB} {
		if got := keyOf(id); got != want {
			t.Fatalf("after enrolling in B, %s key = %q, want %q", id, got, want)
		}
	}
}
