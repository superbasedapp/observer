package db

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/db/migrations"
)

const authorityOrgKeyFile = "250_session_authority_org_key.sql"

// TestMigration250AuthorityOrgKey grades the M8.1 attribution step (managed
// SaaS plan 07, operator ruling D-43): every existing session is stamped by
// the migration itself, so no unkeyed row predates the column. A session
// captured while unenrolled (authority 'personal') stays personal; every
// other row takes the enrolment in force when the migration runs, through
// the transient 'pending-250' stamp and the enrolment's pre-image in
// schema_meta (SQLite cannot compute the SHA-256 org key; the store resolves
// it, internal/store TestResolvePendingAuthorityOrgKeys); with no enrolment
// every row is personal and no pre-image is written.
func TestMigration250AuthorityOrgKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		enrolled bool
		want     map[string]string
		wantMeta map[string]string
	}{
		{
			name:     "enrolled",
			enrolled: true,
			want:     map[string]string{"org": "pending-250", "personal": "personal", "legacy": "pending-250"},
			wantMeta: map[string]string{
				"authority_org_key_250_org_id":         "org-A",
				"authority_org_key_250_org_server_url": "https://a.example",
			},
		},
		{
			name:     "not enrolled",
			want:     map[string]string{"org": "personal", "personal": "personal", "legacy": "personal"},
			wantMeta: map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			path := filepath.Join(t.TempDir(), "observer.db")
			database, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(30000)&_pragma=foreign_keys(1)&_txlock=immediate")
			if err != nil {
				t.Fatalf("sql.Open: %v", err)
			}
			defer database.Close()
			if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, lineageWithout(t, authorityOrgKeyFile), lateSteps); err != nil {
				t.Fatalf("migrate to 248: %v", err)
			}
			if _, err := database.ExecContext(ctx, `INSERT INTO projects (id, root_path, created_at) VALUES (1, '/tmp/p', '2026-11-01T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
			for id, authority := range map[string]any{"org": "org", "personal": "personal", "legacy": nil} {
				if _, err := database.ExecContext(ctx,
					`INSERT INTO sessions (id, project_id, tool, started_at, authority) VALUES (?, 1, 'claude-code', '2026-11-01T00:00:00Z', ?)`,
					id, authority); err != nil {
					t.Fatalf("seed %s: %v", id, err)
				}
			}
			if tc.enrolled {
				if _, err := database.ExecContext(ctx, `INSERT INTO org_enrolment
					(id, org_id, org_name, org_server_url, user_id, user_email, enrolled_at, bearer_key_id)
					VALUES (1, 'org-A', 'A', 'https://a.example', 'u1', 'dev@a.example', '2026-11-01T00:00:00Z', 'k')`); err != nil {
					t.Fatal(err)
				}
			}
			if err := runMigrationsFrom(ctx, database, defaultMigrationLockWait, migrations.Files, lateSteps); err != nil {
				t.Fatalf("migrate through 250: %v", err)
			}
			for id, want := range tc.want {
				var got sql.NullString
				if err := database.QueryRowContext(ctx, `SELECT authority_org_key FROM sessions WHERE id = ?`, id).Scan(&got); err != nil {
					t.Fatal(err)
				}
				if !got.Valid || got.String != want {
					t.Errorf("%s: authority_org_key = %+v, want %q", id, got, want)
				}
			}
			rows, err := database.QueryContext(ctx, `SELECT key, value FROM schema_meta WHERE key LIKE 'authority_org_key_250_%'`)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for rows.Next() {
				var k, v string
				if err := rows.Scan(&k, &v); err != nil {
					t.Fatal(err)
				}
				got[k] = v
			}
			if err := rows.Close(); err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tc.wantMeta) {
				t.Fatalf("pre-image = %v, want %v", got, tc.wantMeta)
			}
			for k, v := range tc.wantMeta {
				if got[k] != v {
					t.Errorf("pre-image %s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
