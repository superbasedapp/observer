package db_test

import (
	"context"
	"io/fs"
	"regexp"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
)

// db_staff_login_test.go pins operator ruling A3 (2026-11-13) in the cloud
// lineage: the staff login sbci_staff_svc is the ONLY login granted
// sbci_staff. 0068 grants the role to no login at all (its first, unshipped
// version granted it to the customer serve login), and 0076 revokes it from
// the customer and worker logins of a database that applied that first
// version, grants it to the staff login, and lets the staff process run the
// shared rate-limit counter.

// grantStaffPattern matches any GRANT of sbci_staff to a role.
var grantStaffPattern = regexp.MustCompile(`(?i)GRANT\s+sbci_staff\s+TO`)

func TestStaffRoleGrantedToNoLoginIn0068(t *testing.T) {
	t.Parallel()
	b, err := fs.ReadFile(migrations.Files, "0068_staff_role.sql")
	if err != nil {
		t.Fatal(err)
	}
	if grantStaffPattern.Match(b) {
		t.Fatal("0068 grants sbci_staff to a login; only 0076 grants it, and only to sbci_staff_svc")
	}
}

func TestStaffLoginIsTheOnlyStaffMember(t *testing.T) {
	t.Parallel()
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	// The service logins are cluster-wide; create the ones this test needs
	// (NOLOGIN: membership is what matters) and drop what it created.
	for _, role := range []string{"sbci_api_svc", "sbci_svc", "sbci_staff_svc"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = $1)`, role).Scan(&exists); err != nil {
			t.Fatal(err)
		}
		if exists {
			continue
		}
		if _, err := pool.Exec(ctx, `CREATE ROLE `+pgx.Identifier{role}.Sanitize()+` NOLOGIN`); err != nil {
			t.Fatalf("create %s: %v", role, err)
		}
		t.Cleanup(func() {
			_, _ = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+pgx.Identifier{role}.Sanitize())
		})
	}
	// The first version of 0068 granted the staff role to the serve logins.
	for _, role := range []string{"sbci_api_svc", "sbci_svc"} {
		if _, err := pool.Exec(ctx, `GRANT sbci_staff TO `+pgx.Identifier{role}.Sanitize()); err != nil {
			t.Fatalf("simulate the first 0068 on %s: %v", role, err)
		}
	}
	// Re-applying 0068 as it is now grants nothing; 0076 repairs the rest.
	for _, file := range []string{"0068_staff_role.sql", "0076_staff_login.sql"} {
		applyMigrationFile(t, pool, file)
	}
	for role, want := range map[string]bool{"sbci_api_svc": false, "sbci_svc": false, "sbci_staff_svc": true} {
		var member bool
		if err := pool.QueryRow(ctx, `SELECT pg_has_role($1, 'sbci_staff', 'MEMBER')`, role).Scan(&member); err != nil {
			t.Fatal(err)
		}
		if member != want {
			t.Errorf("%s member of sbci_staff = %v, want %v", role, member, want)
		}
	}
	var exec bool
	if err := pool.QueryRow(ctx,
		`SELECT has_function_privilege('sbci_staff', 'sbci_rate_limit(text, text, integer, bigint)', 'EXECUTE')`).Scan(&exec); err != nil {
		t.Fatal(err)
	}
	if !exec {
		t.Error("sbci_staff cannot execute sbci_rate_limit")
	}
}

// applyMigrationFile runs one embedded migration in a transaction, the way
// the runner does.
func applyMigrationFile(t *testing.T, pool *pgxpool.Pool, name string) {
	t.Helper()
	b, err := fs.ReadFile(migrations.Files, name)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, string(b)); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
