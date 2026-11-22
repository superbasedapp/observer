package db_test

// db_temp_privilege_test.go pins cloud migration 0153 (docs/security.md
// CLOUD-TEMP-1, defence in depth for CLOUD-DEFINER-TEMP-2): no application
// role may create a temporary table in the cloud database.
//
// Before 0153 every role held TEMP through PUBLIC, the database's default
// ACL. A caller's temp table is what every SECURITY DEFINER shadow attack
// needs (a temp table named like a definer's table or type), so 0152 fixed
// the definers and 0153 removes the tool: TEMP is revoked from PUBLIC (and
// from the cloud's group roles, should one hold an explicit grant), and the
// migrating login keeps it explicitly, because migrations 0039, 0041 and 0043
// build temp tables. No runtime code needs TEMP: no Go file under
// internal/cloudserver or cmd/observer-cloud creates a temp table, and no
// function body in the schema does (TestNoFunctionBodyCreatesATempTable).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/db/migrations"
)

// noTempRoles are the cloud's group roles, none of which may hold TEMP on the
// cloud database after 0153: the five caller roles and the definer owner
// (which no function body needs it for).
var noTempRoles = []string{"sbci_aggregator", "sbci_api", "sbci_app", "sbci_defs", "sbci_staff", "sbci_worker"}

// tempCallerRoles are the roles a runtime login is a member of. A login that
// inherits one of them must be refused a temp table.
var tempCallerRoles = []string{"sbci_aggregator", "sbci_api", "sbci_app", "sbci_staff", "sbci_worker"}

// TestNoRoleHoldsTempOnTheCloudDatabase reads the privilege the way the
// server decides it (has_database_privilege covers PUBLIC, explicit grants
// and inherited ones) for every cloud group role, and reads the database ACL
// itself: no PUBLIC entry and no sbci_* entry may carry TEMPORARY. The
// migrating login (the pool's login here) keeps TEMP.
func TestNoRoleHoldsTempOnTheCloudDatabase(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	for _, role := range noTempRoles {
		var temp bool
		if err := pool.QueryRow(ctx,
			`SELECT has_database_privilege($1, current_database(), 'TEMP')`, role).Scan(&temp); err != nil {
			t.Fatalf("has_database_privilege(%s): %v", role, err)
		}
		if temp {
			t.Errorf("%s holds TEMP on the cloud database; want none (a caller's temp table is what every definer shadow attack needs)", role)
		}
	}
	rows, err := pool.Query(ctx, `
		SELECT CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee) END
		  FROM pg_database d, aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) a
		 WHERE d.datname = current_database() AND a.privilege_type = 'TEMPORARY'
		   AND (a.grantee = 0 OR pg_get_userbyid(a.grantee) LIKE 'sbci\_%')`)
	if err != nil {
		t.Fatalf("read the database ACL: %v", err)
	}
	holders, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("read the database ACL: %v", err)
	}
	if len(holders) != 0 {
		t.Errorf("the database ACL grants TEMPORARY to %v; want no PUBLIC or sbci_* entry", holders)
	}
	var migrator string
	var temp bool
	if err := pool.QueryRow(ctx,
		`SELECT current_user, has_database_privilege(current_user, current_database(), 'TEMP')`).Scan(&migrator, &temp); err != nil {
		t.Fatalf("the migrating login's TEMP: %v", err)
	}
	if !temp {
		t.Errorf("the migrating login %s lost TEMP; want it kept (migrations build temp tables)", migrator)
	}
}

// TestRuntimeLoginsCannotCreateTempTables is the live check: a throwaway
// LOGIN that inherits one caller role, as each deployment's runtime logins do
// (sbci_api_svc, sbci_worker_svc, sbci_staff_svc), connects to the cloud
// database and is refused CREATE TEMP TABLE with insufficient_privilege.
func TestRuntimeLoginsCannotCreateTempTables(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	for _, role := range tempCallerRoles {
		t.Run(role, func(t *testing.T) {
			conn := connectAsMemberOf(t, pool, role)
			_, err := conn.Exec(context.Background(), `CREATE TEMP TABLE accounts (account_id uuid)`)
			var pgErr *pgconn.PgError
			if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
				t.Fatalf("CREATE TEMP TABLE as a login member of %s = %v; want SQLSTATE 42501 (permission denied to create temporary tables)", role, err)
			}
		})
	}
}

// TestNoFunctionBodyCreatesATempTable is why the definer owner may lose TEMP
// too: no function in the schema builds a temp table at call time (0037's
// sbci_project_digest_candidates did, and 0038 replaced it), so revoking TEMP
// breaks no runtime path. A new body that needs one fails here first.
func TestNoFunctionBodyCreatesATempTable(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	rows, err := pool.Query(context.Background(), `
		SELECT p.oid::regprocedure::text
		  FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
		   AND p.prosrc ~* '(create\s+(global\s+|local\s+)?(temp|temporary)\s+table|\mpg_temp\.)'`)
	if err != nil {
		t.Fatalf("scan function bodies: %v", err)
	}
	fns, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatalf("scan function bodies: %v", err)
	}
	if len(fns) != 0 {
		t.Fatalf("function bodies that build or name a temp table: %v; no role but the migrator holds TEMP (0153)", fns)
	}
}

// TestTempRevokeStepFailsClosed replays 0153 against a database whose PUBLIC
// holds TEMP again. Run by a role that may not change the database's ACL,
// REVOKE only warns, so the step's own check must fail it and the rollback
// must leave the ACL as it was; run by the owner it succeeds and the revoke
// holds again.
func TestTempRevokeStepFailsClosed(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	step, err := migrations.Files.ReadFile("0153_revoke_temp_from_public.sql")
	if err != nil {
		t.Fatalf("read 0153: %v", err)
	}
	var db string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `GRANT TEMPORARY ON DATABASE `+pgx.Identifier{db}.Sanitize()+` TO PUBLIC`); err != nil {
		t.Fatalf("give PUBLIC TEMP back: %v", err)
	}
	publicHoldsTemp := func() bool {
		t.Helper()
		var temp bool
		if err := pool.QueryRow(ctx, `SELECT has_database_privilege('sbci_app', current_database(), 'TEMP')`).Scan(&temp); err != nil {
			t.Fatal(err)
		}
		return temp
	}
	if !publicHoldsTemp() {
		t.Fatal("fixture: sbci_app has no TEMP through PUBLIC")
	}
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	stranger := pgx.Identifier{"sbci_t_" + hex.EncodeToString(b)}.Sanitize()
	if _, err := pool.Exec(ctx, `CREATE ROLE `+stranger+` NOLOGIN`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dropLogin(t, pool, stranger) })

	run := func(asRole string) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if asRole != "" {
			if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+asRole); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.Exec(ctx, string(step)); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}

	err = run(stranger)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("0153 as a role that may not change the ACL = %v; want SQLSTATE 42501", err)
	}
	t.Logf("0153 as a role that may not change the ACL refused: %s", pgErr.Message)
	if !publicHoldsTemp() {
		t.Fatal("the refused step changed the ACL; want it rolled back")
	}
	if err := run(""); err != nil {
		t.Fatalf("0153 as the owner: %v", err)
	}
	if publicHoldsTemp() {
		t.Fatal("0153 as the owner left sbci_app holding TEMP")
	}
}

// connectAsMemberOf creates a throwaway LOGIN role that inherits role (and
// nothing else), connects it to the pool's database and drops it on cleanup.
func connectAsMemberOf(t *testing.T, pool *pgxpool.Pool, role string) *pgx.Conn {
	t.Helper()
	ctx := context.Background()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	name, password := "sbci_t_"+hex.EncodeToString(b[:8]), hex.EncodeToString(b[8:])
	ident := pgx.Identifier{name}.Sanitize()
	for _, stmt := range []string{
		`CREATE ROLE ` + ident + ` LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '` + password + `'`,
		`GRANT ` + pgx.Identifier{role}.Sanitize() + ` TO ` + ident,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("login fixture: %v", err)
		}
	}
	t.Cleanup(func() { dropLogin(t, pool, ident) })
	cfg := pool.Config().ConnConfig.Copy()
	cfg.User, cfg.Password = name, password
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as a login member of %s: %v", role, err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// dropLogin drops a throwaway login, retrying for a few seconds: a role
// cannot be dropped while a just-closed session of it still owns a temp
// table the server has not cleaned up yet (what a regression that let the
// login create one would leave behind).
func dropLogin(t *testing.T, pool *pgxpool.Pool, ident string) {
	t.Helper()
	var err error
	for range 50 {
		if _, err = pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+ident); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("drop throwaway login %s: %v", ident, err)
}

// grantAttackerTemp gives role TEMP on the pool's database again, so a test
// can model an attacker who kept it (a deployment that has not applied 0153,
// or an explicit grant re-added by hand). The definer tests run on that
// footing on purpose: 0152's search_path fix must hold even when a caller can
// create temp tables, and TestNoRoleHoldsTempOnTheCloudDatabase proves the
// revoke on its own. The database is the test's own and is dropped after it.
func grantAttackerTemp(t *testing.T, pool *pgxpool.Pool, role string) {
	t.Helper()
	ctx := context.Background()
	var db string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil {
		t.Fatalf("current_database: %v", err)
	}
	if _, err := pool.Exec(ctx, `GRANT TEMPORARY ON DATABASE `+pgx.Identifier{db}.Sanitize()+` TO `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatalf("grant TEMP back to %s: %v", role, err)
	}
}
