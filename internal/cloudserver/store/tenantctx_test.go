package store_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/tenantctx"
	"github.com/marmutapp/superbased-observer/internal/tenantctx/attacktest"
)

// The cloud service's adoption of internal/tenantctx (plan 07 M3b.2 and
// M6.1b): the MAC'd account context, verified by sbci_current_account()
// (migration 0067) against the keys in sbci_tenant_context_keys (0066).

const (
	kitAccountA = "0f3a9c1e-1111-4222-8333-444455556666"
	kitAccountB = "0f3a9c1e-aaaa-4bbb-8ccc-ddddeeeeffff"
)

func kitKey() []byte { return bytes.Repeat([]byte{0x5a}, 32) }

// TestSetTenantContextKeyRefusesBadKeys (native): a key outside 32 to 1024
// bytes is refused and leaves the store's key unchanged; a good key changes
// the key id to tenantctx.KeyID of it.
func TestSetTenantContextKeyRefusesBadKeys(t *testing.T) {
	t.Parallel()
	s := store.New(nil)
	before := s.TenantContextKeyID()
	if len(before) != 16 {
		t.Fatalf("the default key id is %q", before)
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, tenantctx.MaxKeyBytes+1)} {
		if err := s.SetTenantContextKey(bad); !errors.Is(err, tenantctx.ErrInvalidContext) {
			t.Errorf("SetTenantContextKey(%d bytes) = %v", len(bad), err)
		}
		if s.TenantContextKeyID() != before {
			t.Fatal("a refused key replaced the store's key")
		}
	}
	if err := s.SetTenantContextKey(kitKey()); err != nil {
		t.Fatal(err)
	}
	if got := s.TenantContextKeyID(); got != tenantctx.KeyID(kitKey()) {
		t.Fatalf("key id %q, want %q", got, tenantctx.KeyID(kitKey()))
	}
	if _, err := store.InstallTenantContextKey(context.Background(), nil, make([]byte, 8), false); !errors.Is(err, tenantctx.ErrInvalidContext) {
		t.Fatalf("InstallTenantContextKey(short) = %v", err)
	}
}

// kitFixture is one database with the kit's probe table, two accounts' rows
// in it, the kit key installed, and a throwaway runtime login.
type kitFixture struct {
	admin *pgxpool.Pool
	login *pgx.ConnConfig
}

// newKitFixture creates the probe table tenantctx_probe, a tenant table
// shaped like every account-owned table (ENABLE and FORCE row-level
// security, the one policy account_id = sbci_current_account(), sbci_app
// DML), seeds one row for each kit account as the harness superuser,
// installs kitKey(), and creates a LOGIN role that is a member of sbci_app
// only, like the deploy's runtime login.
func newKitFixture(t *testing.T) *kitFixture {
	t.Helper()
	ctx := t.Context()
	admin := cloudtestpg.NewDB(t)
	for _, stmt := range []string{
		`CREATE TABLE tenantctx_probe (
			account_id uuid NOT NULL DEFAULT sbci_current_account(),
			body       text NOT NULL DEFAULT '')`,
		`ALTER TABLE tenantctx_probe ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE tenantctx_probe FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY tenantctx_probe_tenant ON tenantctx_probe
			USING (account_id = sbci_current_account()) WITH CHECK (account_id = sbci_current_account())`,
		`GRANT SELECT, INSERT, UPDATE, DELETE ON tenantctx_probe TO sbci_app`,
		`INSERT INTO tenantctx_probe (account_id, body) VALUES ('` + kitAccountA + `', 'a'), ('` + kitAccountB + `', 'b')`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture: %v\n%s", err, stmt)
		}
	}
	if _, err := store.InstallTenantContextKey(ctx, admin, kitKey(), false); err != nil {
		t.Fatalf("install the kit key: %v", err)
	}
	return &kitFixture{admin: admin, login: newRuntimeLogin(t, admin)}
}

// newRuntimeLogin creates a throwaway LOGIN role, a member of sbci_app only
// (INHERIT, no SUPERUSER or BYPASSRLS), and returns its connection config in
// the simple protocol (so DISCARD ALL never strands a prepared statement).
func newRuntimeLogin(t *testing.T, admin *pgxpool.Pool) *pgx.ConnConfig {
	t.Helper()
	ctx := t.Context()
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	name := "sbci_t_" + hex.EncodeToString(raw)
	password := hex.EncodeToString(append(raw, raw...))
	if _, err := admin.Exec(ctx, fmt.Sprintf(
		`CREATE ROLE %s LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '%s' IN ROLE sbci_app`,
		name, password)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP OWNED BY "+name); err != nil {
			t.Errorf("drop what %s owns: %v", name, err)
		}
		if _, err := admin.Exec(cleanupCtx, "DROP ROLE IF EXISTS "+name); err != nil {
			t.Errorf("drop %s: %v", name, err)
		}
	})
	cfg := admin.Config().ConnConfig.Copy()
	cfg.User = name
	cfg.Password = password
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return cfg
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// TestTenantContextAttackKit runs the shared attack-test kit (M3b.2,
// internal/tenantctx/attacktest) against sbci_current_account() as a
// runtime login that is a member of sbci_app: forged, expired and
// wrong-scope (org-kind) tokens, a context reused across transactions, a raw
// set_config of a bare account id (the pre-0067 mechanism), RESET and
// DISCARD ALL, and a missing context all see and write nothing; a valid
// context sees exactly its own account. The org server's tenantdb runs the
// same kit against sbo_current_org().
func TestTenantContextAttackKit(t *testing.T) {
	t.Parallel()
	f := newKitFixture(t)
	attacktest.Run(t, attacktest.Harness{
		Kind:  tenantctx.KindAccount,
		Key:   kitKey(),
		A:     kitAccountA,
		B:     kitAccountB,
		Begin: []string{"BEGIN", "SET LOCAL ROLE sbci_app"},
		Open: func(ctx context.Context) (attacktest.Session, error) {
			conn, err := pgx.ConnectConfig(ctx, f.login)
			if err != nil {
				return nil, err
			}
			return &cloudKitSession{conn: conn}, nil
		},
	})
}

// cloudKitSession is one runtime-login connection over the probe table.
type cloudKitSession struct{ conn *pgx.Conn }

func (s *cloudKitSession) Exec(ctx context.Context, query string, args ...any) error {
	_, err := s.conn.Exec(ctx, query, args...)
	return err
}

func (s *cloudKitSession) Visible(ctx context.Context) ([]string, error) {
	var ids string
	if err := s.conn.QueryRow(ctx,
		`SELECT coalesce(string_agg(DISTINCT account_id::text, ',' ORDER BY account_id::text), '') FROM tenantctx_probe`).Scan(&ids); err != nil {
		return nil, err
	}
	if ids == "" {
		return nil, nil
	}
	return strings.Split(ids, ","), nil
}

func (s *cloudKitSession) Current(ctx context.Context) (string, error) {
	var id string
	err := s.conn.QueryRow(ctx, `SELECT coalesce(sbci_current_account()::text, '')`).Scan(&id)
	return id, err
}

func (s *cloudKitSession) Insert(ctx context.Context, accountID string) error {
	_, err := s.conn.Exec(ctx, `INSERT INTO tenantctx_probe (account_id, body) VALUES ($1::uuid, 'attacktest')`, accountID)
	return err
}

func (s *cloudKitSession) Close() error { return s.conn.Close(context.Background()) }

// TestTenantContextKeyPosture: the runtime login can neither read the key
// table nor install a key; sbci_current_account() is a SECURITY DEFINER
// owned by sbci_defs with a pinned search_path and still executable by the
// application roles; and no policy or other function reads the
// sbci.account_id setting (m6.0 design 3.2: the one function is the seam).
func TestTenantContextKeyPosture(t *testing.T) {
	t.Parallel()
	f := newKitFixture(t)
	ctx := t.Context()
	conn, err := pgx.ConnectConfig(ctx, f.login)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	for name, stmt := range map[string]string{
		"read the key table":  `SELECT count(*) FROM sbci_tenant_context_keys`,
		"install a key":       `SELECT sbci_tenant_context_install(decode(repeat('ab', 32), 'hex'), NULL)`,
		"compute HMAC pads":   `SELECT * FROM sbci_hmac_pads('\x00'::bytea)`,
		"write the key table": `DELETE FROM sbci_tenant_context_keys`,
	} {
		if _, err := conn.Exec(ctx, stmt); sqlState(err) != "42501" {
			t.Errorf("the runtime login could %s: %v", name, err)
		}
	}

	var owner string
	var secDef bool
	var config []string
	if err := f.admin.QueryRow(ctx, `SELECT pg_get_userbyid(proowner), prosecdef, proconfig FROM pg_proc WHERE oid = 'sbci_current_account()'::regprocedure`).Scan(&owner, &secDef, &config); err != nil {
		t.Fatal(err)
	}
	if owner != "sbci_defs" || !secDef || len(config) != 1 || config[0] != "search_path=pg_catalog, pg_temp" {
		t.Fatalf("sbci_current_account(): owner %q definer %v config %v", owner, secDef, config)
	}
	for _, role := range []string{"sbci_app", "sbci_api", "sbci_worker"} {
		var ok bool
		if err := f.admin.QueryRow(ctx, `SELECT has_function_privilege($1, 'sbci_current_account()', 'EXECUTE')`, role).Scan(&ok); err != nil || !ok {
			t.Errorf("%s lost EXECUTE on sbci_current_account(): %v %v", role, ok, err)
		}
	}

	rows, err := f.admin.Query(ctx, `
		SELECT c.relname || '.' || p.polname
		  FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
		 WHERE coalesce(pg_get_expr(p.polqual, p.polrelid), '') LIKE '%current_setting%'
		    OR coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') LIKE '%current_setting%'
		UNION ALL
		SELECT p.oid::regprocedure::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'public' AND p.prosrc LIKE '%sbci.account_id%' AND p.proname <> 'sbci_current_account'`)
	if err != nil {
		t.Fatal(err)
	}
	readers, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(readers) != 0 {
		t.Fatalf("these read the tenant setting directly instead of sbci_current_account(): %v", readers)
	}
}

// TestInstallTenantContextKey: an install returns tenantctx.KeyID, is
// idempotent and re-arms; a second key without rotate leaves both live; a
// rotation caps the others at the overlap; a zero-overlap rotation retires
// the old key for the next transaction.
func TestInstallTenantContextKey(t *testing.T) {
	t.Parallel()
	f := newKitFixture(t)
	ctx := t.Context()
	other := bytes.Repeat([]byte{0xa5}, 32)
	s := store.New(f.admin)
	if err := s.SetTenantContextKey(kitKey()); err != nil {
		t.Fatal(err)
	}
	visible := func(st *store.Store) int {
		t.Helper()
		var n int
		if err := st.WithAccount(ctx, kitAccountA, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM tenantctx_probe`).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for i := 0; i < 2; i++ {
		id, err := store.InstallTenantContextKey(ctx, f.admin, kitKey(), false)
		if err != nil || id != tenantctx.KeyID(kitKey()) {
			t.Fatalf("install #%d = %q, %v", i, id, err)
		}
	}
	if err := s.VerifyTenantContext(ctx); err != nil || visible(s) != 1 {
		t.Fatalf("the installed key does not verify: %v", err)
	}

	s2 := store.New(f.admin)
	if err := s2.SetTenantContextKey(other); err != nil {
		t.Fatal(err)
	}
	if err := s2.VerifyTenantContext(ctx); err == nil || visible(s2) != 0 {
		t.Fatalf("a key never installed verified: %v", err)
	}
	if _, err := store.InstallTenantContextKey(ctx, f.admin, other, true); err != nil {
		t.Fatal(err)
	}
	if visible(s) != 1 || visible(s2) != 1 {
		t.Fatal("within the overlap both keys must verify")
	}
	var notAfter time.Time
	if err := f.admin.QueryRow(ctx, `SELECT not_after FROM sbci_tenant_context_keys WHERE key_id = $1`, tenantctx.KeyID(kitKey())).Scan(&notAfter); err != nil {
		t.Fatal(err)
	}
	if d := time.Until(notAfter); d < store.TenantKeyOverlap-time.Hour || d > store.TenantKeyOverlap+time.Hour {
		t.Fatalf("the replaced key expires in %s, want about %s", d, store.TenantKeyOverlap)
	}
	if _, err := f.admin.Exec(ctx, `SELECT sbci_tenant_context_install($1, interval '0')`, other); err != nil {
		t.Fatal(err)
	}
	if visible(s) != 0 || visible(s2) != 1 {
		t.Fatal("a zero-overlap rotation must retire the old key at once")
	}
	if _, err := f.admin.Exec(ctx, `SELECT sbci_tenant_context_install($1, interval '25 hours')`, other); err == nil {
		t.Fatal("an overlap over 24 hours was accepted")
	}
}

// TestDefaultKeyInstallsItselfOnlyWithMigratorRights: a Store on the
// process-random key installs it on first use through the harness
// superuser, and the same Store over the runtime login cannot (the dev
// posture works, the split-role posture must configure the key).
func TestDefaultKeyInstallsItselfOnlyWithMigratorRights(t *testing.T) {
	t.Parallel()
	f := newKitFixture(t)
	ctx := t.Context()
	auto := store.New(f.admin)
	if err := auto.VerifyTenantContext(ctx); err != nil {
		t.Fatalf("the default key did not install itself: %v", err)
	}
	var n int
	if err := auto.WithAccount(ctx, kitAccountB, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM tenantctx_probe WHERE body = 'b'`).Scan(&n)
	}); err != nil || n != 1 {
		t.Fatalf("WithAccount on the default key read %d, %v", n, err)
	}

	rtPool, err := pgxpool.NewWithConfig(ctx, mustPoolConfig(t, f.login))
	if err != nil {
		t.Fatal(err)
	}
	defer rtPool.Close()
	runtime := store.New(rtPool)
	if err := runtime.VerifyTenantContext(ctx); err == nil || !strings.Contains(err.Error(), "SBCI_TENANT_CONTEXT_KEY") {
		t.Fatalf("the runtime login installed a key: %v", err)
	}
	if err := runtime.WithAccount(ctx, kitAccountA, func(context.Context, pgx.Tx) error { return nil }); err == nil {
		t.Fatal("WithAccount ran on a key the database does not hold")
	}
	configured := store.New(rtPool)
	if err := configured.SetTenantContextKey(kitKey()); err != nil {
		t.Fatal(err)
	}
	if err := configured.VerifyTenantContext(ctx); err != nil {
		t.Fatalf("the runtime login with the installed key: %v", err)
	}
}

func mustPoolConfig(t *testing.T, conn *pgx.ConnConfig) *pgxpool.Config {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig = conn.Copy()
	cfg.MaxConns = 2
	return cfg
}
