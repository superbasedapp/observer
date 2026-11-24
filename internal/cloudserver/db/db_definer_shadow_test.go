package db_test

// db_definer_shadow_test.go pins cloud migration 0152 (docs/security.md
// CLOUD-DEFINER-TEMP-2): no SECURITY DEFINER function in the cloud schema may
// resolve a name to the CALLER's temporary schema.
//
// PostgreSQL searches the session's pg_temp schema FIRST for relation and type
// names whenever a search_path does not list pg_temp explicitly, and the
// temporary schema belongs to the session, not to the role, so it stays in
// effect inside a SECURITY DEFINER body. Before 0153 every application role
// held the default TEMP privilege. So a caller that creates a temp table
// named like a table (or a type) the definer uses decides what the BYPASSRLS
// owner sbci_defs reads and writes, and a trigger on that shadow (or a cast
// to the shadow's row type) runs the caller's own code as sbci_defs.
//
// Since 0153 no application role holds TEMP (db_temp_privilege_test.go).
// These tests still give the attacking role TEMP on their own database
// (grantAttackerTemp, in openAttacker): they model an attacker who kept it,
// so the definers are proven safe without relying on the revoke.
//
// Seven definers named their tables unqualified with no trailing pg_temp
// (0003, 0007, 0008, 0017, 0020, 0035): 0152 re-creates them with public.*
// names and `search_path = pg_catalog, public, pg_temp`. Thirty-nine more
// already qualified every table but still had `pg_catalog, public`, which
// leaves TYPE names shadowable; 0152 sets the same search_path on them.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
)

// probePrefix starts every notice a hostile probe raises. A probe only ever
// runs when a definer touched the caller's shadow, so any notice with this
// prefix is a failure.
const probePrefix = "sbci-shadow-probe"

// definerSearchPathAllowList names SECURITY DEFINER functions allowed to keep
// a search_path that does not end in pg_temp, each with the reason. It is
// empty and should stay empty: a definer that cannot pin pg_temp last is a
// finding, not an exception.
var definerSearchPathAllowList = map[string]string{}

// attackerSession is one dedicated connection playing a caller role. It
// records every notice the server sends, so a probe that fired inside a
// statement that later failed is still seen.
type attackerSession struct {
	conn    *pgx.Conn
	mu      sync.Mutex
	notices []string
}

// openAttacker opens a dedicated connection to the test database as the
// pool's (superuser) login and switches it to role for the whole session, so
// its temp objects live in the role's own session as an attacker's would. It
// first gives role TEMP on the test database (grantAttackerTemp): the
// attacker modelled here kept TEMP, which 0153 revokes.
func openAttacker(t *testing.T, pool *pgxpool.Pool, role string) *attackerSession {
	t.Helper()
	grantAttackerTemp(t, pool, role)
	ctx := context.Background()
	s := &attackerSession{}
	cfg := pool.Config().ConnConfig.Copy()
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.notices = append(s.notices, n.Message)
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open %s session: %v", role, err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	if _, err := conn.Exec(ctx, `SET ROLE `+pgx.Identifier{role}.Sanitize()); err != nil {
		t.Fatalf("SET ROLE %s: %v", role, err)
	}
	s.conn = conn
	return s
}

// exec runs one attacker statement and fails the test if it errors.
func (s *attackerSession) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := s.conn.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("attacker statement failed: %v\n%s", err, sql)
	}
}

// resetNotices forgets every notice seen so far.
func (s *attackerSession) resetNotices() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notices = nil
}

// probes returns the probe notices seen since the last reset.
func (s *attackerSession) probes() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, n := range s.notices {
		if strings.HasPrefix(n, probePrefix) {
			out = append(out, n)
		}
	}
	return out
}

// shadowTable creates the caller's temp table named like the real one and
// grants it to PUBLIC, which its owner may do, so a definer that resolves the
// name to it can read and write it rather than fail on its ACL.
func (s *attackerSession) shadowTable(t *testing.T, table, columns string) {
	t.Helper()
	s.exec(t, `CREATE TEMP TABLE `+table+` (`+columns+`) ON COMMIT PRESERVE ROWS`)
	s.exec(t, `GRANT ALL ON pg_temp.`+table+` TO PUBLIC`)
}

// armProbe puts a BEFORE INSERT OR UPDATE OR DELETE statement trigger on the
// caller's shadow table. A statement trigger fires even when no row matches,
// so any write a definer aims at the shadow is seen. The probe reports the
// role it runs as and how many rows of public.evidence_blobs that role can
// read (-1 when it may not read the table at all).
func (s *attackerSession) armProbe(t *testing.T, table string) {
	t.Helper()
	s.exec(t, `CREATE OR REPLACE FUNCTION pg_temp.sbci_shadow_probe() RETURNS trigger
		LANGUAGE plpgsql AS $$
		DECLARE v_blobs bigint;
		BEGIN
		    BEGIN
		        SELECT count(*) INTO v_blobs FROM public.evidence_blobs;
		    EXCEPTION WHEN insufficient_privilege THEN
		        v_blobs := -1;
		    END;
		    RAISE NOTICE '`+probePrefix+`: % % on the caller''s temp % ran as current_user=% (public.evidence_blobs rows it can read: %)',
		        TG_WHEN, TG_OP, TG_TABLE_NAME, current_user, v_blobs;
		    RETURN NULL;
		END $$`)
	s.exec(t, `CREATE TRIGGER sbci_shadow_probe BEFORE INSERT OR UPDATE OR DELETE ON pg_temp.`+table+
		` FOR EACH STATEMENT EXECUTE FUNCTION pg_temp.sbci_shadow_probe()`)
	s.resetNotices()
}

// shadowEnv is what one hostile-shadow case gets: the superuser pool for
// seeding and reading the real tables, the attacker session, its role, and a
// victim account in another tenant.
type shadowEnv struct {
	ctx      context.Context
	pool     *pgxpool.Pool
	attacker *attackerSession
	role     string
	victim   string
}

// shadowCase is one SECURITY DEFINER function and the table a caller shadows
// to subvert it. seed writes the real rows (as superuser) and the shadow rows
// (as the attacker), and returns the attack: the call as the caller role and
// the checks on what the definer did to the REAL tables.
type shadowCase struct {
	function string // regprocedure text, the key into definerGrants
	callers  string // the definerGrants key whose roles reach the function
	table    string // the relation the attacker shadows
	columns  string // the shadow's columns: enough for the body to run on it
	seed     func(t *testing.T, e shadowEnv) (attack func(t *testing.T))
}

// shadowCases is one row per definer 0152 re-creates with public.* names.
var shadowCases = []shadowCase{
	{
		function: "sbci_lease_next_job(text,timestamp with time zone,text[],integer)",
		callers:  "sbci_lease_next_job(text,timestamp with time zone,text[],integer)",
		table:    "analysis_jobs",
		columns: `id uuid, account_id uuid, evidence_pk uuid, feature text, route_id text,
			route_version bigint, prompt_version bigint, consent_generation bigint,
			consent_receipt_id uuid, reservation_id uuid, state text, lease_worker text,
			lease_acquired_at timestamptz, lease_expires_at timestamptz,
			available_at timestamptz, attempts int, lease_generation bigint,
			created_at timestamptz, updated_at timestamptz`,
		seed: seedLeaseShadow,
	},
	{
		function: "sbci_sweep_expired_exports(timestamp with time zone)",
		callers:  "sbci_sweep_expired_exports(timestamp with time zone)",
		table:    "export_artifacts",
		columns:  `export_id uuid, account_id uuid, expires_at timestamptz`,
		seed: func(t *testing.T, e shadowEnv) func(t *testing.T) {
			var live, expired string
			if err := e.pool.QueryRow(e.ctx, `
				WITH l AS (INSERT INTO export_artifacts (account_id, schema_version, ciphertext, size_bytes, expires_at)
				           VALUES ($1::uuid, 'v1', '\x00', 1, now() + interval '1 hour') RETURNING export_id),
				     x AS (INSERT INTO export_artifacts (account_id, schema_version, ciphertext, size_bytes, expires_at)
				           VALUES ($1::uuid, 'v1', '\x00', 1, now() - interval '1 hour') RETURNING export_id)
				SELECT (SELECT export_id::text FROM l), (SELECT export_id::text FROM x)`, e.victim).Scan(&live, &expired); err != nil {
				t.Fatalf("seed exports: %v", err)
			}
			e.attacker.exec(t, `INSERT INTO pg_temp.export_artifacts VALUES (gen_random_uuid(), $1::uuid, now() - interval '1 day')`, e.victim)
			return func(t *testing.T) {
				var n int
				if err := e.attacker.conn.QueryRow(e.ctx, `SELECT sbci_sweep_expired_exports(now())`).Scan(&n); err != nil {
					t.Fatalf("sbci_sweep_expired_exports as %s with a pg_temp shadow: %v", e.role, err)
				}
				assertRowGone(t, e, `export_artifacts`, `export_id`, expired, true)
				assertRowGone(t, e, `export_artifacts`, `export_id`, live, false)
			}
		},
	},
	{
		function: "sbci_sweep_expired_pop_replay(timestamp with time zone)",
		callers:  "sbci_sweep_expired_pop_replay(timestamp with time zone)",
		table:    "pop_replay",
		columns:  `account_id uuid, jti text, expires_at timestamptz`,
		seed: func(t *testing.T, e shadowEnv) func(t *testing.T) {
			live, expired := "live-"+e.role, "expired-"+e.role
			if _, err := e.pool.Exec(e.ctx, `
				INSERT INTO pop_replay (account_id, jti, expires_at) VALUES
				    ($1::uuid, $2, now() + interval '1 hour'),
				    ($1::uuid, $3, now() - interval '1 hour')`, e.victim, live, expired); err != nil {
				t.Fatalf("seed pop_replay: %v", err)
			}
			e.attacker.exec(t, `INSERT INTO pg_temp.pop_replay VALUES ($1::uuid, 'shadow', now() - interval '1 day')`, e.victim)
			return func(t *testing.T) {
				var n int
				if err := e.attacker.conn.QueryRow(e.ctx, `SELECT sbci_sweep_expired_pop_replay(now())`).Scan(&n); err != nil {
					t.Fatalf("sbci_sweep_expired_pop_replay as %s with a pg_temp shadow: %v", e.role, err)
				}
				assertRowGone(t, e, `pop_replay`, `jti`, expired, true)
				assertRowGone(t, e, `pop_replay`, `jti`, live, false)
			}
		},
	},
	{
		function: "sbci_introspect_token(text)",
		callers:  "sbci_introspect_token(text)",
		table:    "api_tokens",
		columns:  `id uuid, account_id uuid, device_id uuid, token_hash text, expires_at timestamptz, revoked_at timestamptz`,
		seed: func(t *testing.T, e shadowEnv) func(t *testing.T) {
			var device, token string
			if err := e.pool.QueryRow(e.ctx, `
				WITH d AS (INSERT INTO device_registrations (account_id, public_key, thumbprint)
				           VALUES ($1::uuid, '\x01', 'probe-'||$2) RETURNING id)
				SELECT (SELECT id::text FROM d)`, e.victim, e.role).Scan(&device); err != nil {
				t.Fatalf("seed device: %v", err)
			}
			if err := e.pool.QueryRow(e.ctx, `
				INSERT INTO api_tokens (account_id, device_id, token_hash, expires_at)
				VALUES ($1::uuid, $2::uuid, 'real-'||$3, now() + interval '1 hour') RETURNING id::text`,
				e.victim, device, e.role).Scan(&token); err != nil {
				t.Fatalf("seed token: %v", err)
			}
			// The forged row names the victim's real device and account under
			// a token hash the attacker chose: it would mint a principal.
			e.attacker.exec(t, `INSERT INTO pg_temp.api_tokens VALUES (gen_random_uuid(), $1::uuid, $2::uuid, 'forged-'||$3, now() + interval '1 day', NULL)`,
				e.victim, device, e.role)
			return func(t *testing.T) {
				assertIntrospection(t, e, `SELECT account_id::text, token_id::text FROM sbci_introspect_token($1)`, "forged-"+e.role, "", "")
				assertIntrospection(t, e, `SELECT account_id::text, token_id::text FROM sbci_introspect_token($1)`, "real-"+e.role, e.victim, token)
			}
		},
	},
	{
		function: "sbci_find_identity_link(text,text)",
		callers:  "sbci_find_identity_link(text,text)",
		table:    "identity_links",
		columns:  `id uuid, account_id uuid, provider text, subject text`,
		seed: func(t *testing.T, e shadowEnv) func(t *testing.T) {
			var link string
			if err := e.pool.QueryRow(e.ctx, `
				INSERT INTO identity_links (account_id, provider, subject)
				VALUES ($1::uuid, 'shadow-probe', 'real-'||$2) RETURNING id::text`, e.victim, e.role).Scan(&link); err != nil {
				t.Fatalf("seed identity link: %v", err)
			}
			e.attacker.exec(t, `INSERT INTO pg_temp.identity_links VALUES (gen_random_uuid(), $1::uuid, 'shadow-probe', 'forged-'||$2)`, e.victim, e.role)
			return func(t *testing.T) {
				q := `SELECT account_id::text, link_id::text FROM sbci_find_identity_link('shadow-probe', $1)`
				assertIntrospection(t, e, q, "forged-"+e.role, "", "")
				assertIntrospection(t, e, q, "real-"+e.role, e.victim, link)
			}
		},
	},
	{
		function: "sbci_introspect_browser_session(text)",
		callers:  "sbci_introspect_browser_session(text)",
		table:    "browser_sessions",
		columns: `id uuid, account_id uuid, session_hash text, csrf_hash text, expires_at timestamptz,
			revoked_at timestamptz, idle_expires_at timestamptz, last_seen_at timestamptz`,
		seed: func(t *testing.T, e shadowEnv) func(t *testing.T) {
			var session string
			if err := e.pool.QueryRow(e.ctx, `
				INSERT INTO browser_sessions (account_id, session_hash, expires_at)
				VALUES ($1::uuid, 'real-'||$2, now() + interval '1 hour') RETURNING id::text`, e.victim, e.role).Scan(&session); err != nil {
				t.Fatalf("seed browser session: %v", err)
			}
			e.attacker.exec(t, `INSERT INTO pg_temp.browser_sessions (id, account_id, session_hash, expires_at)
				VALUES (gen_random_uuid(), $1::uuid, 'forged-'||$2, now() + interval '1 day')`, e.victim, e.role)
			return func(t *testing.T) {
				q := `SELECT account_id::text, session_id::text FROM sbci_introspect_browser_session($1)`
				assertIntrospection(t, e, q, "forged-"+e.role, "", "")
				assertIntrospection(t, e, q, "real-"+e.role, e.victim, session)
			}
		},
	},
	{
		// sbci_rate_limit_at is granted to no application role: callers reach
		// it through sbci_rate_limit, and the INNER function's own search_path
		// is what resolves the counters table.
		function: "sbci_rate_limit_at(text,text,integer,bigint,timestamp with time zone)",
		callers:  "sbci_rate_limit(text,text,integer,bigint)",
		table:    "sbci_rate_limit_counters",
		columns: `bucket text, counter_key_hash text, window_start timestamptz, hit_count bigint,
			over_cap boolean, expires_at timestamptz, updated_at timestamptz,
			PRIMARY KEY (bucket, counter_key_hash, window_start)`,
		seed: func(t *testing.T, e shadowEnv) func(t *testing.T) {
			// Exhaust a one-request, one-day window on the real counters, so
			// the next call for the key must be denied.
			const window = int64(24 * 60 * 60 * 1000)
			key := strings.Repeat("0", 56) + hexRole(e.role)
			for i, want := range []bool{true, false} {
				var allowed bool
				if err := e.pool.QueryRow(e.ctx, `SELECT allowed FROM sbci_rate_limit('shadow-probe', $1, 1, $2)`, key, window).Scan(&allowed); err != nil {
					t.Fatalf("seed rate limit call %d: %v", i+1, err)
				}
				if allowed != want {
					t.Fatalf("seed rate limit call %d: allowed=%v, want %v", i+1, allowed, want)
				}
			}
			return func(t *testing.T) {
				var allowed bool
				if err := e.attacker.conn.QueryRow(e.ctx, `SELECT allowed FROM sbci_rate_limit('shadow-probe', $1, 1, $2)`, key, window).Scan(&allowed); err != nil {
					t.Fatalf("sbci_rate_limit as %s with a pg_temp shadow: %v", e.role, err)
				}
				if allowed {
					t.Errorf("sbci_rate_limit as %s admitted a key whose real window is exhausted: the counters resolved to the caller's temp shadow", e.role)
				}
			}
		},
	},
}

// hexRole turns a role name into eight lowercase hex digits, so each role's
// rate-limit key differs and stays a valid 64-hex counter key.
func hexRole(role string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(role); i++ {
		h ^= uint32(role[i])
		h *= 16777619
	}
	const digits = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = digits[h&0xf]
		h >>= 4
	}
	return string(out)
}

// seedLeaseShadow is the lease case: a real queued job and a queued shadow
// job of the same class. Before 0152 the definer picked the shadow row, and
// the probe's BEFORE UPDATE trigger ran as sbci_defs; after it the shadow is
// never read and the real job is leased.
func seedLeaseShadow(t *testing.T, e shadowEnv) func(t *testing.T) {
	feature := "shadow-probe-" + e.role
	var evidence, job string
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO evidence_objects (account_id, blob_ref, upload_digest, evidence_content_digest, expires_at)
		VALUES ($1::uuid, 'evidence/'||$2, 'sha256:u', 'sha256:c', now() + interval '1 hour') RETURNING id::text`,
		e.victim, feature).Scan(&evidence); err != nil {
		t.Fatalf("seed evidence object: %v", err)
	}
	if err := e.pool.QueryRow(e.ctx, `
		INSERT INTO analysis_jobs (account_id, evidence_pk, feature, route_id, route_version, prompt_version,
		                           canonical_job_key, consent_generation, upload_digest, available_at)
		VALUES ($1::uuid, $2::uuid, $3, 'route', 1, 1, 'key-'||$3, 1, 'sha256:u', now() - interval '1 minute')
		RETURNING id::text`, e.victim, evidence, feature).Scan(&job); err != nil {
		t.Fatalf("seed queued job: %v", err)
	}
	e.attacker.exec(t, `INSERT INTO pg_temp.analysis_jobs
		(id, account_id, evidence_pk, feature, route_id, route_version, prompt_version, consent_generation,
		 state, available_at, attempts, lease_generation, created_at, updated_at)
		VALUES (gen_random_uuid(), $1::uuid, gen_random_uuid(), $2, 'route', 1, 1, 1,
		        'queued', now() - interval '1 hour', 0, 0, now(), now())`, e.victim, feature)
	return func(t *testing.T) {
		var leased string
		err := e.attacker.conn.QueryRow(e.ctx,
			`SELECT job_id::text FROM sbci_lease_next_job('shadow-probe', now(), ARRAY[$1], 60)`, feature).Scan(&leased)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("sbci_lease_next_job as %s with a pg_temp shadow: %v", e.role, err)
		}
		if leased != job {
			t.Errorf("sbci_lease_next_job as %s leased %q, want the real job %s: it read the caller's temp shadow", e.role, leased, job)
		}
		var state, worker string
		if err := e.pool.QueryRow(e.ctx,
			`SELECT state, coalesce(lease_worker, '') FROM public.analysis_jobs WHERE id = $1::uuid`, job).Scan(&state, &worker); err != nil {
			t.Fatalf("read real job: %v", err)
		}
		if state != "leased" || worker != "shadow-probe" {
			t.Errorf("real job after the lease: state=%q worker=%q, want leased by shadow-probe", state, worker)
		}
	}
}

// assertRowGone reads one real row by key and checks whether the sweep
// deleted it.
func assertRowGone(t *testing.T, e shadowEnv, table, key, value string, wantGone bool) {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(e.ctx, `SELECT count(*) FROM public.`+table+` WHERE `+key+`::text = $1`, value).Scan(&n); err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	if gone := n == 0; gone != wantGone {
		if wantGone {
			t.Errorf("the expired %s row %s survived the sweep as %s: the sweep deleted from the caller's temp shadow instead", table, value, e.role)
		} else {
			t.Errorf("the live %s row %s was deleted by the sweep as %s", table, value, e.role)
		}
	}
}

// assertIntrospection runs a two-column lookup as the attacker and checks its
// answer: wantAccount empty means no row.
func assertIntrospection(t *testing.T, e shadowEnv, query, arg, wantAccount, wantID string) {
	t.Helper()
	rows, err := e.attacker.conn.Query(e.ctx, query, arg)
	if err != nil {
		t.Fatalf("%s as %s: %v", query, e.role, err)
	}
	var got [][2]string
	for rows.Next() {
		var a, id string
		if err := rows.Scan(&a, &id); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got = append(got, [2]string{a, id})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s as %s: %v", query, e.role, err)
	}
	switch {
	case wantAccount == "" && len(got) != 0:
		t.Errorf("lookup of the caller-chosen %q as %s answered %v, want no row: the definer read the caller's temp shadow and handed out another tenant's account", arg, e.role, got)
	case wantAccount != "" && (len(got) != 1 || got[0] != [2]string{wantAccount, wantID}):
		t.Errorf("lookup of the real %q as %s answered %v, want [[%s %s]]", arg, e.role, got, wantAccount, wantID)
	}
}

// TestDefinersIgnoreCallerTempTableShadows plays the shadow attack against
// each definer 0152 re-creates, as every role that can reach it: the caller
// shadows the table the body names, arms a trigger probe on the shadow, and
// calls the function. The definer must work on the real table and never
// touch the shadow.
func TestDefinersIgnoreCallerTempTableShadows(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	var victim string
	if err := pool.QueryRow(ctx,
		`INSERT INTO accounts (status) VALUES ('active') RETURNING account_id::text`).Scan(&victim); err != nil {
		t.Fatalf("create victim account: %v", err)
	}
	// One evidence blob, so a probe running as the BYPASSRLS owner shows it
	// can read across tenants.
	if _, err := pool.Exec(ctx,
		`INSERT INTO evidence_blobs (account_id, blob_ref, ciphertext) VALUES ($1::uuid, 'evidence/victim', '\x00')`, victim); err != nil {
		t.Fatalf("seed victim evidence blob: %v", err)
	}

	for _, c := range shadowCases {
		roles, ok := definerGrants[c.callers]
		if !ok || len(roles) == 0 {
			t.Fatalf("%s: definerGrants has no callers under %q", c.function, c.callers)
		}
		for _, role := range roles {
			t.Run(c.function+"/"+role, func(t *testing.T) {
				a := openAttacker(t, pool, role)
				a.shadowTable(t, c.table, c.columns)
				attack := c.seed(t, shadowEnv{ctx: ctx, pool: pool, attacker: a, role: role, victim: victim})
				a.armProbe(t, c.table)
				attack(t)
				if p := a.probes(); len(p) != 0 {
					t.Errorf("%s as %s touched the caller's temp %s; the probe trigger fired:\n  %s",
						c.function, role, c.table, strings.Join(p, "\n  "))
				}
			})
		}
	}
}

// TestDefinerTypeNamesIgnoreCallerTempShadows covers the other half of the
// class, on a definer that already qualified every table: with `search_path =
// pg_catalog, public` a caller's temp table named `date` became the `date`
// type inside sbci_expire_org_usage_days, and a cast the caller defined to
// that row type ran the caller's code as sbci_defs. With pg_temp last,
// pg_catalog.date wins and the caller's casts are never used.
func TestDefinerTypeNamesIgnoreCallerTempShadows(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		WITH a AS (INSERT INTO accounts (status) VALUES ('active') RETURNING account_id)
		INSERT INTO evidence_blobs (account_id, blob_ref, ciphertext) SELECT account_id, 'evidence/victim', '\x00' FROM a`); err != nil {
		t.Fatalf("seed victim evidence blob: %v", err)
	}

	const fn = "sbci_expire_org_usage_days(date)"
	roles := definerGrants[fn]
	if len(roles) == 0 {
		t.Fatalf("definerGrants has no callers for %s", fn)
	}
	for _, role := range roles {
		t.Run(role, func(t *testing.T) {
			a := openAttacker(t, pool, role)
			a.exec(t, `CREATE TEMP TABLE date (x int)`)
			a.exec(t, `CREATE FUNCTION pg_temp.sbci_type_probe(timestamp) RETURNS pg_temp.date
				LANGUAGE plpgsql AS $$
				BEGIN
				    RAISE NOTICE '`+probePrefix+`: a cast to the caller''s temp type date ran as current_user=% (public.evidence_blobs rows it can read: %)',
				        current_user, (SELECT count(*) FROM public.evidence_blobs);
				    RETURN NULL;
				END $$`)
			a.exec(t, `CREATE FUNCTION pg_temp.sbci_type_probe_back(pg_temp.date) RETURNS pg_catalog.date
				LANGUAGE plpgsql AS $$
				BEGIN
				    RAISE NOTICE '`+probePrefix+`: a cast from the caller''s temp type date ran as current_user=%', current_user;
				    RETURN '2999-01-01'::pg_catalog.date;
				END $$`)
			a.exec(t, `CREATE CAST (timestamp AS pg_temp.date) WITH FUNCTION pg_temp.sbci_type_probe(timestamp) AS ASSIGNMENT`)
			a.exec(t, `CREATE CAST (pg_temp.date AS pg_catalog.date) WITH FUNCTION pg_temp.sbci_type_probe_back(pg_temp.date) AS IMPLICIT`)
			a.resetNotices()

			var n int64
			if err := a.conn.QueryRow(ctx, `SELECT sbci_expire_org_usage_days('2000-01-01'::pg_catalog.date)`).Scan(&n); err != nil {
				t.Errorf("sbci_expire_org_usage_days as %s with a temp type shadow: %v", role, err)
			}
			if p := a.probes(); len(p) != 0 {
				t.Errorf("%s as %s resolved a type name to the caller's temp schema; the caller's cast ran:\n  %s",
					fn, role, strings.Join(p, "\n  "))
			}
		})
	}
}

// TestEveryDefinerSearchPathEndsInPgTemp is the catalog ratchet: every
// SECURITY DEFINER function outside the system schemas sets its own
// search_path, and that search_path ends in pg_temp, so no relation or type
// name in its body can resolve to the caller's temporary schema. A function
// that truly cannot comply goes on definerSearchPathAllowList with a reason.
func TestEveryDefinerSearchPathEndsInPgTemp(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT p.oid::regprocedure::text,
		       coalesce((SELECT substr(c, length('search_path=') + 1)
		                   FROM unnest(p.proconfig) c
		                  WHERE c LIKE 'search_path=%'), '')
		  FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE p.prosecdef
		   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		 ORDER BY 1`)
	if err != nil {
		t.Fatalf("read definer search paths: %v", err)
	}
	seen := map[string]bool{}
	for rows.Next() {
		var sig, path string
		if err := rows.Scan(&sig, &path); err != nil {
			t.Fatalf("scan: %v", err)
		}
		seen[sig] = true
		ok := lastSearchPathEntry(path) == "pg_temp"
		reason, allowed := definerSearchPathAllowList[sig]
		switch {
		case !ok && !allowed:
			if path == "" {
				t.Errorf("SECURITY DEFINER function %s sets no search_path, so it runs with the caller's: pin `SET search_path = pg_catalog, public, pg_temp`", sig)
			} else {
				t.Errorf("SECURITY DEFINER function %s has search_path %q, which does not end in pg_temp: the caller's temp schema is searched first for relation and type names (CLOUD-DEFINER-TEMP-2); pin `SET search_path = pg_catalog, public, pg_temp`", sig, path)
			}
		case ok && allowed:
			t.Errorf("%s is on definerSearchPathAllowList (%s) but its search_path %q now ends in pg_temp: remove it from the list", sig, reason, path)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(seen) == 0 {
		t.Fatal("found no SECURITY DEFINER function at all: the catalog query is wrong")
	}
	for sig := range definerSearchPathAllowList {
		if !seen[sig] {
			t.Errorf("definerSearchPathAllowList lists %s, but no such SECURITY DEFINER function exists", sig)
		}
	}
}

// lastSearchPathEntry returns the last schema of a proconfig search_path
// value such as `pg_catalog, public, "pg_temp"`, unquoted.
func lastSearchPathEntry(path string) string {
	parts := strings.Split(path, ",")
	return strings.Trim(strings.TrimSpace(parts[len(parts)-1]), `"`)
}

// TestReCreatedDefinersKeepTheirShape pins what 0152 must not change on the
// seven functions it re-creates: still SECURITY DEFINER, still owned by
// sbci_defs, and the exact search_path. Grants are pinned for every definer by
// TestDefinerFunctionExecuteGrants.
func TestReCreatedDefinersKeepTheirShape(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()
	for _, c := range shadowCases {
		var owner, cfg string
		var secdef bool
		if err := pool.QueryRow(ctx,
			`SELECT pg_get_userbyid(proowner), prosecdef, coalesce(array_to_string(proconfig, ','), '')
			   FROM pg_proc WHERE oid = $1::regprocedure`, c.function).Scan(&owner, &secdef, &cfg); err != nil {
			t.Fatalf("introspect %s: %v", c.function, err)
		}
		if owner != "sbci_defs" || !secdef || cfg != "search_path=pg_catalog, public, pg_temp" {
			t.Errorf("%s: owner=%q secdef=%v config=%q; want sbci_defs, true, search_path=pg_catalog, public, pg_temp", c.function, owner, secdef, cfg)
		}
	}
}
