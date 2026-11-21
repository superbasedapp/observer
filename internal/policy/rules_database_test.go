package policy

import (
	"strings"
	"testing"
	"time"
)

// dbCase is one database-family conformance row: a command line, the rule
// it must hit ("" = none at all) and that rule's enforce-mode decision
// (every row of the family flags in observe mode).
type dbCase struct {
	name, cmd       string
	dialect         Dialect
	home, cwd, root string
	wantRule        string
	wantEnforce     Decision
	// notInReason is a string the verdict reason must not carry (a
	// password in a connection string).
	notInReason string
}

// runDBCases evaluates each case through observe- and enforce-mode engines
// built from base (Mode and Home are set per run).
func runDBCases(t *testing.T, cases []dbCase, base Config) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			home, root := tc.home, tc.root
			if home == "" {
				home = "/home/u"
			}
			if root == "" {
				root = "/home/u/proj"
			}
			cwd := tc.cwd
			if cwd == "" {
				cwd = root
			}
			ev := Event{
				Kind: KindShellExec, ActionType: "run_command", Target: tc.cmd, Dialect: tc.dialect,
				Cwd: cwd, ProjectRoot: root, SessionID: "s1",
				Now: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC),
			}
			for _, mode := range []Mode{ModeObserve, ModeEnforce} {
				cfg := base
				cfg.Mode, cfg.Home = mode, home
				eng, err := New(cfg)
				if err != nil {
					t.Fatalf("New: %v", err)
				}
				v := eng.Evaluate(ev)
				if tc.wantRule == "" {
					if v.RuleID != "" {
						t.Fatalf("%s: want no hit, got %s/%s (%q)", mode, v.RuleID, v.Decision, v.Reason)
					}
					continue
				}
				want := tc.wantEnforce
				if mode == ModeObserve {
					want = DecisionFlag
				}
				if v.RuleID != tc.wantRule || v.Decision != want {
					t.Errorf("%s: got %s/%s, want %s/%s (%q)", mode, v.RuleID, v.Decision, tc.wantRule, want, v.Reason)
				}
				if tc.notInReason != "" && strings.Contains(v.Reason, tc.notInReason) {
					t.Errorf("%s: reason %q carries %q", mode, v.Reason, tc.notInReason)
				}
			}
		})
	}
}

// TestDatabaseRulesInline covers R-120 (as widened onto the database CLI
// table) and R-121 to R-124: one case per rule row and per CLI, plus near
// misses.
func TestDatabaseRulesInline(t *testing.T) {
	t.Parallel()
	win := func(c dbCase) dbCase {
		c.home, c.cwd, c.root = `C:\Users\u`, `C:\Users\u\proj`, `C:\Users\u\proj`
		return c
	}
	cases := []dbCase{
		// --- R-120 on the CLIs the table added ---
		{name: "R-120 clickhouse-client query", cmd: `clickhouse-client -q "DROP TABLE events"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 clickhouse client subcommand", cmd: `clickhouse client --query "TRUNCATE TABLE events"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 sqlcmd -Q", cmd: `sqlcmd -S sql01 -Q "DROP DATABASE app"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		win(dbCase{name: "R-120 sqlcmd slash form under cmd", cmd: `sqlcmd /S sql01 /Q "DROP DATABASE app"`, dialect: DialectCmd, wantRule: "R-120", wantEnforce: DecisionDeny}),
		{name: "R-120 cockroach sql -e", cmd: `cockroach sql --insecure -e "DELETE FROM accounts"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 duckdb -c", cmd: `duckdb app.duckdb -c "DROP TABLE t"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 duckdb operand SQL", cmd: `duckdb app.duckdb "DROP TABLE t"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 cqlsh -e", cmd: `cqlsh -e "DROP TABLE app.users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 sqlite3 -cmd", cmd: `sqlite3 -cmd "DROP TABLE t" app.db`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 mysql --init-command", cmd: `mysql --init-command="TRUNCATE TABLE logs" app`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 psql boolean -e before -c", cmd: `psql -e -c "DROP TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 comment as whitespace", cmd: `psql -c "DROP/**/TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 commented-out WHERE", cmd: `psql -c "DELETE FROM users -- WHERE id = 1"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 MySQL executable comment", cmd: `mysql -e "/*!50000 DROP TABLE users */"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "R-120 near-miss: duckdb SELECT", cmd: `duckdb app.duckdb "SELECT 1"`},

		// --- R-121: UPDATE without WHERE ---
		{name: "R-121 psql", cmd: `psql -c "UPDATE users SET admin = true"`, wantRule: "R-121", wantEnforce: DecisionAsk},
		{name: "R-121 mysql lowercase", cmd: `mysql -e "update accounts set balance = 0"`, wantRule: "R-121", wantEnforce: DecisionAsk},
		{name: "R-121 sqlite3 operand", cmd: `sqlite3 app.db "UPDATE t SET x = 1"`, wantRule: "R-121", wantEnforce: DecisionAsk},
		{name: "R-121 heredoc", cmd: "psql <<SQL\nUPDATE t SET x = 1;\nSQL", wantRule: "R-121", wantEnforce: DecisionAsk},
		{name: "R-121 second statement", cmd: `psql -c "SELECT 1; UPDATE t SET x = 1"`, wantRule: "R-121", wantEnforce: DecisionAsk},
		{name: "R-121 near-miss: WHERE", cmd: `psql -c "UPDATE users SET admin = true WHERE id = 7"`},
		{name: "R-121 near-miss: upsert", cmd: `psql -c "INSERT INTO t (id, n) VALUES (1, 2) ON CONFLICT (id) DO UPDATE SET n = excluded.n"`},
		{name: "R-121 near-miss: MySQL upsert", cmd: `mysql -e "INSERT INTO t VALUES (1) ON DUPLICATE KEY UPDATE n = n + 1"`},
		{name: "R-121 near-miss: row lock", cmd: `psql -c "SELECT * FROM t FOR UPDATE"`},
		{name: "R-121 near-miss: foreign-key action", cmd: `psql -c "CREATE TABLE a (b int REFERENCES c(id) ON UPDATE SET NULL)"`},
		{name: "R-121 near-miss: commented out", cmd: `psql -c "-- UPDATE t SET x = 1"`},
		{name: "R-121 near-miss: not a database CLI", cmd: `echo "UPDATE t SET x = 1"`},

		// --- R-122: schema destruction ---
		{name: "R-122 drop index", cmd: `psql -c "DROP INDEX idx_users_email"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop materialized view", cmd: `psql -c "DROP MATERIALIZED VIEW daily_totals"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop view", cmd: `mysql -e "DROP VIEW active_users"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop user", cmd: `mysql -e "DROP USER 'bob'@'%'"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop role", cmd: `psql -c "DROP ROLE analyst"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop function", cmd: `psql -c "DROP FUNCTION refresh_totals"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop procedure", cmd: `sqlcmd -Q "DROP PROCEDURE dbo.cleanup"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop trigger", cmd: `psql -c "DROP TRIGGER audit ON users"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop sequence", cmd: `psql -c "DROP SEQUENCE users_id_seq"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop type", cmd: `psql -c "DROP TYPE mood"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop extension", cmd: `psql -c "DROP EXTENSION postgis"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 drop owned", cmd: `psql -c "DROP OWNED BY app_user"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 alter table drop column", cmd: `psql -c "ALTER TABLE users DROP COLUMN email"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 alter table drop constraint", cmd: `mysql -e "ALTER TABLE orders DROP CONSTRAINT fk_user"`, wantRule: "R-122", wantEnforce: DecisionAsk},
		{name: "R-122 near-miss: drop default", cmd: `psql -c "ALTER TABLE users ALTER COLUMN email DROP DEFAULT"`},
		{name: "R-122 near-miss: drop not null", cmd: `psql -c "ALTER TABLE users ALTER COLUMN email DROP NOT NULL"`},
		{name: "R-122 near-miss: create index", cmd: `psql -c "CREATE INDEX idx ON users (email)"`},
		{name: "R-122 drop table stays R-120", cmd: `psql -c "DROP TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},

		// --- R-123: NoSQL / key-value destruction ---
		{name: "R-123 mongosh dropDatabase", cmd: `mongosh --eval "db.dropDatabase()"`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 mongo collection drop", cmd: `mongo app --eval 'db.users.drop()'`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 mongosh deleteMany empty filter", cmd: `mongosh "mongodb://localhost/app" --eval "db.users.deleteMany({})"`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 mongosh deleteMany no filter", cmd: `mongosh --eval "db.users.deleteMany()"`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 mongosh remove empty filter", cmd: `mongosh --eval "db.users.remove({})"`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 near-miss: mongosh filtered delete", cmd: `mongosh --eval 'db.users.deleteMany({status: "inactive"})'`},
		{name: "R-123 near-miss: mongosh find", cmd: `mongosh --eval "db.users.find()"`},
		{name: "R-123 redis FLUSHALL", cmd: "redis-cli FLUSHALL", wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 redis flushdb after flags", cmd: "redis-cli -n 0 -h cache.example.internal flushdb", wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 redis flushall async", cmd: "redis-cli -h cache.example.internal FlushAll ASYNC", wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 valkey FLUSHALL", cmd: "valkey-cli FLUSHALL", wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 redis cluster call", cmd: "redis-cli --cluster call cache.example.internal:6379 FLUSHALL", wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 redis heredoc", cmd: "redis-cli <<EOF\nFLUSHDB\nEOF", wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 near-miss: redis key named flushall", cmd: "redis-cli GET flushall"},
		{name: "R-123 near-miss: redis keys", cmd: "redis-cli -n 0 KEYS 'user:*'"},
		{name: "R-123 cqlsh drop keyspace", cmd: `cqlsh -e "DROP KEYSPACE app"`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 cqlsh host then drop keyspace", cmd: `cqlsh cass.example.internal -e "drop keyspace if exists app"`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 near-miss: cqlsh describe", cmd: `cqlsh -e "DESCRIBE KEYSPACES"`},
		{name: "R-123 etcdctl prefix on empty key", cmd: `etcdctl del "" --prefix`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 etcdctl prefix on root", cmd: "etcdctl del / --prefix", wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 etcdctl from-key empty", cmd: `etcdctl --endpoints=https://etcd.example.internal:2379 del --from-key ""`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "R-123 near-miss: etcdctl scoped prefix", cmd: "etcdctl del /app/config --prefix"},
		{name: "R-123 near-miss: etcdctl get everything", cmd: `etcdctl get "" --prefix`},
		{name: "R-123 near-miss: etcdctl prefix false", cmd: `etcdctl del "" --prefix=false`},

		// --- R-124: ORM / migration resets (record-only) ---
		{name: "R-124 prisma migrate reset", cmd: "prisma migrate reset", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 npx prisma", cmd: "npx prisma migrate reset --force", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 pnpm exec prisma db push force-reset", cmd: "pnpm exec prisma db push --force-reset", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 pnpm dlx prisma", cmd: "pnpm dlx prisma migrate reset", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 yarn prisma", cmd: "yarn prisma migrate reset", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 bunx prisma", cmd: "bunx prisma migrate reset", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 rails db:drop", cmd: "rails db:drop", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 bin/rails db:reset", cmd: "bin/rails db:reset", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 bundle exec rake db:purge", cmd: "bundle exec rake db:create db:purge", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 rails db:drop:all", cmd: "rails db:drop:all", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 alembic downgrade base", cmd: "alembic downgrade base", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 poetry run alembic with config", cmd: "poetry run alembic -c alembic.ini downgrade base", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 python manage.py flush", cmd: "python manage.py flush --noinput", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 uv run python manage.py flush", cmd: "uv run python manage.py flush", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 django-admin flush", cmd: "django-admin flush", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 knex rollback all", cmd: "npx knex migrate:rollback --all", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 sequelize db:drop", cmd: "npx sequelize-cli db:drop", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 sequelize undo all", cmd: "sequelize db:migrate:undo:all", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 typeorm schema:drop", cmd: "npx typeorm schema:drop", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 artisan migrate:fresh", cmd: "php artisan migrate:fresh --seed", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 artisan db:wipe", cmd: "php artisan db:wipe", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 flyway clean", cmd: "flyway -url=jdbc:postgresql://localhost/app clean", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 liquibase dropAll", cmd: "liquibase dropAll", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 dotnet ef database drop", cmd: "dotnet ef database drop --force", wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "R-124 near-miss: prisma migrate dev", cmd: "prisma migrate dev --name reset"},
		{name: "R-124 near-miss: prisma db push", cmd: "npx prisma db push"},
		{name: "R-124 near-miss: rails db:migrate", cmd: "rails db:migrate"},
		{name: "R-124 near-miss: alembic upgrade", cmd: "alembic upgrade head"},
		{name: "R-124 near-miss: knex single rollback", cmd: "npx knex migrate:rollback"},
		{name: "R-124 near-miss: artisan migrate", cmd: "php artisan migrate"},
		{name: "R-124 near-miss: echo is not a runner", cmd: "echo prisma migrate reset"},
	}
	runDBCases(t, cases, Config{})
}

// TestDatabaseRuleR125 covers R-125's production-target matching: each flag,
// operand and environment source, both pattern forms, and the inert
// default.
func TestDatabaseRuleR125(t *testing.T) {
	t.Parallel()
	pats := Config{DatabaseProdPatterns: []string{"prod", "*.live.example.internal"}}
	cases := []dbCase{
		{name: "psql host flag", cmd: `psql -h db.prod.example.com -c "SELECT 1"`, wantRule: "R-125", wantEnforce: DecisionAsk},
		{
			name: "psql URI operand, password kept out of the reason", cmd: "psql postgres://app:s3cret@db.prod.example.com:5432/app",
			wantRule: "R-125", wantEnforce: DecisionAsk, notInReason: "s3cret",
		},
		{name: "psql database flag", cmd: "psql -d app_prod", wantRule: "R-125", wantEnforce: DecisionAsk},
		{
			name: "psql conninfo operand, glob on the host", cmd: `psql "host=pg.live.example.internal dbname=app password=hunter2"`,
			wantRule: "R-125", wantEnforce: DecisionAsk, notInReason: "hunter2",
		},
		{name: "PGHOST prefix assignment", cmd: `PGHOST=db.prod.example.com psql -c "SELECT 1"`, wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "PGHOST exported earlier in the line", cmd: "export PGHOST=db.prod.example.com && psql", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "mysql attached host", cmd: "mysql -uroot -hdb.prod.example.com app", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "mysql login path profile", cmd: "mysql --login-path=prod app", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "mongosh srv URI", cmd: `mongosh "mongodb+srv://u:pw@cluster0.prod.example.net/app"`, wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "redis host glob", cmd: "redis-cli -h cache.live.example.internal GET k", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "redis URI flag glob", cmd: "redis-cli -u redis://cache.live.example.internal:6379 GET k", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "sqlcmd server glob", cmd: `sqlcmd -S tcp:sql.live.example.internal,1433 -Q "SELECT 1"`, wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "cockroach URL glob", cmd: `cockroach sql --url "postgresql://root@crdb.live.example.internal:26257/defaultdb"`, wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "clickhouse host", cmd: `clickhouse-client --host ch.prod.example.com -q "SELECT 1"`, wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "cqlsh host operand", cmd: "cqlsh cass.prod.example.com", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "etcdctl endpoints glob", cmd: "etcdctl --endpoints=https://etcd.live.example.internal:2379 get k", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "DATABASE_URL on a migration tool", cmd: "DATABASE_URL=postgres://db.prod.example.com/app npx prisma migrate deploy", wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "destructive SQL on prod is still R-120", cmd: `psql -h db.prod.example.com -c "DROP TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "near-miss: staging host", cmd: `psql -h db.staging.example.com -c "SELECT 1"`},
		{name: "near-miss: glob is over the whole host", cmd: "redis-cli -h cache.live.example.internal.example.com GET k"},
		{name: "near-miss: not a database command", cmd: "curl https://api.prod.example.com/health"},
		{name: "near-miss: DATABASE_URL on a non-database command", cmd: "DATABASE_URL=postgres://db.prod.example.com/app npm test"},
	}
	runDBCases(t, cases, pats)

	// Empty patterns (the default) leave R-125 inert.
	runDBCases(t, []dbCase{
		{name: "inert: no patterns", cmd: `psql -h db.prod.example.com -c "SELECT 1"`},
	}, Config{})
}

// TestDatabaseRuleR126 covers R-126 over every SQL-file source, both rows,
// the directory the unit runs in, and the reader's no-match outcomes. The
// fake reader serves synthetic paths only.
func TestDatabaseRuleR126(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"/home/u/proj/drop.sql":      "CREATE TABLE x (id int);\nDROP TABLE users;\n",
		"/home/u/proj/truncate.sql":  "-- nightly cleanup\nTRUNCATE TABLE logs;",
		"/home/u/proj/delete.sql":    "DELETE FROM sessions;",
		"/home/u/proj/update.sql":    "UPDATE users SET admin = true;",
		"/home/u/proj/schema.sql":    "ALTER TABLE users DROP COLUMN email;",
		"/home/u/proj/select.sql":    "SELECT * FROM users WHERE id = 1;",
		"/home/u/proj/commented.sql": "-- DROP TABLE users;\n/* TRUNCATE TABLE logs; */\nSELECT 1;\n",
		"/home/u/proj/upsert.sql":    "INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET n = 1;",
		"/home/u/proj/sub/inner.sql": "DROP DATABASE app;",
		"c:/scripts/drop.sql":        "DROP SCHEMA app CASCADE;",
	}
	cfg := Config{ReadSQLFile: func(p string) ([]byte, bool) {
		s, ok := files[p]
		return []byte(s), ok
	}}
	cases := []dbCase{
		{name: "psql -f", cmd: "psql -f drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "psql --file=", cmd: "psql --file=truncate.sql app", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "psql absolute path", cmd: "psql -f /home/u/proj/drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "psql meta-command include", cmd: `psql -c "\i drop.sql"`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "mysql input redirect", cmd: "mysql app < delete.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "mariadb input redirect", cmd: "mariadb app < drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "mysql source", cmd: `mysql app -e "source drop.sql"`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "mysql backslash-dot", cmd: `mysql app -e "\. drop.sql"`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "sqlite3 input redirect", cmd: "sqlite3 app.db < drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "sqlite3 .read", cmd: `sqlite3 app.db ".read drop.sql"`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "sqlcmd -i list", cmd: "sqlcmd -S sql01 -i select.sql,drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "cqlsh -f", cmd: "cqlsh -f drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "cockroach sql -f", cmd: "cockroach sql --insecure -f drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "clickhouse-client --queries-file", cmd: "clickhouse-client --queries-file drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "duckdb input redirect", cmd: "duckdb app.duckdb < drop.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "relative to an earlier cd", cmd: "cd sub && psql -f inner.sql", wantRule: "R-126", wantEnforce: DecisionDeny},
		{
			name: "windows path under cmd", cmd: `sqlcmd -S sql01 -i C:\scripts\drop.sql`, dialect: DialectCmd,
			home: `C:\Users\u`, cwd: `C:\Users\u\proj`, root: `C:\Users\u\proj`, wantRule: "R-126", wantEnforce: DecisionDeny,
		},
		{name: "ask row: UPDATE without WHERE", cmd: "psql -f update.sql", wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "ask row: schema drop", cmd: "mysql app < schema.sql", wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "near-miss: SELECT file", cmd: "psql -f select.sql"},
		{name: "near-miss: commented-out statements", cmd: "psql -f commented.sql"},
		{name: "near-miss: upsert", cmd: "psql -f upsert.sql"},
		{name: "absent or oversized file is not judged, so it asks", cmd: "psql -f big.sql", wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "near-miss: not a database CLI", cmd: "cat drop.sql"},
		{name: "a directory the guard cannot place is not judged, so it asks", cmd: "cd $DIR && psql -f drop.sql", wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "near-miss: stdin form of -f", cmd: "psql -f -"},
	}
	runDBCases(t, cases, cfg)

	// A nil reader (the pure default) leaves R-126 inert.
	runDBCases(t, []dbCase{
		{name: "inert: no reader", cmd: "psql -f drop.sql"},
	}, Config{})
}

// TestCloudDestroyAdditions pins the R-130 sub-table rows added beside the
// database family: one hit per row, plus near misses.
func TestCloudDestroyAdditions(t *testing.T) {
	t.Parallel()
	cases := []destructiveCase{
		{name: "pulumi destroy", cmd: "pulumi destroy --yes", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "pulumi down after a stack flag", cmd: "pulumi --stack prod down", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "cdk destroy", cmd: "cdk destroy MyStack", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "npx cdk destroy", cmd: "npx cdk destroy --force", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "az group delete", cmd: "az group delete --name rg-app --yes", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "docker system prune -a", cmd: "docker system prune -af", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "docker volume rm", cmd: "docker volume rm pgdata", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "docker volume prune", cmd: "docker volume prune -f", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "docker compose down -v", cmd: "docker compose -f stack.yml down -v", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "docker-compose down --volumes", cmd: "docker-compose down --volumes", wantRule: "R-130", wantEnforce: DecisionAsk},
		{name: "near-miss: pulumi up", cmd: "pulumi up --yes"},
		{name: "near-miss: cdk deploy", cmd: "npx cdk deploy"},
		{name: "near-miss: az group list", cmd: "az group list"},
		{name: "near-miss: dangling-only prune", cmd: "docker system prune"},
		{name: "near-miss: compose down keeps volumes", cmd: "docker compose down"},
		{name: "near-miss: volume ls", cmd: "docker volume ls"},
	}
	runRuleCases(t, cases, KindShellExec, "run_command")
}

// TestStripSQLComments pins the comment stripper's quote awareness.
func TestStripSQLComments(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"DROP/**/TABLE t", "DROP TABLE t"},
		{"SELECT 1 -- note\nDELETE FROM t", "SELECT 1  \nDELETE FROM t"},
		{"SELECT '-- not a comment' FROM t", "SELECT '-- not a comment' FROM t"},
		{`SELECT "a /* b */" FROM t`, `SELECT "a /* b */" FROM t`},
		{"SELECT $$ -- body $$ FROM t", "SELECT $$ -- body $$ FROM t"},
		{"SELECT a--1 FROM t", "SELECT a--1 FROM t"},
		{"/*!50000 DROP TABLE t */", "/*!50000 DROP TABLE t */"},
		{"/* unterminated DROP TABLE t", " "},
	} {
		if got := stripSQLComments(tc.in); got != tc.want {
			t.Errorf("stripSQLComments(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
