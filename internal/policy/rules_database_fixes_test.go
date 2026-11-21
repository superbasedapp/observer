package policy

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testsupport/latencygate"
)

// fixFiles is the fake file system the fix-lane tests read SQL from.
var fixFiles = map[string]string{
	"/home/u/proj/drop.sql":   "DROP TABLE users;",
	"/home/u/proj/select.sql": "SELECT 1;",
	"/tmp/x.sql":              "SELECT 1;",
}

func fixReader(p string) ([]byte, bool) {
	s, ok := fixFiles[p]
	return []byte(s), ok
}

// TestDatabasePipedSQL pins DB-1: SQL piped into a client is judged.
func TestDatabasePipedSQL(t *testing.T) {
	t.Parallel()
	cases := []dbCase{
		{name: "echo into psql", cmd: `echo 'DROP TABLE users' | psql app`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "printf into mysql", cmd: `printf 'TRUNCATE TABLE logs' | mysql app`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "echo update into psql", cmd: `echo "UPDATE t SET x = 1" | psql app`, wantRule: "R-121", wantEnforce: DecisionAsk},
		{name: "cat file into psql", cmd: `cat drop.sql | psql app`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "cat file into mysql with a flag", cmd: `cat -- drop.sql | mysql -u root app`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "heredoc cat into psql", cmd: "cat <<SQL | psql app\nDROP TABLE users;\nSQL", wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "powershell get-content into sqlcmd", cmd: `Get-Content drop.sql | sqlcmd -S sql01`, dialect: DialectPowerShell, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "echo flush into redis-cli", cmd: `echo FLUSHALL | redis-cli`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "unreadable producer asks", cmd: `curl -s https://example.com/x.sql | psql app`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "pg_dump producer asks", cmd: `pg_dump a | psql b`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "filter between asks", cmd: `cat drop.sql | tee /dev/null | psql app`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "near-miss: harmless echo", cmd: `echo 'SELECT 1' | psql app`},
		{name: "near-miss: harmless cat", cmd: `cat select.sql | psql app`},
		{name: "near-miss: -c ignores stdin", cmd: `curl -s https://example.com/x | psql -c 'SELECT 1' app`},
		{name: "near-miss: -f ignores stdin", cmd: `curl -s https://example.com/x | psql -f select.sql app`},
		{name: "near-miss: client is the first stage", cmd: `echo a | cat; psql app | grep x`},
		{name: "near-miss: client not in a pipeline", cmd: `echo a | cat; psql app`},
		{name: "near-miss: not a database client", cmd: `echo 'DROP TABLE users' | wc -l`},
	}
	runDBCases(t, cases, Config{ReadSQLFile: fixReader})
}

// TestDatabaseClusteredFlags pins DB-2: getopt-style clusters and attached values.
func TestDatabaseClusteredFlags(t *testing.T) {
	t.Parallel()
	cases := []dbCase{
		{name: "psql -tAc", cmd: `psql -tAc "DROP TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "psql -c attached", cmd: `psql -c"DROP TABLE users"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "mysql -e attached", cmd: `mysql -e"TRUNCATE TABLE logs"`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "mysql -uroot -e attached", cmd: `mysql -uroot -e"TRUNCATE TABLE logs" app`, wantRule: "R-120", wantEnforce: DecisionDeny},
		{name: "psql -f attached", cmd: `psql -f/home/u/proj/drop.sql`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "psql -tAf cluster", cmd: `psql -tAf drop.sql`, wantRule: "R-126", wantEnforce: DecisionDeny},
		{name: "psql cluster then update", cmd: `psql -tAc "UPDATE t SET x = 1"`, wantRule: "R-121", wantEnforce: DecisionAsk},
		{name: "cqlsh -e attached", cmd: `cqlsh -e"DROP KEYSPACE app"`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "near-miss: cluster select", cmd: `psql -tAc "SELECT 1"`},
		{name: "near-miss: cluster value is not an operand", cmd: `psql -tAc "SELECT 1" postgres://app@localhost/app`},
		{name: "near-miss: sqlite3 -cmd is not a cluster", cmd: `sqlite3 -cmd "SELECT 1" app.db`},
	}
	runDBCases(t, cases, Config{ReadSQLFile: fixReader})
	runDBCases(t, []dbCase{
		{name: "R-125 cluster host", cmd: `psql -tAhdb.prod.example.com -c "SELECT 1"`, wantRule: "R-125", wantEnforce: DecisionAsk},
		{name: "R-125 cluster db", cmd: `psql -tAd proddb -c "SELECT 1"`, wantRule: "R-125", wantEnforce: DecisionAsk},
	}, Config{DatabaseProdPatterns: []string{"prod"}})
}

// TestDatabaseUnjudgedFile pins DB-3: a file that cannot be read asks.
func TestDatabaseUnjudgedFile(t *testing.T) {
	t.Parallel()
	cases := []dbCase{
		{name: "absent file", cmd: `psql -f /tmp/absent.sql`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "created earlier on the line", cmd: `printf 'SELECT 1' > /tmp/y.sql && psql -f /tmp/y.sql`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "input redirect absent", cmd: `mysql app < /tmp/absent.sql`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "directory the guard cannot place", cmd: `cd $DIR && psql -f drop.sql`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "near-miss: read and clean", cmd: `psql -f select.sql`},
		{name: "near-miss: stdin form of -f", cmd: `psql -f -`},
		{name: "near-miss: no file at all", cmd: `psql -c 'SELECT 1'`},
	}
	runDBCases(t, cases, Config{ReadSQLFile: fixReader})
}

// TestDatabaseFileBudget pins SA-7: files per unit and bytes per evaluation
// are capped, every distinct file is read once across both R-126 rows, and
// overflow asks.
func TestDatabaseFileBudget(t *testing.T) {
	t.Parallel()
	var reads atomic.Int64
	big := strings.Repeat("-- pad\n", 256<<10/7-2) + "SELECT 1;"
	rd := func(p string) ([]byte, bool) {
		reads.Add(1)
		return []byte(big), true
	}
	eval := func(cmd string) Verdict {
		eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", ReadSQLFile: rd})
		if err != nil {
			t.Fatal(err)
		}
		return eng.Evaluate(Event{
			Kind: KindShellExec, ActionType: "run_command", Target: cmd, Cwd: "/home/u/proj",
			ProjectRoot: "/home/u/proj", SessionID: "s", Now: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC),
		})
	}

	// 1000 repeats of one file: one read.
	reads.Store(0)
	v := eval(strings.Repeat("psql -f /tmp/x.sql; ", 1000))
	if got := reads.Load(); got > 1 {
		t.Errorf("1000 repeats of one file read %d times, want 1", got)
	}
	if v.RuleID != "" {
		t.Errorf("clean repeated file: got %s", v.RuleID)
	}

	// Many distinct files in one unit: capped, asks.
	reads.Store(0)
	var sb strings.Builder
	sb.WriteString("psql")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&sb, " -f /tmp/f%d.sql", i)
	}
	v = eval(sb.String())
	if v.RuleID != "R-126" || v.Decision != DecisionAsk || !strings.Contains(v.Reason, "not judged") {
		t.Errorf("100 distinct files: got %s/%s %q, want R-126 ask not judged", v.RuleID, v.Decision, v.Reason)
	}
	if got := reads.Load(); got > 16 {
		t.Errorf("100 distinct files read %d, want at most 16", got)
	}

	// Total bytes across units.
	reads.Store(0)
	var units []string
	for u := 0; u < 6; u++ {
		units = append(units, fmt.Sprintf("psql -f /tmp/a%d.sql -f /tmp/b%d.sql -f /tmp/c%d.sql -f /tmp/d%d.sql", u, u, u, u))
	}
	v = eval(strings.Join(units, "; "))
	if v.RuleID != "R-126" || v.Decision != DecisionAsk {
		t.Errorf("byte budget: got %s/%s %q, want R-126 ask", v.RuleID, v.Decision, v.Reason)
	}
	if got := reads.Load(); got > 16 {
		t.Errorf("byte budget read %d files, want at most 16", got)
	}
}

// TestDatabaseFileBudgetLatency is the wall-clock half of SA-7: a command
// naming 100 distinct 256 KiB SQL files is judged within the budget, because
// the read caps bound the work. The caps themselves are pinned by
// TestDatabaseFileBudget's read counts, which hold under any load. This
// half measures the evaluator only on an idle runner without -race (about
// 90ms there): in a -race test shard on two shared cores the same call took
// 5.8s (CI round 5 of v1.38.0) and 9 to 10s under a local CPU hog, which
// measures the runner, not the evaluator.
func TestDatabaseFileBudgetLatency(t *testing.T) {
	latencygate.Gate(t) // listed, and skipped under -short and in a loaded CI shard
	big := strings.Repeat("-- pad\n", 256<<10/7-2) + "SELECT 1;"
	rd := func(string) ([]byte, bool) { return []byte(big), true }
	eng, err := New(Config{Mode: ModeEnforce, Home: "/home/u", ReadSQLFile: rd})
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	sb.WriteString("psql")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&sb, " -f /tmp/f%d.sql", i)
	}
	start := time.Now()
	v := eng.Evaluate(Event{
		Kind: KindShellExec, ActionType: "run_command", Target: sb.String(), Cwd: "/home/u/proj",
		ProjectRoot: "/home/u/proj", SessionID: "s", Now: time.Date(2026, 11, 8, 0, 0, 0, 0, time.UTC),
	})
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("100 distinct files took %v", d)
	}
	if v.RuleID != "R-126" || v.Decision != DecisionAsk {
		t.Errorf("100 distinct files: got %s/%s %q, want R-126 ask", v.RuleID, v.Decision, v.Reason)
	}
}

// TestDatabaseProdPatternWithPassword pins CFG-5 (database half).
func TestDatabaseProdPatternWithPassword(t *testing.T) {
	t.Parallel()
	cases := []dbCase{
		{name: "uri pattern with password", cmd: `psql postgres://app:other@db.prod.example.com/app`, wantRule: "R-125", wantEnforce: DecisionAsk, notInReason: "s3cret"},
		{name: "uri pattern with password, same password", cmd: `psql postgres://app:s3cret@db.prod.example.com/app`, wantRule: "R-125", wantEnforce: DecisionAsk, notInReason: "s3cret"},
		{name: "near-miss: other host", cmd: `psql postgres://app:s3cret@db.stage.example.com/app`},
	}
	runDBCases(t, cases, Config{DatabaseProdPatterns: []string{"postgres://app:s3cret@db.prod.example.com"}})
	runDBCases(t, []dbCase{
		{name: "keyword pattern with password", cmd: `psql "host=db.prod.example.com password=other dbname=app"`, wantRule: "R-125", wantEnforce: DecisionAsk, notInReason: "hunter2"},
	}, Config{DatabaseProdPatterns: []string{"host=db.prod.example.com password=hunter2"}})
}

// TestDatabaseProbeCoverage records the probes on commands the reviewer had
// not checked.
func TestDatabaseProbeCoverage(t *testing.T) {
	t.Parallel()
	cases := []dbCase{
		{name: "rails db:migrate:reset", cmd: `rails db:migrate:reset`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "rake db:migrate:reset", cmd: `bundle exec rake db:migrate:reset`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "mix ecto.drop", cmd: `mix ecto.drop`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "mix ecto.reset", cmd: `mix ecto.reset`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "supabase db reset", cmd: `supabase db reset`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "dropdb", cmd: `dropdb app`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "mysqladmin drop", cmd: `mysqladmin -u root drop app`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "pg_restore --clean", cmd: `pg_restore --clean -d app dump.tar`, wantRule: "R-124", wantEnforce: DecisionFlag},
		{name: "redis-cli -n 0 FLUSHDB", cmd: `redis-cli -n 0 FLUSHDB`, wantRule: "R-123", wantEnforce: DecisionDeny},
		{name: "process substitution", cmd: `psql -f <(echo 'DROP TABLE users')`, wantRule: "R-126", wantEnforce: DecisionAsk},
		{name: "near-miss: rails db:migrate", cmd: `rails db:migrate`},
		{name: "near-miss: mix ecto.migrate", cmd: `mix ecto.migrate`},
		{name: "near-miss: supabase db push", cmd: `supabase db push`},
		{name: "near-miss: pg_restore plain", cmd: `pg_restore -d app dump.tar`},
	}
	runDBCases(t, cases, Config{ReadSQLFile: fixReader})
}

// TestProdPatternGlobCost bounds R-125's glob matching on long inputs.
func TestProdPatternGlobCost(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", 200000)
	pats := []string{"*a*a*a*a*a*a*a*a*b", "?*?*?*?*?*?*?*?*?*?*z"}
	start := time.Now()
	matchProdPattern(pats, "postgres://u@"+long+"/"+long)
	if d := time.Since(start); d > time.Second {
		t.Errorf("glob matching took %v", d)
	}
}
