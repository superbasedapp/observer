package policy

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// Database rules R-121 to R-126 (docs/guard.md "Database rules"), the
// family R-120 (rules_destructive.go) started: SQL and NoSQL destruction
// beyond DROP/TRUNCATE/DELETE, ORM resets, production targets
// ([guard.database] prod_patterns) and SQL run from a file. The database
// CLI table below is the ONE description of how each database CLI takes
// the statements it runs and names the database it connects to; R-120's
// matcher reads it too.

// databaseRules returns the database family's table rows, in catalog order.
func databaseRules() []Rule {
	shell := []EventKind{KindShellExec}
	return []Rule{
		{
			ID: "R-121", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchUpdateWithoutWhere,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "SQL UPDATE without WHERE through a database CLI",
			Advice: "Add a WHERE clause that scopes the update, or run it against a scratch database first.",
		},
		{
			ID: "R-122", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSchemaDrop,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "schema-destroying SQL through a database CLI (DROP INDEX/VIEW/USER/ROLE/FUNCTION and similar, ALTER TABLE ... DROP, DROP OWNED)",
			Advice: "Confirm the dropped object is disposable, and prefer a reversible migration with a backup taken first.",
		},
		{
			ID: "R-123", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchNoSQLDestroy,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "NoSQL or key-value store destruction (mongosh dropDatabase/drop/deleteMany({}), redis-cli FLUSHALL/FLUSHDB, cqlsh DROP KEYSPACE, etcdctl del of every key)",
			Advice: "Scope the delete to specific keys or documents, or run it against a scratch instance; take a backup first.",
		},
		{
			ID: "R-124", Category: CategoryDestructive, Severity: SeverityWarn,
			AppliesTo: shell, MatchCmd: matchORMReset,
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "ORM or migration-tool database reset (prisma migrate reset, rails db:drop, alembic downgrade base, manage.py flush and similar)",
			Advice: "A reset wipes the database; make sure it points at a local or disposable database before running it.",
		},
		{
			ID: "R-125", Category: CategoryDestructive, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchProdDatabase,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "database command against a production host, connection string, database or profile ([guard.database] prod_patterns)",
			Advice: "Run it against a staging or local database, or have a human confirm the production target first.",
		},
		{
			ID: "R-126", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchSQLFileDestructive,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "SQL file run through a database CLI that contains destructive SQL (DROP TABLE/DATABASE/SCHEMA, TRUNCATE, DELETE without WHERE)",
			Advice: "Review the file's destructive statements and run it against a scratch database, or take a backup first.",
		},
		{
			ID: "R-126", Category: CategoryDestructive, Severity: SeverityCritical,
			AppliesTo: shell, MatchCmd: matchSQLFileRisky,
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "SQL file run through a database CLI that contains an UPDATE without WHERE or a schema drop",
			Advice: "Review the file's UPDATE and DROP statements before running it against a database you care about.",
		},
	}
}

// --- the database CLI table --------------------------------------------

// dbLang is the statement language a database CLI speaks.
type dbLang uint8

// dbLang values.
const (
	// dbSQL is SQL: the SQL rules (R-120 to R-122, R-126) read it.
	dbSQL dbLang = iota
	// dbCQL is Cassandra's CQL: SQL-shaped, so the SQL rules read it too,
	// plus R-123's DROP KEYSPACE arm.
	dbCQL
	// dbMongo is the MongoDB shell's JavaScript (R-123).
	dbMongo
	// dbRedis is a Redis command line (R-123).
	dbRedis
	// dbEtcd is an etcdctl command line (R-123).
	dbEtcd
)

// dbCLI is one row of the database CLI table: how the CLI takes the
// statements it runs and how it names the database it connects to. The
// flag lists are exact tokens; a "--flag=VALUE" form is read too.
type dbCLI struct {
	// base is the canonical Command.Base; sub, when set, is the subcommand
	// that opens the SQL shell (`cockroach sql`, `clickhouse client`).
	base, sub string
	lang      dbLang
	// inline are the flags whose value is statement text (`psql -c`).
	inline []string
	// posSQL: the operands after the first (the database file) are
	// statement text (`sqlite3 app.db "DROP TABLE t"`).
	posSQL bool
	// files are the flags whose value is a script file the CLI runs
	// (`psql -f`); fileList: a value may be a comma-separated list
	// (`sqlcmd -i a.sql,b.sql`).
	files    []string
	fileList bool
	// stdin: standard input is read as statements (`mysql < x.sql`).
	stdin bool
	// scripts are the in-text commands that run a file (`\i x.sql`,
	// `source x.sql`, `.read x.sql`).
	scripts []string
	// host, db, uri and profile are the flags naming the server, the
	// database, a whole connection string and a stored connection profile
	// (R-125). attached: a single-letter host or db flag may carry its
	// value attached (`mysql -hdb.example.com`).
	host, db, uri, profile []string
	attached               bool
	// cluster: single-dash short flags cluster getopt-style (`psql -tAc SQL`),
	// the first value-taking letter taking the rest of the token, or the next
	// token when nothing follows it. rest are the letters whose value is only
	// ever the rest of their token (`mysql -pSECRET`).
	cluster bool
	rest    []string
	restSet map[string]bool
	// arg names what the first operand is ("database", "server"), "" when
	// it is not a connection target.
	arg string
	// env are the environment variables the CLI reads its server,
	// database or profile from (genericDBEnv applies to every row).
	env []string
	// valued are the CLI's other value-taking flags, so the operands read
	// at the right position.
	valued []string
	// vf is every value-taking flag of the row (computed).
	vf map[string]bool
}

// sqlLike reports whether the SQL rules read the CLI's statements.
func (r *dbCLI) sqlLike() bool { return r.lang == dbSQL || r.lang == dbCQL }

// genericDBEnv are the connection variables every row honours: the
// convention ORMs and twelve-factor apps use, which a CLI wrapper or a
// script around the CLI commonly expands.
var genericDBEnv = []string{"DATABASE_URL", "DB_URL", "DB_HOST", "DB_DATABASE"}

// mysqlRow is the mysql client's row, shared by its mariadb twin.
func mysqlRow(base string) dbCLI {
	return dbCLI{
		base: base, lang: dbSQL,
		inline: []string{"-e", "--execute", "--init-command"}, stdin: true,
		scripts: []string{"source", `\.`},
		host:    []string{"-h", "--host"}, db: []string{"-D", "--database"}, profile: []string{"--login-path"},
		attached: true, cluster: true, rest: []string{"-p"}, arg: "database", env: []string{"MYSQL_HOST"},
		valued: []string{"-u", "--user", "-P", "--port", "-S", "--socket", "--defaults-file", "--defaults-extra-file"},
	}
}

// clickhouseRow is clickhouse-client's row; `clickhouse client` is the same
// client behind the multi-tool binary.
func clickhouseRow(base, sub string) dbCLI {
	return dbCLI{
		base: base, sub: sub, lang: dbSQL,
		inline: []string{"-q", "--query"}, files: []string{"--queries-file"}, stdin: true,
		host: []string{"-h", "--host"}, db: []string{"-d", "--database"},
		env:     []string{"CLICKHOUSE_HOST"},
		cluster: true,
		valued:  []string{"--port", "-u", "--user", "--password", "-f", "--format", "-C", "--config-file", "--config"},
	}
}

// mongoRow is the MongoDB shell's row (mongosh, and the legacy mongo).
func mongoRow(base string) dbCLI {
	return dbCLI{
		base: base, lang: dbMongo,
		inline: []string{"--eval"}, stdin: true,
		host: []string{"--host"}, uri: []string{"--uri"}, arg: "server",
		env: []string{"MONGODB_URI", "MONGO_URI", "MONGO_URL"},
		valued: []string{
			"--port", "-u", "--username", "-p", "--password", "--authenticationDatabase",
			"--authenticationMechanism", "-f", "--file", "--tlsCAFile", "--tlsCertificateKeyFile", "--apiVersion",
		},
	}
}

// redisRow is the Redis CLI's row (redis-cli, and the valkey-cli fork).
func redisRow(base string) dbCLI {
	return dbCLI{
		base: base, lang: dbRedis, stdin: true,
		host: []string{"-h"}, uri: []string{"-u"},
		env: []string{"REDIS_URL", "REDIS_HOST"},
		valued: []string{
			"-p", "-s", "-a", "-r", "-i", "-n", "-d", "-D", "--user", "--pass", "--sni", "--cacert",
			"--cacertdir", "--cert", "--key", "--tls-ciphers", "--tls-ciphersuites", "--rdb", "--functions-rdb",
			"--pipe-timeout", "--memkeys-samples", "--pattern", "--count", "--quoted-pattern", "--eval", "--cluster",
		},
	}
}

// dbCLITable is the database CLI table, one row per CLI shape.
var dbCLITable = []dbCLI{
	{
		base: "psql", lang: dbSQL,
		inline: []string{"-c", "--command"}, files: []string{"-f", "--file"}, stdin: true,
		scripts: []string{`\i`, `\include`, `\ir`, `\include_relative`},
		host:    []string{"-h", "--host"}, db: []string{"-d", "--dbname"},
		attached: true, cluster: true, arg: "database",
		env: []string{"PGHOST", "PGHOSTADDR", "PGDATABASE", "PGSERVICE"},
		valued: []string{
			"-p", "--port", "-U", "--username", "-F", "--field-separator", "-L", "--log-file",
			"-o", "--output", "-P", "--pset", "-R", "--record-separator", "-T", "--table-attr", "-v", "--set", "--variable",
		},
	},
	mysqlRow("mysql"),
	mysqlRow("mariadb"),
	{
		base: "sqlite3", lang: dbSQL,
		inline: []string{"-cmd"}, posSQL: true, files: []string{"-init"}, stdin: true,
		scripts: []string{".read"}, arg: "database file",
		valued: []string{
			"-separator", "-newline", "-nullvalue", "-vfs", "-mmap", "-maxsize", "-lookaside",
			"-pagecache", "-heap", "-escape",
		},
	},
	{
		base: "duckdb", lang: dbSQL,
		inline: []string{"-c", "-s", "-cmd"}, posSQL: true, files: []string{"-f", "-init"}, stdin: true,
		scripts: []string{".read"}, arg: "database file",
		valued: []string{"-separator", "-newline", "-nullvalue"},
	},
	{
		// sqlcmd takes its options with "-" or "/".
		base: "sqlcmd", lang: dbSQL,
		inline: []string{"-Q", "-q", "/Q", "/q"}, files: []string{"-i", "/i"}, fileList: true, stdin: true,
		host: []string{"-S", "/S"}, db: []string{"-d", "/d"}, attached: true,
		env: []string{"SQLCMDSERVER", "SQLCMDDBNAME"},
		valued: []string{
			"-U", "-P", "-o", "-H", "-l", "-t", "-w", "-s", "-h", "-v", "-f", "-a", "-c", "-m", "-V", "-Y", "-y",
			"/U", "/P", "/o", "/H", "/l", "/t", "/w", "/s", "/h", "/v", "/f", "/a", "/c", "/m", "/V", "/Y", "/y",
		},
	},
	{
		base: "cockroach", sub: "sql", lang: dbSQL,
		inline: []string{"-e", "--execute"}, files: []string{"-f", "--file"}, stdin: true,
		host: []string{"--host"}, db: []string{"-d", "--database"}, uri: []string{"--url"},
		cluster: true,
		env:     []string{"COCKROACH_URL", "COCKROACH_HOST", "COCKROACH_DATABASE"},
		valued:  []string{"-u", "--user", "-p", "--port", "--certs-dir", "--format", "--set", "--watch"},
	},
	clickhouseRow("clickhouse-client", ""),
	clickhouseRow("clickhouse", "client"),
	{
		base: "cqlsh", lang: dbCQL,
		inline: []string{"-e", "--execute"}, files: []string{"-f", "--file"}, stdin: true,
		db: []string{"-k", "--keyspace"}, arg: "server", cluster: true,
		env: []string{"CQLSH_HOST"},
		valued: []string{
			"-u", "--username", "-p", "--password", "--cqlversion", "--encoding", "--connect-timeout",
			"--request-timeout", "--cqlshrc",
		},
	},
	mongoRow("mongosh"),
	mongoRow("mongo"),
	redisRow("redis-cli"),
	redisRow("valkey-cli"),
	{
		base: "etcdctl", lang: dbEtcd,
		host: []string{"--endpoints"},
		env:  []string{"ETCDCTL_ENDPOINTS"},
		valued: []string{
			"--user", "--password", "--cacert", "--cert", "--key", "--dial-timeout", "--command-timeout",
			"--keepalive-time", "--keepalive-timeout", "-w", "--write-out", "--discovery-srv", "--discovery-srv-name",
		},
	},
}

// dbCLIIndex maps a canonical base to its table rows (computing each row's
// value-flag set once).
var dbCLIIndex = indexDBCLIs(dbCLITable)

// indexDBCLIs fills each row's value-flag set and indexes the rows by base.
func indexDBCLIs(rows []dbCLI) map[string][]*dbCLI {
	idx := make(map[string][]*dbCLI, len(rows))
	for i := range rows {
		r := &rows[i]
		r.vf = map[string]bool{}
		r.restSet = map[string]bool{}
		for _, f := range r.rest {
			r.restSet[f] = true
		}
		for _, list := range [][]string{r.inline, r.files, r.host, r.db, r.uri, r.profile, r.valued} {
			for _, f := range list {
				r.vf[f] = true
			}
		}
		idx[r.base] = append(idx[r.base], r)
	}
	return idx
}

// dbUnit is one command unit of a database CLI, as its table row reads it.
type dbUnit struct {
	cli *dbCLI
	cmd *Command
	// pos are the unit's operands after the row's subcommand, with the
	// row's flag values skipped.
	pos []string
	// opts are the unit's option/value pairs in argv order.
	opts []optHit
	// piped is what the pipeline feeds the unit's standard input.
	piped pipedInput
}

// pipedInput is the standard input a pipeline gives a database client
// (`echo 'DROP TABLE t' | psql`), as far as the guard can read the
// producer: SQL text it carries, SQL files it names, or the reason it
// could not be read.
type pipedInput struct {
	// texts are statement texts (echo/printf operands, a heredoc body).
	texts []string
	// files are SQL files the producer prints (`cat x.sql`).
	files []string
	// unjudged, when set, is the producer the guard could not read.
	unjudged string
}

// dbUnitOf returns the database-CLI reading of a unit, ok=false when the
// unit is not one of the table's CLIs.
func dbUnitOf(ctx *MatchContext, cmd *Command) (dbUnit, bool) {
	for _, r := range dbCLIIndex[cmd.Base] {
		opts, pos := walkOptions(cmd, r.optSpec())
		if r.sub != "" {
			if len(pos) == 0 || strings.ToLower(pos[0]) != r.sub {
				continue
			}
			pos = pos[1:]
		}
		u := dbUnit{cli: r, cmd: cmd, pos: pos, opts: opts}
		u.piped = u.pipedInput(ctx)
		return u, true
	}
	return dbUnit{}, false
}

// optSpec is the row's option grammar, as walkOptions reads it.
func (r *dbCLI) optSpec() optSpec {
	return optSpec{valued: r.vf, cluster: r.cluster, attach: r.attached, rest: r.restSet}
}

// optSpec describes how a CLI takes its options.
type optSpec struct {
	// valued are the flags that take a value.
	valued map[string]bool
	// cluster: single-dash tokens are getopt clusters.
	cluster bool
	// attach: a two-character valued flag may carry its value attached
	// (`-hVALUE`, `/QVALUE`).
	attach bool
	// rest are flags whose value is always the rest of their own token.
	rest map[string]bool
}

// optHit is one option occurrence: the flag as the table spells it and its
// value. hasValue is false for a valued flag that is the last token (its
// value was a substitution the lexer dropped, or was never written).
type optHit struct {
	flag, value string
	hasValue    bool
}

// walkOptions reads a unit's argv under one option grammar and returns the
// valued-option occurrences in order and the operands: a separate value
// ("-c VALUE"), an embedded one ("--command=VALUE"), an attached one
// ("-cVALUE", "-hVALUE") and, for a cluster ("-tAc VALUE", "-tAcVALUE"),
// the value of the first value-taking letter, which is the rest of the
// token or, when nothing follows it, the next token. "--" ends option
// scanning. It is the one reading of a database CLI's flags, shared by the
// operand scan and the value scans.
func walkOptions(cmd *Command, sp optSpec) (hits []optHit, pos []string) {
	rest := false
	for i := 1; i < len(cmd.Argv); i++ {
		t := cmd.Argv[i]
		if rest {
			pos = append(pos, t)
			continue
		}
		if t == "--" {
			rest = true
			continue
		}
		if !cmd.isFlagToken(t) {
			pos = append(pos, t)
			continue
		}
		next := func(flag string) {
			h := optHit{flag: flag}
			if i+1 < len(cmd.Argv) {
				h.value, h.hasValue = cmd.Argv[i+1], true
				i++
			}
			hits = append(hits, h)
		}
		switch {
		case sp.valued[t]:
			next(t)
		case strings.HasPrefix(t, "--"):
			if name, val, ok := strings.Cut(t, "="); ok && sp.valued[name] {
				hits = append(hits, optHit{flag: name, value: val, hasValue: true})
			}
		case strings.ContainsRune(t, '=') && sp.valued[t[:strings.IndexByte(t, '=')]]:
			j := strings.IndexByte(t, '=')
			hits = append(hits, optHit{flag: t[:j], value: t[j+1:], hasValue: true})
		case sp.cluster && t[0] == '-' && len(t) > 2:
			for k := 1; k < len(t); k++ {
				flag := "-" + t[k:k+1]
				if sp.rest[flag] {
					hits = append(hits, optHit{flag: flag, value: t[k+1:], hasValue: true})
					break
				}
				if !sp.valued[flag] {
					continue
				}
				if k+1 < len(t) {
					hits = append(hits, optHit{flag: flag, value: t[k+1:], hasValue: true})
				} else {
					next(flag)
				}
				break
			}
		case sp.attach && len(t) > 2 && sp.valued[t[:2]]:
			hits = append(hits, optHit{flag: t[:2], value: t[2:], hasValue: true})
		}
	}
	return hits, pos
}

// values returns every value of the named flags, in argv order.
func (u dbUnit) values(names []string) []string {
	var out []string
	for _, h := range u.opts {
		if h.hasValue && containsString(names, h.flag) {
			out = append(out, h.value)
		}
	}
	return out
}

// inlineTexts returns the statement texts a unit carries on its own command
// line: inline flag values (every occurrence), operand SQL, the heredoc
// body and the SQL text a pipeline producer prints.
func (u dbUnit) inlineTexts() []string {
	texts := u.values(u.cli.inline)
	if u.cli.posSQL && len(u.pos) > 1 {
		texts = append(texts, u.pos[1:]...)
	}
	if u.cmd.Heredoc != "" {
		texts = append(texts, u.cmd.Heredoc)
	}
	return append(texts, u.piped.texts...)
}

// sqlFiles returns the script files a SQL-like unit runs, as written: file
// flag values, the standard-input redirect source, the files a pipeline
// producer prints and the files in-text script commands name.
func (u dbUnit) sqlFiles() []string {
	var out []string
	for _, v := range u.values(u.cli.files) {
		parts := []string{v}
		if u.cli.fileList {
			parts = strings.Split(v, ",")
		}
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" && p != "-" {
				out = append(out, p)
			}
		}
	}
	if u.cli.stdin {
		out = append(out, u.cmd.InputRedirects...)
		out = append(out, u.piped.files...)
	}
	if len(u.cli.scripts) > 0 {
		for _, t := range u.inlineTexts() {
			out = append(out, scriptFileRefs(t, u.cli.scripts)...)
		}
	}
	return out
}

// fileFlagWithoutValue reports a file flag with no value after it: the
// value was a substitution (`psql -f <(...)`, `-f $(mktemp)`), which the
// guard cannot read.
func (u dbUnit) fileFlagWithoutValue() bool {
	for _, h := range u.opts {
		if !h.hasValue && containsString(u.cli.files, h.flag) {
			return true
		}
	}
	return false
}

// --- SQL piped into a client ----------------------------------------------

// pipeProducer is one row of the producer table: how a command that feeds a
// pipeline hands SQL on.
type pipeProducer struct {
	// bases are the producer's canonical command names.
	bases []string
	// operandsAreText: the non-flag operands are SQL text (echo, printf).
	operandsAreText bool
	// operandsAreFiles: the non-flag operands are files it prints (cat).
	operandsAreFiles bool
	// passthrough: with no operand and no input of its own it forwards its
	// standard input, so the producer before it is the real one (cat).
	passthrough bool
	// fileFlags are the flags whose value is a file it prints
	// (`Get-Content -Path x.sql`).
	fileFlags []string
}

// pipeProducers is the table of producers the guard can read.
var pipeProducers = []pipeProducer{
	{bases: []string{"echo", "printf", "write-output", "write-host"}, operandsAreText: true},
	{bases: []string{"cat", "type"}, operandsAreFiles: true, passthrough: true},
	{bases: []string{"get-content"}, operandsAreFiles: true, fileFlags: []string{"-path", "-literalpath"}},
}

// pipeProducerFor returns the producer row for a canonical base.
func pipeProducerFor(base string) (*pipeProducer, bool) {
	for i := range pipeProducers {
		if containsString(pipeProducers[i].bases, base) {
			return &pipeProducers[i], true
		}
	}
	return nil, false
}

// maxPipeProducers bounds how many passthrough stages the producer walk
// follows.
const maxPipeProducers = 8

// readsStdin reports whether the client takes its statements from standard
// input in this invocation: its row reads stdin and nothing else gave it the
// statements (an inline flag, a file, an operand SQL, a redirect, a
// heredoc). `-f -` is stdin too.
func (u dbUnit) readsStdin() bool {
	if !u.cli.stdin || u.cmd.Heredoc != "" || len(u.cmd.InputRedirects) > 0 {
		return false
	}
	if len(u.values(u.cli.inline)) > 0 || (u.cli.posSQL && len(u.pos) > 1) {
		return false
	}
	for _, v := range u.values(u.cli.files) {
		if strings.TrimSpace(v) != "-" {
			return false
		}
	}
	return true
}

// pipeStepSep returns the list operator in front of a unit, ok=false for a
// unit the step model does not place.
func pipeStepSep(cmd *Command) (seqSep, bool) {
	if cmd.seq == nil || cmd.seqPos < 0 || cmd.seqPos >= len(cmd.seq.steps) {
		return 0, false
	}
	return cmd.seq.steps[cmd.seqPos].sep, true
}

// pipelinePrev returns the unit just before cmd in its command line.
func pipelinePrev(ctx *MatchContext, cmd *Command) *Command {
	if ctx == nil || cmd.seq == nil {
		return nil
	}
	for i := range ctx.Cmds {
		c := &ctx.Cmds[i]
		if c.seq == cmd.seq && c.seqPos == cmd.seqPos-1 {
			return c
		}
	}
	return nil
}

// pipedInput reads the producer feeding a client's standard input. A
// producer in the table gives its text or files; any other producer
// (curl, pg_dump, a filter, a group) is reported unjudged, so the caller can
// ask rather than stay silent.
func (u dbUnit) pipedInput(ctx *MatchContext) pipedInput {
	if sep, ok := pipeStepSep(u.cmd); !ok || sep != sepPipe || !u.readsStdin() {
		return pipedInput{}
	}
	var out pipedInput
	if groupedLine(ctx, u.cmd) {
		// A group on the line (`(echo a; echo b) | psql`, `{ ...; } | psql`) makes
		// the unit before the pipe only the last of its producers.| psql`) makes the unit before
		// the pipe only the last of its producers.
		out.unjudged = "a grouped producer"
		return out
	}
	prod := u.cmd
	for n := 0; n < maxPipeProducers; n++ {
		prod = pipelinePrev(ctx, prod)
		if prod == nil {
			out.unjudged = "an unplaced producer"
			return out
		}
		row, ok := pipeProducerFor(prod.Base)
		if !ok {
			out.unjudged = prod.Base
			return out
		}
		files := append([]string(nil), prod.InputRedirects...)
		var text []string
		if row.operandsAreText || row.operandsAreFiles {
			operands := positionalsSkippingFlags(prod)
			if row.operandsAreText {
				text = operands
			} else {
				for _, o := range operands {
					if o != "-" {
						files = append(files, o)
					}
				}
			}
		}
		for _, f := range row.fileFlags {
			for _, h := range lowerFlagValues(prod, f) {
				files = append(files, h)
			}
		}
		if prod.Heredoc != "" {
			text = append(text, prod.Heredoc)
		}
		if row.passthrough && len(files) == 0 && len(text) == 0 {
			if sep, ok := pipeStepSep(prod); !ok || sep != sepPipe {
				out.unjudged = prod.Base
				return out
			}
			continue // forwards its own input: read the producer before it
		}
		out.texts, out.files = text, files
		return out
	}
	out.unjudged = "a long chain of producers"
	return out
}

// positionalsSkippingFlags is a producer's non-flag operands: every token
// that does not start with '-' (nor '/' under cmd), after an optional "--".
func positionalsSkippingFlags(cmd *Command) []string {
	_, pos := walkOptions(cmd, optSpec{})
	return pos
}

// lowerFlagValues returns the values of a PowerShell-style flag, matched
// case-insensitively (`-Path x`, `-path:x`).
func lowerFlagValues(cmd *Command, flag string) []string {
	var out []string
	for i := 1; i < len(cmd.Argv); i++ {
		t := strings.ToLower(cmd.Argv[i])
		switch {
		case t == flag && i+1 < len(cmd.Argv):
			out = append(out, cmd.Argv[i+1])
			i++
		case strings.HasPrefix(t, flag+":"):
			out = append(out, cmd.Argv[i][len(flag)+1:])
		}
	}
	return out
}

// groupedLine reports a line with a parenthesised group or a brace group
// (the lexer drops the braces, so the text is checked).
func groupedLine(ctx *MatchContext, cmd *Command) bool {
	if ctx != nil && ctx.Event != nil && strings.Contains(ctx.Event.Target, "{") {
		return true
	}
	if cmd.seq == nil {
		return false
	}
	for _, s := range cmd.seq.steps {
		if s.opens > 0 || s.closes > 0 {
			return true
		}
	}
	return false
}

// scriptFileRefs returns the files a SQL text runs through the CLI's
// in-text script commands, one command per line or statement.
func scriptFileRefs(text string, cmds []string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == ';' }) {
		l := strings.TrimSpace(line)
		for _, c := range cmds {
			if len(l) <= len(c)+1 || !strings.EqualFold(l[:len(c)], c) || (l[len(c)] != ' ' && l[len(c)] != '\t') {
				continue
			}
			if arg := strings.Trim(strings.TrimSpace(l[len(c):]), `'"`); arg != "" {
				out = append(out, arg)
			}
		}
	}
	return out
}

// --- SQL statements ------------------------------------------------------

// SQL shape patterns. Go regexp is RE2 — linear time, no
// catastrophic backtracking (a documented advantage over PCRE-based
// competitors, spec §4.4).
var (
	reSQLDrop     = regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA)\b`)
	reSQLTruncate = regexp.MustCompile(`(?i)\bTRUNCATE(\s+TABLE)?\s+\w`)
	reSQLDelete   = regexp.MustCompile(`(?i)\bDELETE\s+FROM\b`)
	reSQLWhere    = regexp.MustCompile(`(?i)\bWHERE\b`)
	// reSQLUpdate finds UPDATE keywords; the captured word before one marks
	// an upsert or a merge arm (`ON CONFLICT DO UPDATE SET`, `ON DUPLICATE
	// KEY UPDATE`, `WHEN MATCHED THEN UPDATE SET`), a row lock (`FOR
	// UPDATE`) or a foreign-key or column action (`ON UPDATE SET NULL`),
	// none of which is a table-wide update.
	reSQLUpdate  = regexp.MustCompile(`(?i)(?:\b(DO|KEY|THEN|FOR|ON)\s+)?\bUPDATE\b`)
	reSQLSet     = regexp.MustCompile(`(?i)\bSET\b`)
	reSQLDropObj = regexp.MustCompile(`(?i)\bDROP\s+(INDEX|VIEW|MATERIALIZED\s+VIEW|USER|ROLE|FUNCTION|PROCEDURE|TRIGGER|SEQUENCE|TYPE|EXTENSION|OWNED)\b`)
	reSQLAlter   = regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`)
	// reSQLDropAny finds every DROP with the word after it; an ALTER TABLE
	// statement's DROP of a column default, a NOT NULL, an identity or a
	// generation expression keeps the column's data and is no hit.
	reSQLDropAny      = regexp.MustCompile(`(?i)\bDROP\b(?:\s+(\w+))?`)
	reCQLDropKeyspace = regexp.MustCompile(`(?i)\bDROP\s+KEYSPACE\b`)
)

// alterDropKept are the ALTER TABLE ... DROP forms that drop no data.
var alterDropKept = setOf("DEFAULT", "NOT", "IDENTITY", "EXPRESSION")

// matchDangerousSQL implements R-120 over the database CLI table's
// statement texts: inline flags, operand SQL and heredoc bodies. Each text
// is judged as written (R-120's original scan, so no command it ever
// denied passes) and with its comments stripped, which also catches a
// comment used as whitespace (`DROP/**/TABLE`) or hiding a WHERE.
func matchDangerousSQL(ctx *MatchContext, cmd *Command) (bool, string) {
	u, ok := dbUnitOf(ctx, cmd)
	if !ok || !u.cli.sqlLike() {
		return false, ""
	}
	for _, t := range u.inlineTexts() {
		if hit, why := dangerousSQL(t); hit {
			return true, why
		}
		for _, stmt := range sqlStatements(t) {
			if hit, why := dangerousSQLStmt(stmt); hit {
				return true, why
			}
		}
	}
	return false, ""
}

// dangerousSQL scans SQL text statement-by-statement for the R-120
// shapes, comments included (R-120's original scan).
func dangerousSQL(text string) (bool, string) {
	for _, stmt := range strings.Split(text, ";") {
		if hit, why := dangerousSQLStmt(stmt); hit {
			return true, why
		}
	}
	return false, ""
}

// dangerousSQLStmt judges one statement for the R-120 shapes.
func dangerousSQLStmt(stmt string) (bool, string) {
	switch {
	case reSQLDrop.MatchString(stmt):
		return true, "DROP statement: " + excerpt(stmt)
	case reSQLTruncate.MatchString(stmt):
		return true, "TRUNCATE statement: " + excerpt(stmt)
	case reSQLDelete.MatchString(stmt) && !reSQLWhere.MatchString(stmt):
		return true, "DELETE without WHERE: " + excerpt(stmt)
	}
	return false, ""
}

// updateWithoutWhere judges one statement for R-121: an UPDATE ... SET that
// is not an upsert or merge arm, in a statement with no WHERE.
func updateWithoutWhere(stmt string) (bool, string) {
	if reSQLWhere.MatchString(stmt) {
		return false, ""
	}
	for _, m := range reSQLUpdate.FindAllStringSubmatchIndex(stmt, -1) {
		if m[2] >= 0 {
			continue // DO / KEY / THEN / FOR / ON UPDATE
		}
		if reSQLSet.MatchString(stmt[m[1]:]) {
			return true, "UPDATE without WHERE: " + excerpt(stmt)
		}
	}
	return false, ""
}

// schemaDrop judges one statement for R-122: a DROP of a schema object
// R-120 does not cover, DROP OWNED, or an ALTER TABLE that drops a column,
// constraint, index, key or partition.
func schemaDrop(stmt string) (bool, string) {
	if m := reSQLDropObj.FindStringSubmatch(stmt); m != nil {
		return true, "DROP " + strings.ToUpper(strings.Join(strings.Fields(m[1]), " ")) + " statement: " + excerpt(stmt)
	}
	loc := reSQLAlter.FindStringIndex(stmt)
	if loc == nil {
		return false, ""
	}
	for _, m := range reSQLDropAny.FindAllStringSubmatch(stmt[loc[1]:], -1) {
		if !alterDropKept[strings.ToUpper(m[1])] {
			return true, "ALTER TABLE ... DROP statement: " + excerpt(stmt)
		}
	}
	return false, ""
}

// riskySQLStmt judges one statement for the R-121 and R-122 shapes.
func riskySQLStmt(stmt string) (bool, string) {
	if hit, why := updateWithoutWhere(stmt); hit {
		return true, why
	}
	return schemaDrop(stmt)
}

// sqlStatements splits SQL text into statements on every ';', the way
// R-120 always has (a ';' inside a literal over-splits, which errs toward a
// hit and never merges two statements), and strips each statement's
// comments (stripSQLComments). It is lexical and best effort.
func sqlStatements(text string) []string {
	parts := strings.Split(text, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := stripSQLComments(p); strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// stripSQLComments replaces the comments of one statement with a space, so
// a commented-out statement or clause is not judged and a comment used as
// whitespace (`DROP/**/TABLE`) is. A comment is `--` followed by
// whitespace or the end (to the end of the line; MySQL needs the space, and
// requiring it strips less) or a `/* */` block (to its end, or the end of
// the statement). Quoted text ('...', "...", PostgreSQL $tag$...$tag$) is
// kept as is, and a MySQL executable comment (`/*!...*/`, `/*M!...*/`) is
// code, so it is kept too.
func stripSQLComments(s string) string {
	if !strings.Contains(s, "--") && !strings.Contains(s, "/*") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\'' || c == '"':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				b.WriteString(s[i:])
				return b.String()
			}
			b.WriteString(s[i : i+j+2])
			i += j + 2
		case c == '$':
			if tag, ok := dollarTag(s, i); ok {
				j := strings.Index(s[i+len(tag):], tag)
				if j < 0 {
					b.WriteString(s[i:])
					return b.String()
				}
				end := i + len(tag) + j + len(tag)
				b.WriteString(s[i:end])
				i = end
				continue
			}
			b.WriteByte(c)
			i++
		case c == '-' && strings.HasPrefix(s[i:], "--") && (i+2 == len(s) || isSQLSpace(s[i+2])):
			j := strings.IndexByte(s[i:], '\n')
			b.WriteByte(' ')
			if j < 0 {
				return b.String()
			}
			i += j
		case c == '/' && strings.HasPrefix(s[i:], "/*") && !strings.HasPrefix(s[i:], "/*!") && !strings.HasPrefix(s[i:], "/*M!"):
			j := strings.Index(s[i+2:], "*/")
			b.WriteByte(' ')
			if j < 0 {
				return b.String()
			}
			i += 2 + j + 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// isSQLSpace reports whether c is whitespace or a control character, the
// bytes MySQL accepts after a `--` comment marker.
func isSQLSpace(c byte) bool { return c <= ' ' }

// dollarTag returns the PostgreSQL dollar-quote delimiter starting at s[i]
// (`$$`, `$body$`): an optional identifier that does not start with a digit,
// between two '$', not preceded by an identifier character (`a$b$` is an
// identifier, `$1` a parameter).
func dollarTag(s string, i int) (string, bool) {
	if i > 0 && (isNameByte(s[i-1]) || s[i-1] == '$') {
		return "", false
	}
	j := i + 1
	for j < len(s) && isNameByte(s[j]) {
		if j == i+1 && s[j] >= '0' && s[j] <= '9' {
			return "", false
		}
		j++
	}
	if j < len(s) && s[j] == '$' {
		return s[i : j+1], true
	}
	return "", false
}

// --- R-121 / R-122 -------------------------------------------------------

// matchUpdateWithoutWhere implements R-121 over a SQL-like unit's statement
// texts, comments stripped.
func matchUpdateWithoutWhere(ctx *MatchContext, cmd *Command) (bool, string) {
	return matchInlineSQL(ctx, cmd, updateWithoutWhere)
}

// matchSchemaDrop implements R-122 over a SQL-like unit's statement texts,
// comments stripped.
func matchSchemaDrop(ctx *MatchContext, cmd *Command) (bool, string) {
	return matchInlineSQL(ctx, cmd, schemaDrop)
}

// matchInlineSQL judges every statement of a SQL-like unit's inline texts.
func matchInlineSQL(ctx *MatchContext, cmd *Command, judge func(string) (bool, string)) (bool, string) {
	u, ok := dbUnitOf(ctx, cmd)
	if !ok || !u.cli.sqlLike() {
		return false, ""
	}
	for _, t := range u.inlineTexts() {
		for _, stmt := range sqlStatements(t) {
			if hit, why := judge(stmt); hit {
				return true, why
			}
		}
	}
	return false, ""
}

// --- R-123: NoSQL / key-value destruction --------------------------------

// noSQLChecks is the R-123 sub-table: one check per statement language
// (table-driven per Module rule 5; each entry pinned by its own test case).
var noSQLChecks = map[dbLang]func(dbUnit) (bool, string){
	dbCQL:   checkCQLDropKeyspace,
	dbMongo: checkMongoDestroy,
	dbRedis: checkRedisFlush,
	dbEtcd:  checkEtcdDeleteAll,
}

// matchNoSQLDestroy implements R-123 by dispatching on the unit's
// statement language.
func matchNoSQLDestroy(ctx *MatchContext, cmd *Command) (bool, string) {
	u, ok := dbUnitOf(ctx, cmd)
	if !ok {
		return false, ""
	}
	if check := noSQLChecks[u.cli.lang]; check != nil {
		return check(u)
	}
	return false, ""
}

// checkCQLDropKeyspace: cqlsh `DROP KEYSPACE`, judged as written and with
// comments stripped, like R-120.
func checkCQLDropKeyspace(u dbUnit) (bool, string) {
	for _, t := range u.inlineTexts() {
		texts := append(strings.Split(t, ";"), sqlStatements(t)...)
		for _, stmt := range texts {
			if reCQLDropKeyspace.MatchString(stmt) {
				return true, "DROP KEYSPACE statement: " + excerpt(stmt)
			}
		}
	}
	return false, ""
}

// MongoDB shell destruction shapes: dropping a database or a collection,
// and deleting with an empty filter (every document).
var (
	reMongoDropDB    = regexp.MustCompile(`(?i)\bdropDatabase\b`)
	reMongoDrop      = regexp.MustCompile(`\.drop\s*\(\s*\)`)
	reMongoDeleteAll = regexp.MustCompile(`\.(deleteMany|remove)\s*\(\s*(\{\s*\}\s*)?[,)]`)
)

// checkMongoDestroy: mongosh/mongo `--eval` (and heredoc) JavaScript that
// drops a database or collection or deletes every document.
func checkMongoDestroy(u dbUnit) (bool, string) {
	for _, t := range u.inlineTexts() {
		switch {
		case reMongoDropDB.MatchString(t):
			return true, "dropDatabase: " + excerpt(t)
		case reMongoDrop.MatchString(t):
			return true, "collection drop(): " + excerpt(t)
		case reMongoDeleteAll.MatchString(t):
			return true, "delete with an empty filter: " + excerpt(t)
		}
	}
	return false, ""
}

// redisFlush are the Redis commands that delete every key.
var redisFlush = setOf("flushall", "flushdb")

// checkRedisFlush: a redis-cli command word of FLUSHALL or FLUSHDB (the
// first operand after the connection flags; any operand under `--cluster
// call`, which runs it on every node), or a heredoc line starting with one.
func checkRedisFlush(u dbUnit) (bool, string) {
	cluster := u.cmd.HasLongFlag("--cluster")
	for i, p := range u.pos {
		if i > 0 && !cluster {
			break
		}
		if redisFlush[strings.ToLower(p)] {
			return true, u.cmd.Base + " " + strings.ToUpper(p)
		}
	}
	for _, line := range strings.Split(strings.Join(append([]string{u.cmd.Heredoc}, u.piped.texts...), "\n"), "\n") {
		if f := strings.Fields(line); len(f) > 0 && redisFlush[strings.ToLower(f[0])] {
			return true, u.cmd.Base + " " + strings.ToUpper(f[0])
		}
	}
	return false, ""
}

// checkEtcdDeleteAll: `etcdctl del` of every key — `--prefix` on the empty
// key or "/", or `--from-key` from the empty key.
func checkEtcdDeleteAll(u dbUnit) (bool, string) {
	if len(u.pos) < 2 || u.pos[0] != "del" {
		return false, ""
	}
	key := u.pos[1]
	switch {
	case flagOn(u.cmd, "--prefix") && (key == "" || key == "/"):
		return true, "etcdctl del --prefix " + strconv.Quote(key) + " deletes every key"
	case flagOn(u.cmd, "--from-key") && key == "":
		return true, `etcdctl del --from-key "" deletes every key`
	}
	return false, ""
}

// flagOn reports a boolean long flag that is set and not "=false".
func flagOn(cmd *Command, name string) bool {
	for _, t := range cmd.flagTokens() {
		if t == name {
			return true
		}
		if v, ok := strings.CutPrefix(t, name+"="); ok {
			return !strings.EqualFold(v, "false")
		}
	}
	return false
}

// --- R-124: ORM / migration resets ---------------------------------------

// ormReset is one row of the R-124 table: a migration tool and the verbs
// that reset its database.
type ormReset struct {
	// words are the tool's command words (canonical base form).
	words []string
	// verbs is the verb sequence that must follow the tool word, as
	// consecutive operands anywhere after it; each slot lists alternatives.
	// An alternative with a ':' (a task name) also matches its sub-tasks
	// (`db:drop` matches `db:drop:all`).
	verbs [][]string
	// flags, when set, must be on the command (any one of them).
	flags []string
}

// ormResets is the R-124 table, one row per reset shape.
var ormResets = []ormReset{
	{words: []string{"prisma"}, verbs: [][]string{{"migrate"}, {"reset"}}},
	{words: []string{"prisma"}, verbs: [][]string{{"db"}, {"push"}}, flags: []string{"--force-reset"}},
	{words: []string{"rails", "rake"}, verbs: [][]string{{"db:drop", "db:reset", "db:purge", "db:migrate:reset"}}},
	{words: []string{"alembic"}, verbs: [][]string{{"downgrade"}, {"base"}}},
	{words: []string{"manage.py", "django-admin", "django-admin.py"}, verbs: [][]string{{"flush"}}},
	{words: []string{"knex"}, verbs: [][]string{{"migrate:rollback"}}, flags: []string{"--all"}},
	{words: []string{"sequelize", "sequelize-cli"}, verbs: [][]string{{"db:drop", "db:migrate:undo:all"}}},
	{words: []string{"typeorm", "typeorm-ts-node-commonjs", "typeorm-ts-node-esm"}, verbs: [][]string{{"schema:drop"}}},
	{words: []string{"artisan"}, verbs: [][]string{{"migrate:fresh", "migrate:reset", "db:wipe"}}},
	{words: []string{"flyway"}, verbs: [][]string{{"clean"}}},
	{words: []string{"liquibase"}, verbs: [][]string{{"dropall", "drop-all"}}},
	{words: []string{"ef"}, verbs: [][]string{{"database"}, {"drop"}}},
	{words: []string{"mix"}, verbs: [][]string{{"ecto.drop", "ecto.reset"}}},
	{words: []string{"supabase"}, verbs: [][]string{{"db"}, {"reset"}}},
	{words: []string{"dropdb"}},
	{words: []string{"mysqladmin", "mariadb-admin"}, verbs: [][]string{{"drop"}}},
	{words: []string{"pg_restore"}, flags: []string{"--clean"}},
}

// commandRunners are the commands that run another tool named in their
// operands (`npx prisma`, `bundle exec rails`, `uv run python manage.py`);
// an interpreter (`python manage.py`, `php artisan`) is one too.
var commandRunners = setOf("npx", "pnpx", "pnpm", "yarn", "bunx", "bun", "npm", "bundle", "uv", "uvx",
	"poetry", "pipenv", "pdm", "dotnet")

// isCommandRunner reports whether a base runs a tool named in its operands.
func isCommandRunner(base string) bool {
	if commandRunners[base] {
		return true
	}
	_, ok := interpreterFor(base)
	return ok
}

// ormWords is the unit's command word followed by its operands: where
// R-124 and R-125 look for a migration tool's word.
func ormWords(cmd *Command) []string {
	return append([]string{cmd.Base}, cmd.Positionals()...)
}

// ormToolAt reports whether words[i] is one of row's tool words in a
// position that runs it: the unit's own command, or an operand of a
// package runner.
func ormToolAt(cmd *Command, words []string, i int, row *ormReset) bool {
	if i > 0 && !isCommandRunner(cmd.Base) {
		return false
	}
	w := canonicalBase(words[i], cmd.Dialect)
	for _, t := range row.words {
		if w == t {
			return true
		}
	}
	return false
}

// verbMatches reports whether an operand matches one verb alternative.
func verbMatches(word, alt string) bool {
	w := strings.ToLower(word)
	return w == alt || (strings.Contains(alt, ":") && strings.HasPrefix(w, alt+":"))
}

// match reports whether the unit runs this reset, with the words matched.
func (row *ormReset) match(cmd *Command, words []string) (bool, string) {
	if len(row.flags) > 0 && !cmd.HasLongFlag(row.flags...) {
		return false, ""
	}
	for i := range words {
		if !ormToolAt(cmd, words, i, row) {
			continue
		}
		for j := i + 1; j+len(row.verbs) <= len(words); j++ {
			if verbsAt(words[j:], row.verbs) {
				got := append([]string{canonicalBase(words[i], cmd.Dialect)}, words[j:j+len(row.verbs)]...)
				if len(row.flags) > 0 {
					got = append(got, row.flags[0])
				}
				return true, strings.Join(got, " ")
			}
		}
	}
	return false, ""
}

// verbsAt reports whether words starts with the verb sequence.
func verbsAt(words []string, verbs [][]string) bool {
	for k, alts := range verbs {
		ok := false
		for _, a := range alts {
			if verbMatches(words[k], a) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchORMReset implements R-124 by walking the reset table.
func matchORMReset(_ *MatchContext, cmd *Command) (bool, string) {
	words := ormWords(cmd)
	for i := range ormResets {
		if hit, why := ormResets[i].match(cmd, words); hit {
			return true, why + " resets the database"
		}
	}
	return false, ""
}

// ormToolUnit reports whether the unit runs one of the R-124 table's
// migration tools with any verb (a database command for R-125).
func ormToolUnit(cmd *Command) bool {
	words := ormWords(cmd)
	for r := range ormResets {
		for i := range words {
			if ormToolAt(cmd, words, i, &ormResets[r]) {
				return true
			}
		}
	}
	return false
}

// --- R-125: production targets -------------------------------------------

// dbTarget is one connection target a database command names: what it is
// ("host", "environment PGHOST") and its value as written.
type dbTarget struct{ what, value string }

// dbURISchemes are the URI schemes of a connection string given as an
// operand (`psql postgres://...`, `mongosh mongodb+srv://...`).
var dbURISchemes = []string{
	"postgres://", "postgresql://", "mysql://", "mariadb://", "mongodb://", "mongodb+srv://",
	"redis://", "rediss://", "clickhouse://", "cockroachdb://", "sqlserver://", "jdbc:",
}

// targets returns every connection target the unit names: flag values,
// the connection operand, operand URIs and the environment it runs with.
func (u dbUnit) targets(ctx *MatchContext) []dbTarget {
	var out []dbTarget
	add := func(what string, vals []string) {
		for _, v := range vals {
			if strings.TrimSpace(v) != "" {
				out = append(out, dbTarget{what: what, value: v})
			}
		}
	}
	r := u.cli
	add("host", u.values(r.host))
	add("database", u.values(r.db))
	add("connection string", u.values(r.uri))
	add("profile", u.values(r.profile))
	for i, p := range u.pos {
		switch {
		case dbURIOperand(p) || (i == 0 && r.arg != "" && strings.Contains(p, "=")):
			add("connection string", []string{p})
		case i == 0 && r.arg != "":
			add(r.arg, []string{p})
		}
	}
	return append(out, envTargets(ctx, u.cmd, r.env)...)
}

// dbURIOperand reports whether an operand is a connection URI.
func dbURIOperand(p string) bool {
	for _, s := range dbURISchemes {
		if hasFoldPrefix(p, s) {
			return true
		}
	}
	return false
}

// envTargets returns the connection variables a unit runs with (its own
// prefix and `env` assignments, and every export-style assignment in the
// line, read the way the git rows read them), from names plus genericDBEnv.
func envTargets(ctx *MatchContext, cmd *Command, names []string) []dbTarget {
	env := gitUnitEnv(ctx, cmd)
	var out []dbTarget
	for _, n := range append(append([]string(nil), names...), genericDBEnv...) {
		if v := env[n]; strings.TrimSpace(v) != "" {
			out = append(out, dbTarget{what: "environment " + n, value: v})
		}
	}
	return out
}

// matchProdDatabase implements R-125: a database CLI unit, or a migration
// tool run (its environment only), whose connection target matches a
// [guard.database].prod_patterns entry. Inert while the list is empty.
func matchProdDatabase(ctx *MatchContext, cmd *Command) (bool, string) {
	pats := ctx.Cfg.DatabaseProdPatterns
	if len(pats) == 0 {
		return false, ""
	}
	var targets []dbTarget
	if u, ok := dbUnitOf(ctx, cmd); ok {
		targets = u.targets(ctx)
	} else if ormToolUnit(cmd) {
		targets = envTargets(ctx, cmd, nil)
	}
	for _, t := range targets {
		if part, pat, ok := matchProdPattern(pats, t.value); ok {
			return true, t.what + " " + excerpt(part) + " matches production pattern " + strconv.Quote(pat)
		}
	}
	return false, ""
}

// matchProdPattern reports the first part of a connection value (dbValueParts)
// that matches a pattern: a pattern with no '*' or '?' is a case-insensitive
// substring, one with them a case-insensitive glob over the whole part
// ('*' any run, '?' one byte; config.GuardDatabaseConfig documents it).
func matchProdPattern(pats []string, value string) (part, pattern string, ok bool) {
	parts := dbValueParts(value)
	for _, p := range pats {
		// The value is redacted before matching (dbValueParts), so a pattern
		// that carries a password is redacted the same way: it then matches the
		// redacted value, and the reason never quotes the password.
		// The wildcards are the pattern as written: the redaction mask is not one.
		glob := strings.ContainsAny(p, "*?")
		lp := strings.ToLower(strings.TrimSpace(redactDBValue(p)))
		if lp == "" {
			continue
		}
		for _, part := range parts {
			lpart := strings.ToLower(part)
			if (!glob && strings.Contains(lpart, lp)) || (glob && matchSeg(lp, lpart)) {
				return part, redactDBValue(p), true
			}
		}
	}
	return "", "", false
}

// reSecretKV finds a password in a keyword connection string
// (`password=x`, `Pwd=x;`) so it never reaches a verdict reason.
var reSecretKV = regexp.MustCompile(`(?i)\b(password|pwd)\s*=\s*[^\s;]*`)

// dbValueParts splits a connection value into the parts a pattern is
// matched against: the whole value with any password removed, then its
// hosts and database name. Three shapes are read: a URI
// (scheme://user@host1:p,host2/db?host=..&dbname=..), a keyword string
// (`host=x dbname=y`, `Server=x;Database=y`) and a host list
// (`host:port[/db]`, `tcp:host,1433`).
func dbValueParts(v string) []string {
	parts := []string{redactDBValue(v)}
	add := func(s string) {
		if s = strings.TrimSpace(strings.Trim(s, `'"`)); s != "" {
			parts = append(parts, s)
		}
	}
	switch {
	case strings.Contains(v, "://"):
		rest := v[strings.Index(v, "://")+3:]
		auth, tail := rest, ""
		if i := strings.IndexAny(rest, "/?"); i >= 0 {
			auth, tail = rest[:i], rest[i:]
		}
		if i := strings.LastIndexByte(auth, '@'); i >= 0 {
			auth = auth[i+1:]
		}
		for _, h := range strings.Split(auth, ",") {
			add(hostOnly(h))
		}
		path, query, _ := strings.Cut(tail, "?")
		if db := strings.Trim(path, "/"); db != "" {
			add(strings.SplitN(db, "/", 2)[0])
		}
		for _, kv := range strings.Split(query, "&") {
			if k, val, ok := strings.Cut(kv, "="); ok && dbKeywordTarget(k) {
				add(val)
			}
		}
	case strings.Contains(v, "="):
		for _, kv := range strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == '\t' || r == ';' }) {
			if k, val, ok := strings.Cut(kv, "="); ok && dbKeywordTarget(k) {
				add(hostOnly(val))
			}
		}
	default:
		for _, piece := range strings.Split(v, ",") {
			host, db, _ := strings.Cut(strings.TrimSpace(piece), "/")
			add(hostOnly(host))
			add(db)
		}
	}
	return parts
}

// dbKeywordTarget reports whether a connection-string keyword names a host,
// a database or a service.
func dbKeywordTarget(k string) bool {
	switch strings.ToLower(strings.TrimSpace(k)) {
	case "host", "hostaddr", "dbname", "database", "service", "server", "data source", "initial catalog", "address":
		return true
	}
	return false
}

// hostOnly strips a SQL Server protocol prefix and port (`tcp:host,1433`),
// a port (`host:5432`) and IPv6 brackets from a host spelling.
func hostOnly(h string) string {
	h = strings.TrimPrefix(strings.TrimSpace(h), "tcp:")
	if i := strings.IndexByte(h, ','); i >= 0 {
		h = h[:i]
	}
	if strings.HasPrefix(h, "[") {
		if i := strings.IndexByte(h, ']'); i > 0 {
			return h[1:i]
		}
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && strings.Count(h, ":") == 1 {
		return h[:i]
	}
	return h
}

// redactDBValue removes the password from a connection value: a URI's
// `user:password@` becomes `user@`, a keyword string's password=... is
// masked.
func redactDBValue(v string) string {
	if i := strings.Index(v, "://"); i >= 0 {
		rest := v[i+3:]
		end := len(rest)
		if j := strings.IndexAny(rest, "/?"); j >= 0 {
			end = j
		}
		if at := strings.LastIndexByte(rest[:end], '@'); at >= 0 {
			user, _, _ := strings.Cut(rest[:at], ":")
			v = v[:i+3] + user + rest[at:]
		}
	}
	return reSecretKV.ReplaceAllString(v, "$1=***")
}

// --- R-126: SQL from a file ----------------------------------------------

// matchSQLFileDestructive implements R-126's DENY row: a SQL file the unit
// runs holds an R-120 shape.
func matchSQLFileDestructive(ctx *MatchContext, cmd *Command) (bool, string) {
	if s := scanSQLFiles(ctx, cmd); s != nil && s.deny != "" {
		return true, s.deny
	}
	return false, ""
}

// matchSQLFileRisky implements R-126's ASK row: a SQL file the unit runs
// holds an R-121 or R-122 shape, or SQL the unit runs could not be judged
// (SQL piped from a producer the guard cannot read, a file that is absent,
// not a regular file, too large, over the read budget or not placeable).
// Silence means everything the unit runs was read and clean.
func matchSQLFileRisky(ctx *MatchContext, cmd *Command) (bool, string) {
	s := scanSQLFiles(ctx, cmd)
	switch {
	case s == nil:
		return false, ""
	case s.risky != "":
		return true, s.risky
	case s.unjudged != "":
		return true, s.unjudged
	}
	return false, ""
}

// R-126 read budget: how many SQL files one unit may name, and how much one
// evaluation may read, before the rest is reported unjudged (an ask) rather
// than read. The guard's per-file cap bounds each read; these bound the sum.
const (
	maxSQLFilesPerUnit = 16
	maxSQLFilesPerEval = 64
	maxSQLBytesPerEval = 2 << 20
)

// sqlFileScan is what one SQL-like unit's inputs hold: the first
// destructive (R-120 shape) and risky (R-121/R-122 shape) statement found
// in the files it runs, and why anything was not judged.
type sqlFileScan struct {
	deny, risky string
	unjudged    string
}

// note records the first reason something was not judged.
func (s *sqlFileScan) note(reason string) {
	if s.unjudged == "" {
		s.unjudged = reason
	}
}

// sqlFileVerdict is one file's judgement: read (ok) and the first
// destructive and risky statement in it.
type sqlFileVerdict struct {
	ok          bool
	deny, risky string
}

// sqlEvalState is the per-evaluation state of the R-126 rows: each distinct
// file is read once for both rows, each unit scanned once, and the read
// budget is spent across every unit of the evaluation.
type sqlEvalState struct {
	mu    sync.Mutex
	files map[string]sqlFileVerdict
	scans map[*Command]*sqlFileScan
	reads int
	bytes int
}

// sqlEvalStateOf returns the evaluation's state, held on its MatchContext
// (one per Evaluate call, never shared across goroutines), creating it on
// first use.
func sqlEvalStateOf(ctx *MatchContext) *sqlEvalState {
	if ctx.sqlEval == nil {
		ctx.sqlEval = &sqlEvalState{files: map[string]sqlFileVerdict{}, scans: map[*Command]*sqlFileScan{}}
	}
	return ctx.sqlEval
}

// judgeFile reads and judges one resolved file, once per evaluation. A file
// the budget leaves unread is a verdict with ok=false.
func (st *sqlEvalState) judgeFile(p string, read func(string) ([]byte, bool)) sqlFileVerdict {
	if v, ok := st.files[p]; ok {
		return v
	}
	if st.reads >= maxSQLFilesPerEval || st.bytes >= maxSQLBytesPerEval {
		return sqlFileVerdict{}
	}
	st.reads++
	content, ok := read(p)
	v := sqlFileVerdict{ok: ok}
	if ok {
		st.bytes += len(content)
		for _, stmt := range sqlStatements(string(content)) {
			if v.deny == "" {
				if hit, why := dangerousSQLStmt(stmt); hit {
					v.deny = why
				}
			}
			if v.risky == "" {
				if hit, why := riskySQLStmt(stmt); hit {
					v.risky = why
				}
			}
			if v.deny != "" && v.risky != "" {
				break
			}
		}
	}
	st.files[p] = v
	return v
}

// scanSQLFiles judges everything a SQL-like unit runs from outside its
// command text: the files it names (through the injected, bounded
// Config.ReadSQLFile) and the SQL a pipeline feeds it. nil for a unit that
// is not a SQL-like database CLI. Without a reader the file half is inert.
func scanSQLFiles(ctx *MatchContext, cmd *Command) *sqlFileScan {
	u, ok := dbUnitOf(ctx, cmd)
	if !ok || !u.cli.sqlLike() {
		return nil
	}
	st := sqlEvalStateOf(ctx)
	st.mu.Lock()
	defer st.mu.Unlock()
	if s, ok := st.scans[cmd]; ok {
		return s
	}
	s := &sqlFileScan{}
	st.scans[cmd] = s
	note := s.note
	if cmd.altReading {
		// The second reading only adds findings: a path it mis-lexes is
		// the primary reading's to judge.
		note = func(string) {}
	}
	if u.piped.unjudged != "" {
		note("SQL from a pipe not judged (producer: " + excerpt(u.piped.unjudged) + ")")
	}
	read := ctx.Cfg.ReadSQLFile
	if read == nil {
		return s
	}
	if u.fileFlagWithoutValue() {
		note("SQL file given by a substitution not judged")
	}
	seenSrc := map[string]bool{}
	seenPath := map[string]bool{}
	for _, src := range u.sqlFiles() {
		if seenSrc[src] {
			continue
		}
		seenSrc[src] = true
		paths := sqlFilePaths(ctx, cmd, src)
		if len(paths) == 0 {
			note("SQL file " + excerpt(src) + " not judged (its path cannot be placed)")
		}
		for _, p := range paths {
			if seenPath[p] {
				continue
			}
			if len(seenPath) >= maxSQLFilesPerUnit {
				note("more than " + strconv.Itoa(maxSQLFilesPerUnit) + " SQL files in one command not judged")
				return s
			}
			seenPath[p] = true
			v := st.judgeFile(p, read)
			switch {
			case !v.ok:
				note("SQL file " + excerpt(src) + " not judged (absent, not a regular file, too large or over the read budget)")
			default:
				if v.deny != "" && s.deny == "" {
					s.deny = "SQL file " + excerpt(src) + ": " + v.deny
				}
				if v.risky != "" && s.risky == "" {
					s.risky = "SQL file " + excerpt(src) + ": " + v.risky
				}
			}
		}
	}
	return s
}

// sqlFilePaths resolves a SQL file token from every directory the unit can
// run in (cwdtrack.go), the way the delete rules resolve their operands,
// through links created earlier in the line. A relative token from a
// directory the guard cannot place, or through a link whose target is
// unknown, is skipped; only absolute paths are returned.
func sqlFilePaths(ctx *MatchContext, cmd *Command, tok string) []string {
	home := ctx.Cfg.Home
	var out []string
	seen := map[string]bool{}
	for _, a := range unitAnchors(ctx, cmd) {
		var p string
		if a.unknown || a.opaque {
			p = resolvePath(tok, home, "", "")
		} else {
			p = resolvePath(tok, home, a.cwd, "")
			if sub, unknown, through := throughSameCmdLinks(p, a.links); through {
				if unknown {
					continue
				}
				p = sub
			}
		}
		if p == "" || !isAbsPath(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
