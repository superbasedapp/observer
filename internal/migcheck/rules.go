package migcheck

import (
	"fmt"
	"strings"
)

// stmtClass is what kind of statement a unit is, for the step rules.
type stmtClass int

const (
	classDDL         stmtClass = iota // schema change
	classLockTimeout                  // SET lock_timeout
	classStmtTimeout                  // SET statement_timeout
	classSessionSet                   // another harmless SET
	classTxControl                    // BEGIN, COMMIT, ...
	classPolicy                       // policy or row-level-security change
	classAddValue                     // ALTER TYPE ... ADD VALUE
	classInsert                       // INSERT
	classBackfill                     // UPDATE, DELETE, MERGE
	classDo                           // DO block
	classRead                         // SELECT, VALUES, ANALYZE
)

// isHeader reports whether a class is a header SET, which the own-step and
// one-statement rules do not count.
func (c stmtClass) isHeader() bool {
	return c == classLockTimeout || c == classStmtTimeout || c == classSessionSet
}

// stmtRule is one row of the statement table.
type stmtRule struct {
	id    string
	class stmtClass
	// plan is the plan 06 18.2.4 rule text the row implements (or why the
	// row exists), for the reader.
	plan  string
	match func(u *unit) bool
	// check returns what the unit still requires (nil when it is allowed).
	// It may record lineage state for later steps (indexes, constraints,
	// routines). nil means the row only classifies.
	check func(u *unit, s *stepState) []string
}

// statementRules is THE ordered statement table: walked top-down, the first
// row whose match is true classifies the unit and checks it. The last row
// matches anything (unknown DDL requires contract). Keep specific rows above
// general ones.
var statementRules = []stmtRule{
	{
		id: "set-lock-timeout", class: classLockTimeout, plan: "the SET lock_timeout header",
		match: func(u *unit) bool { return setParam(u) == "lock_timeout" },
	},
	{
		id: "set-statement-timeout", class: classStmtTimeout, plan: "a data step's own statement_timeout",
		match: func(u *unit) bool { return setParam(u) == "statement_timeout" },
	},
	{
		id: "set-session", class: classSessionSet, plan: "harmless session settings",
		match: func(u *unit) bool { return sessionSettings[setParam(u)] },
	},
	{
		id: "transaction-control", class: classTxControl, plan: "the runner owns the transaction",
		match: func(u *unit) bool { return !u.alter && firstWordIn(u.toks, txWords) },
		check: func(*unit, *stepState) []string {
			return []string{"no transaction control: the runner owns each step's transaction"}
		},
	},
	{
		id: "policy", class: classPolicy, plan: "CREATE/ALTER POLICY: a step of its own, with lock_timeout",
		match: func(u *unit) bool {
			if u.alter || len(u.toks) < 2 || !firstWordIn(u.toks, map[string]bool{"CREATE": true, "ALTER": true, "DROP": true}) || !u.toks[1].isWord("POLICY") {
				return false
			}
			u.target = nameAfter(u.toks, "ON")
			return true
		},
	},
	{
		id: "row-level-security", class: classPolicy, plan: "ENABLE/FORCE ROW LEVEL SECURITY: a step of its own, with lock_timeout",
		match: func(u *unit) bool {
			if !u.alter {
				return false
			}
			a := u.action
			i := 0
			if at(a, 0, "NO", "FORCE") {
				i = 1
			} else if !firstWordIn(a, map[string]bool{"ENABLE": true, "DISABLE": true, "FORCE": true}) {
				return false
			}
			if !at(a, i+1, "ROW", "LEVEL", "SECURITY") {
				return false
			}
			u.target = u.table
			return true
		},
	},
	{
		id: "alter-type-add-value", class: classAddValue, plan: "ALTER TYPE ... ADD VALUE: a step of its own",
		match: func(u *unit) bool {
			if u.alter || !at(u.toks, 0, "ALTER", "TYPE") {
				return false
			}
			_, i := qualifiedName(u.toks, 2)
			return at(u.toks, i, "ADD", "VALUE")
		},
	},
	{
		id: "create-index", class: classDDL, plan: "CREATE INDEX on an existing table: CONCURRENTLY and the non-transactional class",
		match: func(u *unit) bool {
			return !u.alter && (at(u.toks, 0, "CREATE", "INDEX") || at(u.toks, 0, "CREATE", "UNIQUE", "INDEX"))
		},
		check: checkCreateIndex,
	},
	{
		id: "drop-index", class: classDDL, plan: "DROP INDEX: CONCURRENTLY and non-transactional, or contract",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "DROP", "INDEX") },
		check: func(u *unit, s *stepState) []string {
			return concurrentOrContract(at(u.toks, 2, "CONCURRENTLY"), s, "DROP INDEX")
		},
	},
	{
		id: "reindex", class: classDDL, plan: "REINDEX: CONCURRENTLY and non-transactional, or contract",
		match: func(u *unit) bool { return !u.alter && firstWordIn(u.toks, map[string]bool{"REINDEX": true}) },
		check: func(u *unit, s *stepState) []string {
			return concurrentOrContract(findAt(u.toks, 0, "CONCURRENTLY") >= 0, s, "REINDEX")
		},
	},
	{
		id: "create-table", class: classDDL, plan: "a new table (its manifest row is the manifest-row step rule)",
		match: func(u *unit) bool { _, ok := createdTable(u.toks); return !u.alter && ok },
	},
	{
		id: "add-column-volatile-default", class: classDDL, plan: "ADD COLUMN with a volatile default (random(), gen_random_uuid(), clock_timestamp(), timeofday(), nextval, a serial type, an identity or stored generated column): never on a populated table; a STABLE default such as now() is allowed",
		match: func(u *unit) bool { rest, ok := addColumnRest(u); return ok && volatile(rest) },
		check: func(u *unit, s *stepState) []string {
			if s.isNew(u.table) {
				return nil
			}
			return []string{"no volatile default (random(), gen_random_uuid(), clock_timestamp(), a sequence, a serial type, an identity or stored generated column): it rewrites a populated table; add the column nullable, backfill it in a data step, then SET DEFAULT"}
		},
	},
	{
		id: "add-column-not-null", class: classDDL, plan: "ADD COLUMN ... NOT NULL without a constant default: never",
		match: func(u *unit) bool {
			rest, ok := addColumnRest(u)
			return ok && findAt(rest, 0, "NOT", "NULL") >= 0 && findAt(rest, 0, "DEFAULT") < 0
		},
		check: func(u *unit, s *stepState) []string {
			if s.isNew(u.table) {
				return nil
			}
			return []string{"a constant default with NOT NULL, or expand (nullable), backfill (data), then SET NOT NULL"}
		},
	},
	{
		id: "add-column-inline-constraint", class: classDDL, plan: "a constraint inline in ADD COLUMN validates at once; it follows the ADD CONSTRAINT rows",
		match: func(u *unit) bool {
			rest, ok := addColumnRest(u)
			if !ok {
				return false
			}
			for _, w := range []string{"CHECK", "UNIQUE", "PRIMARY", "REFERENCES"} {
				if findAt(rest, 0, w) >= 0 {
					return true
				}
			}
			return false
		},
		check: func(u *unit, s *stepState) []string {
			if s.isNew(u.table) {
				return nil
			}
			return []string{"the constraint as its own ADD CONSTRAINT (NOT VALID for CHECK and FOREIGN KEY, USING INDEX for UNIQUE and PRIMARY KEY)"}
		},
	},
	{
		id: "add-column", class: classDDL, plan: "ADD COLUMN, nullable or with a constant default: allowed",
		match: func(u *unit) bool { _, ok := addColumnRest(u); return ok },
	},
	{
		id: "add-constraint-unique-pk", class: classDDL, plan: "ADD CONSTRAINT UNIQUE/PRIMARY KEY: CREATE UNIQUE INDEX CONCURRENTLY in a non-transactional step, then USING INDEX in a later step",
		match: func(u *unit) bool { k, _, _ := constraintKind(u); return k == "UNIQUE" || k == "PRIMARY" },
		check: checkUniqueUsingIndex,
	},
	{
		id: "add-constraint-exclude", class: classDDL, plan: "ADD CONSTRAINT ... EXCLUDE on a populated table: contract only",
		match: func(u *unit) bool { k, _, _ := constraintKind(u); return k == "EXCLUDE" },
		check: func(u *unit, s *stepState) []string {
			if s.isNew(u.table) {
				return nil
			}
			return needContract(s, "an exclusion constraint cannot be built online")
		},
	},
	{
		id: "add-constraint-fk-check", class: classDDL, plan: "ADD CONSTRAINT FOREIGN KEY/CHECK: NOT VALID, VALIDATE CONSTRAINT in a later step",
		match: func(u *unit) bool { k, _, _ := constraintKind(u); return k == "FOREIGN" || k == "CHECK" },
		check: checkFKCheck,
	},
	{
		id: "validate-constraint", class: classDDL, plan: "VALIDATE CONSTRAINT: in a later step than its NOT VALID ADD CONSTRAINT",
		match: func(u *unit) bool { return u.alter && at(u.action, 0, "VALIDATE", "CONSTRAINT") },
		check: checkValidate,
	},
	{
		id: "set-not-null", class: classDDL, plan: "SET NOT NULL: a validated CHECK (col IS NOT NULL) from earlier steps, or contract",
		match: func(u *unit) bool { _, op := alterColumnOp(u); return op == "SET NOT NULL" },
		check: checkSetNotNull,
	},
	{
		id: "alter-column-type", class: classDDL, plan: "ALTER COLUMN ... TYPE, or any rewrite: contract, with a size note",
		match: func(u *unit) bool { _, op := alterColumnOp(u); return op == "TYPE" },
		check: func(u *unit, s *stepState) []string { return rewrite(u, s, "ALTER COLUMN ... TYPE rewrites the table") },
	},
	{
		id: "column-default", class: classDDL, plan: "SET DEFAULT, DROP DEFAULT and DROP NOT NULL change only the catalog: allowed",
		match: func(u *unit) bool {
			_, op := alterColumnOp(u)
			return op == "SET DEFAULT" || op == "DROP DEFAULT" || op == "DROP NOT NULL"
		},
	},
	{
		id: "drop-column", class: classDDL, plan: "DROP COLUMN: contract",
		match: func(u *unit) bool { return u.alter && at(u.action, 0, "DROP") && !at(u.action, 1, "CONSTRAINT") },
		check: func(u *unit, s *stepState) []string {
			return contractUnlessNew(u, s, "a dropped column breaks the release still running")
		},
	},
	{
		id: "drop-constraint", class: classDDL, plan: "dropping a constraint (an ON CONFLICT target, a guarantee the running release relies on): contract",
		match: func(u *unit) bool { return u.alter && at(u.action, 0, "DROP", "CONSTRAINT") },
		check: func(u *unit, s *stepState) []string {
			return contractUnlessNew(u, s, "a dropped constraint can break the release still running")
		},
	},
	{
		id: "owner", class: classDDL, plan: "OWNER TO on an object the same step creates (a SECURITY DEFINER function's owner): allowed; on an older object: contract",
		match: func(u *unit) bool {
			if u.alter {
				return at(u.action, 0, "OWNER", "TO")
			}
			return at(u.toks, 0, "ALTER") && findAt(u.toks, 0, "OWNER", "TO") >= 0
		},
		check: checkOwner,
	},
	{
		id: "rename", class: classDDL, plan: "RENAME: contract",
		match: func(u *unit) bool {
			if u.alter {
				return at(u.action, 0, "RENAME")
			}
			return at(u.toks, 0, "ALTER") && findAt(u.toks, 0, "RENAME") >= 0
		},
		check: func(u *unit, s *stepState) []string {
			return contractUnlessNew(u, s, "a rename breaks the release still running")
		},
	},
	{
		id: "table-rewrite", class: classDDL, plan: "a table rewrite (SET LOGGED/UNLOGGED/TABLESPACE/ACCESS METHOD, CLUSTER, VACUUM FULL): contract, with a size note",
		match: func(u *unit) bool {
			if u.alter {
				return at(u.action, 0, "SET", "LOGGED") || at(u.action, 0, "SET", "UNLOGGED") ||
					at(u.action, 0, "SET", "TABLESPACE") || at(u.action, 0, "SET", "ACCESS", "METHOD")
			}
			return at(u.toks, 0, "CLUSTER") || (at(u.toks, 0, "VACUUM") && hasWordAnyDepth(u.toks, "FULL"))
		},
		check: func(u *unit, s *stepState) []string { return rewrite(u, s, "it rewrites the table") },
	},
	{
		id: "drop-table", class: classDDL, plan: "DROP TABLE: contract",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "DROP", "TABLE") },
		check: func(_ *unit, s *stepState) []string {
			return needContract(s, "a dropped table breaks the release still running")
		},
	},
	{
		id: "drop-object", class: classDDL, plan: "any other DROP: contract",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "DROP") },
		check: func(_ *unit, s *stepState) []string {
			return needContract(s, "a dropped object can break the release still running")
		},
	},
	{
		id: "truncate", class: classDDL, plan: "TRUNCATE destroys data: contract",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "TRUNCATE") },
		check: func(_ *unit, s *stepState) []string { return needContract(s, "TRUNCATE destroys data") },
	},
	{
		id: "create-or-replace", class: classDDL, plan: "replacing a function, procedure, view or trigger an earlier step created changes what the running release uses: contract",
		match: func(u *unit) bool { k, _ := routineKey(u, true); return k != "" },
		check: checkReplace,
	},
	{
		id: "create-object", class: classDDL, plan: "a new function, procedure, view, sequence, type, domain, schema, extension or trigger: allowed",
		match: func(u *unit) bool {
			if k, _ := routineKey(u, false); k != "" {
				return true
			}
			if u.alter || !at(u.toks, 0, "CREATE") {
				return false
			}
			return firstWordIn(u.toks[1:], additiveObjects) || at(u.toks, 1, "MATERIALIZED", "VIEW")
		},
		check: func(u *unit, s *stepState) []string {
			if k, _ := routineKey(u, false); k != "" {
				if _, seen := s.lin.routines[k]; !seen {
					s.lin.routines[k] = s.step.Version
				}
			}
			return nil
		},
	},
	{
		id: "comment", class: classDDL, plan: "COMMENT ON: allowed",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "COMMENT", "ON") },
	},
	{
		id: "grant", class: classDDL, plan: "GRANT adds a privilege: allowed",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "GRANT") },
	},
	{
		id: "revoke", class: classDDL, plan: "REVOKE can break the release still running: contract",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "REVOKE") },
		check: func(_ *unit, s *stepState) []string {
			return needContract(s, "a revoked privilege can break the release still running")
		},
	},
	{
		id: "dml-insert", class: classInsert, plan: "INSERT (a seed row): allowed in any step",
		match: func(u *unit) bool {
			if u.alter || !at(u.toks, 0, "INSERT") {
				return false
			}
			u.target = nameAfter(u.toks, "INTO")
			return true
		},
	},
	{
		id: "dml-backfill", class: classBackfill, plan: "a backfill (UPDATE, DELETE, MERGE): a data step",
		match: matchBackfill,
		check: func(u *unit, s *stepState) []string {
			if s.isNew(u.target) || s.label() == "data" {
				return nil
			}
			return []string{"the data label: a backfill runs as a data step of its own"}
		},
	},
	{
		id: "do-block", class: classDo, plan: "a DO block is opaque: allowed in a data step, else contract",
		match: func(u *unit) bool { return !u.alter && at(u.toks, 0, "DO") },
		check: func(_ *unit, s *stepState) []string {
			if s.label() == "data" {
				return nil
			}
			return needContract(s, "migcheck cannot see inside a DO block")
		},
	},
	{
		id: "read", class: classRead, plan: "SELECT, VALUES, TABLE, ANALYZE, a read-only WITH: allowed",
		match: func(u *unit) bool {
			return !u.alter && firstWordIn(u.toks, map[string]bool{"SELECT": true, "VALUES": true, "TABLE": true, "ANALYZE": true, "WITH": true})
		},
	},
	{
		id: "unknown", class: classDDL, plan: "unknown DDL is treated as contract",
		match: func(*unit) bool { return true },
		check: func(_ *unit, s *stepState) []string {
			return needContract(s, "migcheck does not recognise this statement")
		},
	},
}

// txWords start a transaction-control statement.
var txWords = map[string]bool{"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "START": true, "END": true, "SAVEPOINT": true, "RELEASE": true, "ABORT": true}

// sessionSettings are the SET parameters a step may set besides the two
// timeouts the rules name.
var sessionSettings = map[string]bool{
	"search_path": true, "client_min_messages": true, "idle_in_transaction_session_timeout": true,
	"maintenance_work_mem": true, "work_mem": true,
}

// additiveObjects are the CREATE kinds that add an object nothing uses yet.
var additiveObjects = map[string]bool{
	"SEQUENCE": true, "TYPE": true, "DOMAIN": true, "SCHEMA": true, "EXTENSION": true,
}

// routineKinds are the CREATE [OR REPLACE] kinds whose names a later step's
// CREATE OR REPLACE is checked against.
var routineKinds = map[string]bool{"FUNCTION": true, "PROCEDURE": true, "VIEW": true, "TRIGGER": true}

// volatileWords mark a VOLATILE default, evaluated once per existing row so
// that ADD COLUMN rewrites the table, and the column types and clauses that
// fill every existing row (serial, identity, stored generated). STABLE
// defaults (now(), CURRENT_TIMESTAMP, CURRENT_DATE, LOCALTIMESTAMP,
// transaction_timestamp(), statement_timestamp()) are evaluated once for
// the statement and stored in the catalog since PostgreSQL 11, so they are
// not listed: they do not rewrite.
var volatileWords = map[string]bool{
	"CLOCK_TIMESTAMP": true, "TIMEOFDAY": true, "RANDOM": true, "GEN_RANDOM_UUID": true,
	"GEN_RANDOM_BYTES": true, "UUID_GENERATE_V1": true, "UUID_GENERATE_V1MC": true, "UUID_GENERATE_V4": true,
	"NEXTVAL": true, "SERIAL": true, "BIGSERIAL": true, "SMALLSERIAL": true, "SERIAL2": true,
	"SERIAL4": true, "SERIAL8": true, "GENERATED": true,
}

func firstWordIn(ts []token, set map[string]bool) bool {
	return len(ts) > 0 && ts[0].kind == tokWord && set[ts[0].up]
}

// setParam returns the parameter a SET statement sets, folded, or "".
func setParam(u *unit) string {
	if u.alter || !at(u.toks, 0, "SET") {
		return ""
	}
	i := 1
	if at(u.toks, i, "LOCAL") || at(u.toks, i, "SESSION") {
		i++
	}
	if i >= len(u.toks) || (u.toks[i].kind != tokWord && u.toks[i].kind != tokQuotedIdent) {
		return ""
	}
	return u.toks[i].ident()
}

func needContract(s *stepState, why string) []string {
	if s.label() == "contract" {
		return nil
	}
	return []string{"the contract label: " + why}
}

func contractUnlessNew(u *unit, s *stepState, why string) []string {
	if u.alter && s.isNew(u.table) {
		return nil
	}
	return needContract(s, why)
}

// rewrite marks a unit that rewrites a populated table: contract, and the
// size-note step rule.
func rewrite(u *unit, s *stepState, why string) []string {
	if u.alter && s.isNew(u.table) {
		return nil
	}
	u.rewrite = true
	return needContract(s, why)
}

const nonTxRequired = "the non-transactional class (-- step: <label> non-transactional): CONCURRENTLY cannot run inside a transaction"

func checkCreateIndex(u *unit, s *stepState) []string {
	ts := u.toks
	i := 1
	unique := at(ts, i, "UNIQUE")
	if unique {
		i++
	}
	i++ // INDEX
	conc := at(ts, i, "CONCURRENTLY")
	if conc {
		i++
	}
	i = skipWords(ts, i, "IF", "NOT", "EXISTS")
	name := ""
	if !at(ts, i, "ON") {
		name, _ = qualifiedName(ts, i)
	}
	u.target = nameAfter(ts, "ON")
	if unique && name != "" {
		if _, seen := s.lin.uniqueIndexes[name]; !seen {
			s.lin.uniqueIndexes[name] = s.step.Version
		}
	}
	if s.isNew(u.target) {
		if conc && !s.dir.nonTx {
			return []string{nonTxRequired}
		}
		return nil
	}
	if conc && s.dir.nonTx {
		return nil
	}
	return []string{"CREATE INDEX CONCURRENTLY in a non-transactional step: an index build on an existing table blocks its writes, and CONCURRENTLY needs the non-transactional class"}
}

// concurrentOrContract is the DROP INDEX and REINDEX rule.
func concurrentOrContract(conc bool, s *stepState, what string) []string {
	if conc && s.dir.nonTx {
		return nil
	}
	if conc {
		return []string{nonTxRequired}
	}
	if s.label() == "contract" {
		return nil
	}
	return []string{what + " CONCURRENTLY in a non-transactional step, or the contract label"}
}

// addColumnRest returns the tokens after the column name of an ALTER TABLE
// ... ADD [COLUMN] [IF NOT EXISTS] name action.
func addColumnRest(u *unit) ([]token, bool) {
	if !u.alter || !at(u.action, 0, "ADD") {
		return nil, false
	}
	if k, _, _ := constraintKind(u); k != "" {
		return nil, false
	}
	a := u.action
	i := skipWords(a, 1, "COLUMN")
	i = skipWords(a, i, "IF", "NOT", "EXISTS")
	if i >= len(a) {
		return nil, false
	}
	return a[i+1:], true
}

func volatile(ts []token) bool {
	for _, t := range ts {
		if t.kind == tokWord && volatileWords[t.up] {
			return true
		}
	}
	return false
}

// constraintKinds start a table constraint in ADD [CONSTRAINT name] ....
var constraintKinds = map[string]bool{"CHECK": true, "FOREIGN": true, "UNIQUE": true, "PRIMARY": true, "EXCLUDE": true}

// constraintKind returns the kind keyword of an ADD [CONSTRAINT name] <kind>
// action, the constraint name ("" when unnamed) and the kind's index.
func constraintKind(u *unit) (kind, name string, idx int) {
	a := u.action
	if !u.alter || !at(a, 0, "ADD") || len(a) < 2 {
		return "", "", -1
	}
	i := 1
	if a[1].isWord("CONSTRAINT") {
		if len(a) < 4 {
			return "", "", -1
		}
		name = a[2].ident()
		i = 3
	}
	if a[i].kind == tokWord && constraintKinds[a[i].up] {
		return a[i].up, name, i
	}
	return "", "", -1
}

func checkUniqueUsingIndex(u *unit, s *stepState) []string {
	if s.isNew(u.table) {
		return nil
	}
	j := findAt(u.action, 0, "USING", "INDEX")
	if j < 0 || j+2 >= len(u.action) {
		return []string{"CREATE UNIQUE INDEX CONCURRENTLY in an earlier non-transactional step, then ADD CONSTRAINT ... USING INDEX"}
	}
	idx := u.action[j+2].ident()
	if v, ok := s.lin.uniqueIndexes[idx]; ok && v < s.step.Version {
		return nil
	}
	return []string{fmt.Sprintf("the unique index %s built in an earlier step (CREATE UNIQUE INDEX CONCURRENTLY, non-transactional)", idx)}
}

func checkFKCheck(u *unit, s *stepState) []string {
	kind, name, i := constraintKind(u)
	notValid := findAt(u.action, 0, "NOT", "VALID") >= 0
	isNew := s.isNew(u.table)
	if kind == "CHECK" && name != "" {
		if col := notNullColumn(u.action[i+1:]); col != "" {
			c := &notNullCheck{table: u.table, name: name, column: col, added: s.step.Version}
			if !notValid || isNew {
				c.validated = s.step.Version
			}
			s.lin.checks = append(s.lin.checks, c)
		}
	}
	if isNew {
		return nil
	}
	if notValid {
		if name != "" {
			if s.notValid == nil {
				s.notValid = map[string]bool{}
			}
			s.notValid[u.table+"."+name] = true
		}
		return nil
	}
	return []string{"NOT VALID, with VALIDATE CONSTRAINT in a later step"}
}

// notNullColumn returns col when ts is "( col IS NOT NULL )" (extra
// parentheses allowed), else "".
func notNullColumn(ts []token) string {
	var inner []token
	if len(ts) == 0 || !ts[0].isPunct("(") {
		return ""
	}
	base := ts[0].depth
	for _, t := range ts[1:] {
		if t.isPunct(")") && t.depth == base {
			break
		}
		if t.isPunct("(") || t.isPunct(")") {
			continue
		}
		inner = append(inner, t)
	}
	if len(inner) == 4 && (inner[0].kind == tokWord || inner[0].kind == tokQuotedIdent) &&
		inner[1].isWord("IS") && inner[2].isWord("NOT") && inner[3].isWord("NULL") {
		return inner[0].ident()
	}
	return ""
}

func checkValidate(u *unit, s *stepState) []string {
	if len(u.action) < 3 {
		return nil
	}
	name := u.action[2].ident()
	if s.notValid[u.table+"."+name] {
		return []string{"VALIDATE CONSTRAINT in a later step than its ADD CONSTRAINT ... NOT VALID"}
	}
	for _, c := range s.lin.checks {
		if c.table == u.table && c.name == name && c.validated == 0 {
			c.validated = s.step.Version
		}
	}
	return nil
}

// alterColumnOp returns the column and the operation of an ALTER TABLE
// ... ALTER [COLUMN] col <op> action: "SET NOT NULL", "TYPE" (with or
// without SET DATA), "SET DEFAULT", "DROP DEFAULT", "DROP NOT NULL", or ""
// for another operation.
func alterColumnOp(u *unit) (col, op string) {
	a := u.action
	if !u.alter || !at(a, 0, "ALTER") {
		return "", ""
	}
	i := skipWords(a, 1, "COLUMN")
	if i >= len(a) {
		return "", ""
	}
	col = a[i].ident()
	i++
	switch {
	case at(a, i, "SET", "NOT", "NULL"):
		return col, "SET NOT NULL"
	case at(a, i, "TYPE"), at(a, i, "SET", "DATA", "TYPE"):
		return col, "TYPE"
	case at(a, i, "SET", "DEFAULT"):
		return col, "SET DEFAULT"
	case at(a, i, "DROP", "DEFAULT"):
		return col, "DROP DEFAULT"
	case at(a, i, "DROP", "NOT", "NULL"):
		return col, "DROP NOT NULL"
	}
	return col, ""
}

func checkSetNotNull(u *unit, s *stepState) []string {
	if s.isNew(u.table) || s.label() == "contract" {
		return nil
	}
	col, _ := alterColumnOp(u)
	v := s.step.Version
	for _, c := range s.lin.checks {
		if c.table == u.table && c.column == col && c.added < v && c.validated > 0 && c.validated < v {
			return nil
		}
	}
	return []string{fmt.Sprintf("a CHECK (%s IS NOT NULL) constraint added NOT VALID and validated in earlier steps, or the contract label", col)}
}

// routineKey returns "<kind>:<name>" for CREATE [OR REPLACE] FUNCTION,
// PROCEDURE, VIEW or TRIGGER (replace selects the OR REPLACE form), else "".
func routineKey(u *unit, replace bool) (string, string) {
	ts := u.toks
	if u.alter || !at(ts, 0, "CREATE") {
		return "", ""
	}
	i := 1
	if at(ts, i, "OR", "REPLACE") != replace {
		return "", ""
	}
	if replace {
		i += 2
	}
	for _, w := range []string{"TEMPORARY", "TEMP", "RECURSIVE", "CONSTRAINT"} {
		i = skipWords(ts, i, w)
	}
	if i >= len(ts) || ts[i].kind != tokWord || !routineKinds[ts[i].up] {
		return "", ""
	}
	kind := strings.ToLower(ts[i].up)
	name, _ := qualifiedName(ts, i+1)
	if name == "" {
		return "", ""
	}
	return kind + ":" + name, kind + " " + name
}

func checkReplace(u *unit, s *stepState) []string {
	key, what := routineKey(u, true)
	v, seen := s.lin.routines[key]
	if !seen {
		s.lin.routines[key] = s.step.Version
		return nil
	}
	if v >= s.step.Version {
		return nil
	}
	return needContract(s, fmt.Sprintf("it replaces %s, which step %d created and the running release uses", what, v))
}

// checkOwner allows OWNER TO on a table, function, procedure or view the
// step itself creates.
func checkOwner(u *unit, s *stepState) []string {
	if u.alter {
		return contractUnlessNew(u, s, "it changes the owner of a table the running release uses")
	}
	if len(u.toks) > 2 && u.toks[1].kind == tokWord && routineKinds[u.toks[1].up] {
		name, _ := qualifiedName(u.toks, 2)
		if v, ok := s.lin.routines[strings.ToLower(u.toks[1].up)+":"+name]; ok && v == s.step.Version {
			return nil
		}
	}
	return needContract(s, "it changes the owner of an object the running release uses")
}

// matchBackfill matches UPDATE, DELETE, MERGE and a WITH that modifies.
func matchBackfill(u *unit) bool {
	if u.alter || len(u.toks) == 0 {
		return false
	}
	ts := u.toks
	switch {
	case at(ts, 0, "UPDATE"):
		u.target, _ = qualifiedName(ts, skipWords(ts, 1, "ONLY"))
	case at(ts, 0, "DELETE", "FROM"):
		u.target, _ = qualifiedName(ts, skipWords(ts, 2, "ONLY"))
	case at(ts, 0, "MERGE", "INTO"):
		u.target, _ = qualifiedName(ts, skipWords(ts, 2, "ONLY"))
	case at(ts, 0, "WITH"):
		return hasWordAnyDepth(ts, "UPDATE", "DELETE", "MERGE")
	default:
		return false
	}
	return true
}

// violation is one step-rule finding before it becomes a Finding.
type violation struct {
	stmt     string
	required string
}

// stepRule is one row of the step table. Every row applies.
type stepRule struct {
	id    string
	plan  string
	check func(s *stepState, manifest func(lineage, table string) bool) []violation
}

// stepRules are the rules about a whole step, in report order.
var stepRules = []stepRule{
	{id: "label", plan: "no expand, contract or data label: never", check: func(s *stepState, _ func(string, string) bool) []violation {
		switch len(s.dir.labels) {
		case 0:
			return []violation{{required: "a label: -- step: expand, contract or data"}}
		case 1:
			return nil
		}
		return []violation{{required: "exactly one label, not " + strings.Join(s.dir.labels, ", ")}}
	}},
	{id: "directive", plan: "the -- step: vocabulary is closed", check: func(s *stepState, _ func(string, string) bool) []violation {
		if len(s.dir.unknown) == 0 {
			return nil
		}
		return []violation{{required: "-- step: words from expand, contract, data and non-transactional only; unknown: " + strings.Join(s.dir.unknown, ", ")}}
	}},
	{id: "lock-timeout", plan: "no SET lock_timeout header: never", check: checkLockHeader},
	{id: "policy-own-step", plan: "policy and row-level-security changes: a step of their own", check: func(s *stepState, _ func(string, string) bool) []violation {
		has := false
		for _, u := range s.units {
			if u.class == classPolicy && !s.isNew(u.target) {
				has = true
			}
		}
		if !has {
			return nil
		}
		return ownStep(s, classPolicy, "policy and row-level-security changes in a step of their own (move this statement to another step)")
	}},
	{id: "add-value-own-step", plan: "ALTER TYPE ... ADD VALUE: a step of its own", check: func(s *stepState, _ func(string, string) bool) []violation {
		for _, u := range s.units {
			if u.class == classAddValue {
				return ownStep(s, classAddValue, "ALTER TYPE ... ADD VALUE in a step of its own (move this statement to another step)")
			}
		}
		return nil
	}},
	{id: "non-transactional-one-statement", plan: "the non-transactional class (G2a) is one statement per step", check: func(s *stepState, _ func(string, string) bool) []violation {
		if !s.dir.nonTx {
			return nil
		}
		stmts := map[int]bool{}
		for _, u := range s.units {
			if !u.class.isHeader() {
				stmts[u.stmt] = true
			}
		}
		if len(stmts) == 1 {
			return nil
		}
		return []violation{{required: fmt.Sprintf("exactly one statement besides the SET headers in a non-transactional step (found %d)", len(stmts))}}
	}},
	{id: "data-step", plan: "a data step: batched by key range, its own statement_timeout, progress in the lineage's progress table (schema_meta), or transactional where the runner keeps none", check: checkDataStep},
	{id: "size-note", plan: "a rewrite: contract, with a size note", check: func(s *stepState, _ func(string, string) bool) []violation {
		if s.dir.size != "" {
			return nil
		}
		for _, u := range s.units {
			if u.rewrite {
				return []violation{{stmt: u.excerpt, required: "a size note (-- size: the table's size and the expected duration) for the table rewrite"}}
			}
		}
		return nil
	}},
	{id: "manifest-row", plan: "a T table created without its manifest row (17.1 rule 3): never; the manifest check is injected, nil until M3-0.2", check: func(s *stepState, manifest func(string, string) bool) []violation {
		if manifest == nil {
			return nil
		}
		var out []violation
		for _, t := range s.created {
			if !manifest(s.step.Lineage, t) {
				out = append(out, violation{required: "a tenancy manifest row for table " + t + " (plan 06 17.1 rule 3)"})
			}
		}
		return out
	}},
}

// ownStep reports the first unit that is neither a header nor of class c.
func ownStep(s *stepState, c stmtClass, required string) []violation {
	for _, u := range s.units {
		if !u.class.isHeader() && u.class != c {
			return []violation{{stmt: u.excerpt, required: required}}
		}
	}
	return nil
}

func checkLockHeader(s *stepState, _ func(string, string) bool) []violation {
	var lock *unit
	for _, u := range s.units {
		if u.class == classLockTimeout {
			if lock == nil {
				lock = u
			}
			continue
		}
		if u.class.isHeader() {
			continue
		}
		if lock == nil {
			return []violation{{stmt: u.excerpt, required: "a SET lock_timeout header before the first statement"}}
		}
		break
	}
	if lock != nil && s.dir.nonTx && at(lock.toks, 1, "LOCAL") {
		return []violation{{stmt: lock.excerpt, required: "a plain SET lock_timeout in a non-transactional step: SET LOCAL has no effect outside a transaction"}}
	}
	return nil
}

func checkDataStep(s *stepState, _ func(string, string) bool) []violation {
	if s.label() != "data" {
		return nil
	}
	caps := capabilityOf(s.step.Lineage)
	var out []violation
	timeout, progress := false, false
	for _, u := range s.units {
		switch u.class {
		case classStmtTimeout:
			timeout = true
		case classLockTimeout, classSessionSet:
		case classInsert, classBackfill, classDo, classRead:
			if caps.progressTable != "" && mentions(u.toks, caps.progressTable) {
				progress = true
			}
			if u.class == classBackfill && (at(u.toks, 0, "UPDATE") || at(u.toks, 0, "DELETE")) && findAt(u.toks, 0, "WHERE") < 0 {
				out = append(out, violation{stmt: u.excerpt, required: "a WHERE bounding the batch by key range"})
			}
		default:
			out = append(out, violation{stmt: u.excerpt, required: "DML only in a data step (move the schema change to an expand or contract step)"})
		}
	}
	if !timeout {
		out = append(out, violation{required: "SET statement_timeout: a data step carries its own"})
	}
	out = append(out, dataStepResume(s, caps, progress)...)
	return out
}

// dataStepResume is how a data step survives a failure, by what the
// lineage's runner keeps (lineageCapability): with a progress table, the step
// records its progress there so a rerun resumes it; without one, the step
// must be transactional, so a failure rolls all of it back and the rerun
// starts it over.
func dataStepResume(s *stepState, caps lineageCapability, progress bool) []violation {
	if caps.progressTable == "" {
		if s.dir.nonTx {
			return []violation{{required: "a transactional data step: this lineage's runner keeps no data-step progress table, so a data step commits whole or not at all (drop non-transactional)"}}
		}
		return nil
	}
	if !progress {
		return []violation{{required: "the step's progress recorded in " + caps.progressTable + ", so it resumes"}}
	}
	return nil
}

// mentions reports whether any token names ident, including inside a
// dollar-quoted body (a DO block).
func mentions(ts []token, ident string) bool {
	for _, t := range ts {
		switch t.kind {
		case tokWord, tokQuotedIdent:
			if t.ident() == ident {
				return true
			}
		case tokDollar:
			if strings.Contains(strings.ToLower(t.text), ident) {
				return true
			}
		}
	}
	return false
}
