// Package nontx holds the pure decisions of the non-transactional migration
// step class (plan 07 row M3a.1, plan 06 G2a and section 18.2.4): the step a
// PostgreSQL runner applies outside a transaction, one statement per step,
// because CREATE INDEX CONCURRENTLY and its siblings refuse to run inside one.
//
// A step opts in with internal/migcheck's directive
//
//	-- step: expand non-transactional
//
// and must then hold exactly one statement of an allowed kind (the kinds
// table: CREATE [UNIQUE] INDEX CONCURRENTLY with a name, DROP INDEX
// CONCURRENTLY, REINDEX INDEX|TABLE CONCURRENTLY) plus SET headers from a
// closed parameter table (the same harmless set migcheck accepts as headers,
// lock_timeout first among them). Parse checks that shape and returns what
// the runner executes in order: the headers before the statement, the
// statement, the headers after it.
//
// The runner (internal/orgserver/db/pgmigrations) owns every query. Before
// each attempt it probes the catalogue for the step's index and hands the
// facts to Resume, an ordered rule table that makes the step resumable: an
// index an earlier run finished is just recorded, an invalid index an
// interrupted CREATE INDEX CONCURRENTLY left behind is dropped before the
// retry, an index an earlier DROP already removed is just recorded, and the
// invalid _ccnew/_ccold leftovers of an interrupted REINDEX CONCURRENTLY are
// dropped before the rebuild. A failed attempt goes to RetryPolicy.Next, whose
// table names the retryable SQLSTATEs (lock_timeout's lock_not_available and
// deadlock_detected); the wait doubles from Base up to Cap for at most
// MaxAttempts attempts, and the runner sleeps through an injected sleeper.
//
// The statement splitter here is a small SQL lexer (comments, nested block
// comments, quoted strings and identifiers, dollar quotes): the runner must
// send each statement on its own, because a multi-statement simple query is
// an implicit transaction block and CONCURRENTLY refuses it. internal/migcheck
// has the same lexer unexported; folding the two onto one owner is a named
// follow-up.
//
// The package is pure: no SQL driver, HTTP, filesystem or fsnotify (pinned by
// imports_test.go).
package nontx
