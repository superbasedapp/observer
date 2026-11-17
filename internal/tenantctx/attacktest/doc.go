// Package attacktest is the shared attack-test kit of internal/tenantctx
// (managed-SaaS plan 07, M3b.2 and M6.1b): one ordered table of attacks on a
// tenant context, run by every adopter against its own live database.
//
// An adopter describes itself in a [Harness]: its [tenantctx.Kind], the key
// the database verifies against, two subjects that each own probe rows, the
// statements that open one of its tenant transactions, and how to open a
// dedicated [Session] logged in as its runtime login. [Run] then runs every
// [Case] as a subtest, each on a fresh session. [Check] returns the same
// results without a *testing.T, which is how the kit tests itself against an
// in-memory model of the database (model_test.go), including broken models
// it must catch.
//
// The cases (one row each; the table is [Cases]):
//
//   - a valid context sees its own subject's rows and no other's, and can
//     write only its own (the positive control);
//   - a missing context sees nothing and writes nothing;
//   - forged tokens ([Forgeries]: a subject swapped under a kept MAC, an
//     extended expiry, a flipped bit, upper-case hex, another key's MAC,
//     extra or missing segments, an overlong token, a bare subject) see
//     nothing;
//   - an expired token, correctly signed, sees nothing;
//   - a wrong-scope token, a token of another kind for the same subject
//     under the same key, sees nothing;
//   - token reuse across transactions: a context set in one transaction is
//     gone in the next on the same session, after commit or rollback;
//   - raw set_config by the runtime login: a bare subject set at session or
//     transaction level, or by SET, sees nothing;
//   - RESET and SET ... TO DEFAULT inside a transaction remove the context;
//   - DISCARD ALL clears even a session-level context, and refused inside a
//     transaction it leaves nothing behind.
//
// The kit judges only what the session can see and write, through the
// adopter's probe: it does not assume how the database checks the token.
// It drives transactions with plain BEGIN / COMMIT / ROLLBACK / SAVEPOINT
// statements on one session, so a [Session] must keep one connection.
//
// It is a normal package, not a _test.go file, so both adopters' tests can
// import it; it imports "testing" and is referenced only from tests, so it
// never enters a production binary. Driver-agnostic: no database/sql, pgx,
// net/http or fsnotify, and no adopter (imports_test.go).
package attacktest
