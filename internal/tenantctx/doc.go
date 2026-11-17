// Package tenantctx is the one row-level-security context mechanism of the
// managed-SaaS platform (plan 07, M3b.2): the token a tenant transaction
// carries, the signer that mints it, the Go statement of the database check,
// and the statement an adopter runs to set it. It has two adopters:
//
//   - the org server's internal/orgserver/tenantdb ([KindOrg]: the subject
//     is an org id, the setting sbo.tenant, the database check
//     sbo_current_org() in org pgmigrations 0189);
//   - the cloud service's internal/cloudserver/store ([KindAccount]: the
//     subject is an account id, the setting sbci.account_id, the database
//     check sbci_current_account() in cloud migration 0067).
//
// The shared attack-test kit both adopters run against their live database
// is the subpackage attacktest.
//
// # The token
//
//	<subject>.<expiry>.<mac>
//
// subject: the org or account id (no whitespace or control characters; it
// may contain dots, the token splits from the right; an account id is a
// lower-case canonical UUID). expiry: unix seconds. mac: the lower-case hex
// HMAC-SHA256, under a key only the database's checking function can read,
// of the kind's domain followed by "<subject>.<expiry>". The database accepts
// the token while expiry is later than now(), the transaction's start, so a
// context never lapses inside the transaction that set it. Any session may
// set a custom setting, so the setting proves nothing; the MAC is what a
// session without the key cannot make.
//
// The key is a secret the service loads (the org server from its platform
// secrets, the cloud service from SBCI_TENANT_CONTEXT_KEY or its _FILE form)
// and installs into the database through a SECURITY DEFINER function the
// runtime login cannot execute. It is never generated in SQL. The database
// stores the key's two HMAC pads (RFC 2104) and computes the MAC with core
// sha256(), so no extension is needed. [KeyID] names a key's row, so
// installing the same key twice is idempotent.
//
// # Kinds never cross
//
// An org token never verifies as an account token, nor the reverse, even
// under one key. The kind is bound into the MAC, not only into the setting
// name: the MAC input is the kind's domain followed by "<subject>.<expiry>".
// The org kind's domain is empty, because its MAC input is the one org
// pgmigrations 0189 already computes and that step is not changed here
// (changing the token would need a new org step and a coordinated roll).
// Every other kind's domain ends in a newline and contains no other control
// character, and no subject of any kind may contain a control character, so
// the set of MAC inputs of one kind is disjoint from every other kind's:
// an account MAC input always contains a newline and an org one never does.
// A MAC therefore proves the kind it was made for. The kind table in kind.go
// is the whole definition; TestKindDomainsAreDisjoint pins the rule.
//
// # Per transaction, not per session (the L-21 decision, settled here)
//
// Plan 06 5.3.4 describes a session-scoped token set by a tenant pool's
// connector, with a 24-hour expiry, and names the per-transaction form its
// fallback. This package settles on per transaction for both adopters:
// every tenant transaction's first step is the kind's [Kind.SetLocalSQL],
// set_config(<setting>, $1, true), with a token of [DefaultTTL]. The reasons:
//
//  1. One mechanism for both adopters. The cloud service has always set its
//     context per transaction (store.WithAccount); a session token would
//     give it a second mechanism or a pool per account.
//  2. It survives a transaction pooler. The S-2 spike found a pooler in
//     transaction mode hands a server connection to another client between
//     transactions; a session setting would travel with it. A SET LOCAL
//     value reverts when the transaction ends, commit or rollback, so a
//     returned connection carries no subject to its next borrower.
//  3. It fits the connection budget. S-2 measured about 94 usable
//     connections on the chosen database tier; a per-transaction context
//     lets tenant work share one pool instead of one per org (5.3.4's own
//     fallback), and it does not forbid per-org pools either.
//  4. A short-lived bearer value. A session token lives as long as its
//     connection (5.3.4: a 24-hour expiry); a transaction token is minted
//     per transaction and lives 15 minutes, so one copied out of a log or
//     pg_stat_activity is worth little. The token is a bind parameter, not
//     statement text, in the first place.
//  5. It fails closed. RESET, SET ... TO DEFAULT or DISCARD ALL inside the
//     transaction can only remove the context, never install another
//     subject's; a transaction that never set one sees no tenant row.
//
// The cost, which 5.3.4 names: every runtime statement that reads tenant
// rows must run inside a transaction that began with the step. The org
// server's tenantdb.Tenant and tenantdb.Fenced and the cloud store's
// WithAccount are those transactions. M4.0's step slot in tenantdb (the
// ordered in-transaction steps) is where the org side's step runs.
//
// # Imports
//
// tenantctx is pure: no database/sql, net/http or fsnotify (imports_test.go).
// An adopter executes the statement and token [Signer.Step] returns on its
// own transaction, with its own driver.
package tenantctx
