// Package migcheck checks new PostgreSQL migration steps for the online
// migration rules of the managed-SaaS plan (plan 06, section 18.2.4,
// "Migration safety at merge time"). In a pooled database one bad migration
// reaches every org at once, so every new step of the org PostgreSQL lineage
// (internal/orgserver/db/pgmigrations) and of the cloud lineage
// (internal/cloudserver/db/migrations) must say what kind of step it is and
// must not take a long blocking lock.
//
// The package is pure: it takes the steps as text (lineage, version, file
// name, SQL) and an exempt set, and returns findings. It reads no files,
// opens no database and makes no network call (pinned by imports_test.go).
// The command tools/migcheck reads the two directories and the shipped
// record and calls Analyze; it runs advisory in scripts/hooks/pre-push and
// as the "migcheck" row of scripts/ci/gate-commands.tsv. That row is
// advisory until R1: it flips to --enforce at R1, when the M0.8 rules land
// in CLAUDE.md and M3a ships the non-transactional step class (G2a).
//
// # Step directives
//
// A step declares itself in line comments in its header, before its first
// SQL statement:
//
//	-- step: expand
//	-- step: contract non-transactional
//	-- size: idx on sessions, about 40 GB on the largest org; 25 minutes
//
// "-- step:" takes one or more words from a closed vocabulary: exactly one
// label, expand, contract or data, plus optionally non-transactional (the
// G2a step class: the runner applies the step outside a transaction, one
// statement per step). Words may also be split over several "-- step:"
// lines. "-- size:" is the size note a table rewrite needs. A directive
// after the first statement is not read.
//
// Every checked step also needs a lock_timeout header: a SET lock_timeout
// statement before its first statement that is not a SET. SET LOCAL is
// accepted in a transactional step; a non-transactional step needs a plain
// SET, because SET LOCAL outside a transaction has no effect.
//
// # The rules
//
// Each statement is classified by one ordered table (statementRules in
// rules.go), walked top-down, first match wins; a multi-action ALTER TABLE is
// split into one unit per action first, so each action meets the same table.
// The last row matches anything: unrecognised DDL requires the contract
// label (it needs the operator's go). Rules that look at the whole step
// (label, header, own-step classes, data steps, size note, tenancy manifest)
// are a second table, stepRules, all of whose rows apply. A statement on a
// table created in the same step is on an empty table, so the lock rules do
// not apply to it.
//
// Some rules look across steps: SET NOT NULL needs a CHECK (col IS NOT NULL)
// constraint added and validated in earlier steps, ADD CONSTRAINT ... USING
// INDEX needs a unique index built in an earlier step, and CREATE OR
// REPLACE of a function or view an earlier step created is a contract
// change. Exempt steps are still read for this state; they only produce no
// findings.
//
// # Exemptions
//
// A step listed in tests/invariant/testdata/shipped-migrations.json is
// exempt: it shipped and can never change (docs/migration-numbering.md, the
// released-step rule). Steps numbered at or below a lineage's pre-migcheck
// head (PreMigcheckHead: org PostgreSQL 0184, cloud 0044) predate migcheck
// and carry no directives; they are exempt too. Those heads are the start of
// the managed-SaaS arc and never move; every later step is checked.
//
// # What it cannot see
//
// The tokenizer knows line and block comments (nested), single-quoted,
// E'...' and U&'...' strings, quoted identifiers and dollar-quoted bodies.
// It does not parse SQL. The body of a DO block or a function is opaque, so
// a DO block outside a data step needs the contract label. A
// BEGIN ATOMIC function body is split at its semicolons; its pieces are
// unrecognised statements, so the step needs contract: loud, never silent.
// A data step's batching by key range is checked only as far as a WHERE
// clause on every UPDATE and DELETE; the rest is review.
//
// The tenancy manifest rule (plan 06 17.1 rule 3: a T table is never created
// without its manifest row) is a step rule whose check is the injected
// Input.ManifestHasTable. The manifest (managed-SaaS M3-0.2) is not built
// yet, so the command passes nil and the row checks nothing today.
package migcheck
