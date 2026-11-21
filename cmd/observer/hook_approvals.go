package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// hook_approvals.go is the hook process's §6.3 approval lookup (P-232).
//
// It used to be a lazy db.Open per blocking verdict: a ping, the pragmas
// and the migration check against the node's full database, then the query
// under the hook timeout, with ANY failure reported as "no grant" and
// nothing recorded. On a large busy node that read could miss a live grant
// silently (the investigation's 08:03:21 S-793 ask). Now the lookup:
//
//   - opens the database READ-ONLY (mode=ro, query_only) and never runs the
//     migration lineage: a hook must not be the process that migrates the
//     node, and a read needs none of it;
//   - bounds SQLite's busy wait inside the hook budget (hookApprovalBusy),
//     with the whole open+query under one context of that budget;
//   - returns the failure as an error, which the guard records on the
//     verdict (" [approval lookup failed: ...]"), so an operator can see why
//     a granted rule still asked. Fail-safe toward enforcement is unchanged.
//
// A database file that does not exist yet, or one with no guard_approvals
// table yet (created by another hook step before the daemon migrated it), is
// (false, nil): a node with no register has no grants, and that is not a
// failure.

// defaultHookApprovalBudget is the budget used when [observer.hooks]
// timeout_ms is unset or zero: the config default (500 ms).
const defaultHookApprovalBudget = 500 * time.Millisecond

// hookApprovalBusy is the SQLite busy_timeout for the hook's approval read:
// half the hook budget, never below 20 ms, so the query still has time to
// run after a wait and the reply is not late.
func hookApprovalBusy(budget time.Duration) time.Duration {
	if budget <= 0 {
		budget = defaultHookApprovalBudget
	}
	busy := budget / 2
	if busy < 20*time.Millisecond {
		busy = 20 * time.Millisecond
	}
	return busy
}

// hookApprovalDSN is the read-only, migration-free DSN of the hook's
// approval read.
func hookApprovalDSN(dbPath string, busy time.Duration) string {
	return fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(%d)",
		sqlitedsn.Escape(dbPath), busy.Milliseconds())
}

// hookApprovalLookup returns the hook guard's approval lookup over the
// database at dbPath, bounded by budget (the hook timeout).
func hookApprovalLookup(dbPath string, budget time.Duration) guard.ApprovalLookup {
	return func(ruleID, sessionID, rootHash string) (bool, error) {
		return hookApprovalRead(dbPath, budget, false, func(ctx context.Context, st *store.Store) (bool, error) {
			return st.ApprovalActiveFor(ctx, ruleID, sessionID, rootHash, time.Now().UTC())
		})
	}
}

// hookApprovalCoverLookup is hookApprovalLookup that also says which approval
// covers (store.ApprovalCoverFor: the same scope semantics, in the same single
// read), so a verdict can name the approval and its grantor (plan section 13.7).
func hookApprovalCoverLookup(dbPath string, budget time.Duration) guard.ApprovalCoverLookup {
	return func(ruleID, sessionID, rootHash string) (guard.ApprovalCover, error) {
		return hookApprovalRead(dbPath, budget, guard.ApprovalCover{}, func(ctx context.Context, st *store.Store) (guard.ApprovalCover, error) {
			c, err := st.ApprovalCoverFor(ctx, ruleID, sessionID, rootHash, time.Now().UTC())
			return guard.ApprovalCover{Found: c.Found, ID: c.ID, GrantedBy: c.GrantedBy}, err
		})
	}
}

// hookApprovalRead runs one read of the approvals register under the hook's
// rules (the file's header comment): read-only open, no migration, one budget
// for the open and the query, and a missing file or register is no grant.
func hookApprovalRead[T any](dbPath string, budget time.Duration, none T, read func(context.Context, *store.Store) (T, error)) (T, error) {
	if budget <= 0 {
		budget = defaultHookApprovalBudget
	}
	if dbPath == "" {
		return none, errors.New("no database path configured")
	}
	if _, err := os.Stat(dbPath); errors.Is(err, fs.ErrNotExist) {
		return none, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	database, err := sql.Open("sqlite", hookApprovalDSN(dbPath, hookApprovalBusy(budget)))
	if err != nil {
		return none, fmt.Errorf("open: %w", err)
	}
	defer database.Close()
	database.SetMaxOpenConns(1)
	got, err := read(ctx, store.New(database))
	if err != nil && !approvalsTablePresent(ctx, database) {
		// A database the daemon has not migrated yet (a fresh file
		// another hook step created) has no register, so no grants:
		// the same answer as a missing file, not a failure.
		return none, nil
	}
	return got, err
}

// approvalsTablePresent reports whether guard_approvals exists. It runs only
// after the lookup failed; when the schema itself cannot be read it reports
// true, so the original error stands.
func approvalsTablePresent(ctx context.Context, database *sql.DB) bool {
	var one int
	err := database.QueryRowContext(ctx,
		`SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'guard_approvals'`).Scan(&one)
	return !errors.Is(err, sql.ErrNoRows)
}
