package main

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// approvalPageSection is the nav section where a guard approval is granted
// (the dashboard Security page). It is hidden by default on a managed node
// (nodegov.ManagedNavDefaults), and the approvals API is refused while it is.
const approvalPageSection = "security"

// approvalPageTTL is how long one governance read answers the guard's
// "is the Security page hidden here" question in a long-lived process.
const approvalPageTTL = 60 * time.Second

// storeOpener opens a store for one governance read and returns its closer.
type storeOpener func(ctx context.Context) (*store.Store, func(), error)

// approvalPageHiddenLookup is the guard's ApprovalPageHidden lookup (CG-16):
// whether this machine's verified node.governance (with the managed-node
// defaults) hides the Security page, so the block texts name the CLI rather
// than a page the developer cannot open. The guard asks it on a blocking
// verdict only. It reads the same verified last-known-good cache every other
// governance consumer reads (loadNodeGovernanceLKG) and caches the answer for
// approvalPageTTL. Any failure keeps the last answer, or reports "shown" when
// there is none, which keeps the texts as they were before this lookup.
func approvalPageHiddenLookup(cfg config.Config, open storeOpener, logger *slog.Logger) func() bool {
	if open == nil {
		return nil
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	var (
		mu    sync.Mutex
		at    time.Time
		known bool
		val   bool
	)
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		if known && time.Since(at) < approvalPageTTL {
			return val
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		st, closeFn, err := open(ctx)
		if err != nil || st == nil {
			return known && val
		}
		defer closeFn()
		val = approvalPageEffective(ctx, cfg, st, logger).IsNavSectionHidden(approvalPageSection)
		known, at = true, time.Now()
		return val
	}
}

// approvalPageEffective resolves this machine's governance posture from the
// verified last-known-good node.governance cache (a var so the lookup's
// table test can stand in a posture without signing a governance body).
var approvalPageEffective = func(ctx context.Context, cfg config.Config, st *store.Store, logger *slog.Logger) govern.Effective {
	ngov := newNodeGovernanceHandle(governanceIdentityLoader(st), logger)
	loadNodeGovernanceLKG(ctx, cfg, st, ngov, logger)
	return ngov.Effective(ctx)
}

// storeOpenerFor reuses an already-open store (the daemon's): no close.
func storeOpenerFor(st *store.Store) storeOpener {
	if st == nil {
		return nil
	}
	return func(context.Context) (*store.Store, func(), error) { return st, func() {}, nil }
}

// hookStoreOpener opens the node database READ-ONLY for a hook process, the
// way the hook's approval lookup does (hookApprovalDSN): no migration run, a
// busy timeout inside the hook budget. A missing file is "no store".
func hookStoreOpener(dbPath string, budget time.Duration) storeOpener {
	if dbPath == "" {
		return nil
	}
	if budget <= 0 {
		budget = defaultHookApprovalBudget
	}
	return func(context.Context) (*store.Store, func(), error) {
		if _, err := os.Stat(dbPath); errors.Is(err, fs.ErrNotExist) {
			return nil, nil, err
		}
		database, err := sql.Open("sqlite", hookApprovalDSN(dbPath, hookApprovalBusy(budget)))
		if err != nil {
			return nil, nil, err
		}
		database.SetMaxOpenConns(1)
		return store.New(database), func() { _ = database.Close() }, nil
	}
}
