package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/tenantctx"
)

// The cloud service's adoption of internal/tenantctx (managed-SaaS plan 07
// M3b.2 / M6.1b). A tenant transaction's context is a MAC'd token of kind
// tenantctx.KindAccount, set per transaction in sbci.account_id and verified
// by sbci_current_account() (migration 0067) against the keys installed in
// sbci_tenant_context_keys (0066). A bare account id in the setting is no
// context at all.
//
// The key. A production process loads it from SBCI_TENANT_CONTEXT_KEY or
// SBCI_TENANT_CONTEXT_KEY_FILE (cmd/observer-cloud; every process of one
// deployment uses the same key), calls SetTenantContextKey, and
// `observer-cloud migrate` installs it with InstallTenantContextKey (only the
// migrating login may write the key table). serve and worker check at boot
// with VerifyTenantContext that the database verifies their key.
//
// A Store given no key (New's default, the dev and test posture) signs with a
// process-random key and installs it itself, once, before its first tenant
// transaction. That install needs the migrating login's privileges, so it
// works in the single-login dev posture and fails, loudly, under the
// split-role logins, where the key must be configured.

// TenantKeyOverlap is how long the keys a rotation replaces keep verifying:
// long enough for every process to restart with the new key.
const TenantKeyOverlap = 24 * time.Hour

// tenantContext is a Store's signer and the state of its key's install.
type tenantContext struct {
	signer *tenantctx.Signer
	key    []byte
	// auto is true for the process-random key: the Store installs it itself.
	auto bool
	// err is a construction failure; every tenant transaction returns it.
	err error

	mu        sync.Mutex
	installed bool
}

// newAutoTenantContext returns the default context: a process-random key.
func newAutoTenantContext() *tenantContext {
	key := make([]byte, tenantctx.MinKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return &tenantContext{err: fmt.Errorf("cloudserver/store: tenant context key: %w", err)}
	}
	signer, err := tenantctx.NewSigner(tenantctx.KindAccount, key, 0, nil)
	if err != nil {
		return &tenantContext{err: fmt.Errorf("cloudserver/store: tenant context key: %w", err)}
	}
	return &tenantContext{signer: signer, key: key, auto: true}
}

// SetTenantContextKey makes key (tenantctx.MinKeyBytes to MaxKeyBytes) the
// key this Store signs tenant contexts with, in place of the process-random
// default. The Store then never installs a key itself: the database must
// already hold this one (InstallTenantContextKey, run by `observer-cloud
// migrate`). Call it at bootstrap, before any transaction.
func (s *Store) SetTenantContextKey(key []byte) error {
	signer, err := tenantctx.NewSigner(tenantctx.KindAccount, key, 0, nil)
	if err != nil {
		return fmt.Errorf("cloudserver/store.SetTenantContextKey: %w", err)
	}
	s.tenant = &tenantContext{signer: signer, key: append([]byte(nil), key...)}
	return nil
}

// TenantContextKeyID returns the id (tenantctx.KeyID) of the key this Store
// signs with, "" when it has none. It names the key's row in
// sbci_tenant_context_keys; it is not secret.
func (s *Store) TenantContextKeyID() string {
	if s.tenant == nil || s.tenant.signer == nil {
		return ""
	}
	return s.tenant.signer.KeyID()
}

// InstallTenantContextKey installs key in the database's key table through
// sbci_tenant_context_install and returns its id, which must equal
// tenantctx.KeyID(key). With rotate, every other installed key stops
// verifying TenantKeyOverlap from now; without it nothing is retired.
// Installing a key already present re-arms it. Only the migrating login may
// install (the application roles hold no privilege on the key table).
func InstallTenantContextKey(ctx context.Context, pool *pgxpool.Pool, key []byte, rotate bool) (string, error) {
	if err := tenantctx.CheckKey(key); err != nil {
		return "", fmt.Errorf("cloudserver/store.InstallTenantContextKey: %w", err)
	}
	var overlapSeconds *int64
	if rotate {
		v := int64(TenantKeyOverlap / time.Second)
		overlapSeconds = &v
	}
	var id string
	if err := pool.QueryRow(ctx,
		`SELECT sbci_tenant_context_install($1, CASE WHEN $2::bigint IS NULL THEN NULL ELSE $2::bigint * interval '1 second' END)`,
		key, overlapSeconds).Scan(&id); err != nil {
		return "", fmt.Errorf("cloudserver/store.InstallTenantContextKey: %w", err)
	}
	if want := tenantctx.KeyID(key); id != want {
		return "", fmt.Errorf("cloudserver/store.InstallTenantContextKey: the database named the key %q, Go names it %q", id, want)
	}
	return id, nil
}

// ReadServerLogSettings reads the named server settings from pg_settings as
// the pool login's session sees them (per-role and per-database settings
// included). A setting the server does not have (pgaudit not loaded) is
// simply absent from the map. The migrate command passes
// tenantctx.KeyLogSettings to decide whether the tenant-context key may be
// sent as a bound parameter.
func ReadServerLogSettings(ctx context.Context, pool *pgxpool.Pool, names []string) (map[string]string, error) {
	rows, err := pool.Query(ctx, `SELECT name, setting FROM pg_settings WHERE name = ANY($1)`, names)
	if err != nil {
		return nil, fmt.Errorf("read the server's logging settings: %w", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, fmt.Errorf("read the server's logging settings: %w", err)
		}
		out[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the server's logging settings: %w", err)
	}
	return out, nil
}

// ensureTenantKey installs the process-random key the first time a tenant
// transaction needs it. A configured key is never installed here.
func (s *Store) ensureTenantKey(ctx context.Context) error {
	t := s.tenant
	if t == nil {
		return errors.New("cloudserver/store: no tenant context")
	}
	if t.err != nil {
		return t.err
	}
	if !t.auto {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.installed {
		return nil
	}
	if _, err := InstallTenantContextKey(ctx, s.pool, t.key, false); err != nil {
		return fmt.Errorf("cloudserver/store: install this process's tenant context key (set SBCI_TENANT_CONTEXT_KEY and run `observer-cloud migrate` when the runtime login may not): %w", err)
	}
	t.installed = true
	return nil
}

// SetAccountContext sets accountID's tenant context on tx, for that
// transaction only: it mints a token of kind tenantctx.KindAccount and runs
// `SELECT set_config('sbci.account_id', $1, true)` with it. accountID must be
// a UUID; it is lower-cased to the canonical form uuid::text prints. The
// transaction-opening helpers (WithAccount) call it; it is exported for the
// few callers that run their own transaction (tests). A bare account id set
// by any other means is no context at all (migration 0067).
func (s *Store) SetAccountContext(ctx context.Context, tx pgx.Tx, accountID string) error {
	t := s.tenant
	if t == nil || t.err != nil || t.signer == nil {
		if t != nil && t.err != nil {
			return fmt.Errorf("cloudserver/store.SetAccountContext: %w", t.err)
		}
		return errors.New("cloudserver/store.SetAccountContext: no tenant context signer")
	}
	query, token, err := t.signer.Step(strings.ToLower(accountID))
	if err != nil {
		return fmt.Errorf("cloudserver/store.SetAccountContext: %w", err)
	}
	if _, err := tx.Exec(ctx, query, token); err != nil {
		return fmt.Errorf("cloudserver/store.SetAccountContext: %w", err)
	}
	return nil
}

// tenantProbeAccount is the account id VerifyTenantContext checks with. No
// account row is read; only sbci_current_account()'s answer is compared.
const tenantProbeAccount = "00000000-0000-0000-0000-000000000000"

// VerifyTenantContext checks that the database verifies this Store's key: in
// a transaction under the store's role it sets a context for a fixed probe
// account and requires sbci_current_account() to return it. serve and
// worker call it at boot, so a key the database does not hold (a missing
// `observer-cloud migrate`, two processes with different keys) stops the
// process instead of making every tenant read silently empty.
func (s *Store) VerifyTenantContext(ctx context.Context) error {
	if err := s.ensureTenantKey(ctx); err != nil {
		return fmt.Errorf("cloudserver/store.VerifyTenantContext: %w", err)
	}
	var got string
	err := s.inTx(ctx, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, s.appRole.setLocalRoleSQL()); err != nil {
			return fmt.Errorf("set role: %w", err)
		}
		if err := s.SetAccountContext(ctx, tx, tenantProbeAccount); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT coalesce(sbci_current_account()::text, '')`).Scan(&got)
	})
	if err != nil {
		return fmt.Errorf("cloudserver/store.VerifyTenantContext: %w", err)
	}
	if got != tenantProbeAccount {
		return fmt.Errorf("cloudserver/store.VerifyTenantContext: the database does not verify tenant context key %s: install it with `observer-cloud migrate` (SBCI_TENANT_CONTEXT_KEY[_FILE] set the same on every process)", s.TenantContextKeyID())
	}
	return nil
}
