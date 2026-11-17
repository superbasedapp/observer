package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/tenantctx"
)

// The tenant-context key (managed-SaaS plan 07 M3b.2 / M6.1b): the HMAC key
// the store signs every tenant transaction's account context with and
// sbci_current_account() verifies (cloud migrations 0066-0067). Every
// process of one deployment (serve, worker, the operator commands) must load
// the same key; `migrate` installs it in the database.
const (
	envTenantContextKey     = "SBCI_TENANT_CONTEXT_KEY"
	envTenantContextKeyFile = "SBCI_TENANT_CONTEXT_KEY_FILE"
)

// tenantContextKeyFromEnv reads the key from SBCI_TENANT_CONTEXT_KEY or the
// file SBCI_TENANT_CONTEXT_KEY_FILE names: hex, at least 64 digits (32
// bytes). It returns nil, nil when neither is set.
func tenantContextKeyFromEnv() ([]byte, error) {
	hexKey, err := readSecretEnv(envTenantContextKey, envTenantContextKeyFile)
	if err != nil {
		return nil, err
	}
	if hexKey == "" {
		return nil, nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%s: not hex: %w", envTenantContextKey, err)
	}
	if err := tenantctx.CheckKey(key); err != nil {
		return nil, fmt.Errorf("%s: %w", envTenantContextKey, err)
	}
	return key, nil
}

// applyTenantContextKey gives s the configured key. With none configured the
// store keeps its process-random key, which it installs itself only when its
// login may write the key table (the single-login dev posture).
func applyTenantContextKey(s *store.Store) error {
	key, err := tenantContextKeyFromEnv()
	if err != nil {
		return err
	}
	if key == nil {
		slog.Default().Warn("observer-cloud: " + envTenantContextKey + "[_FILE] unset - this process signs tenant contexts with a process-random key, which only a login that may install keys can use; set it on every process of a deployment and run `observer-cloud migrate` with it")
		return nil
	}
	return s.SetTenantContextKey(key)
}

// envAllowKeyInDBLog=1 lets migrate send the key although the database's
// logging would write it to the server log (docs/security.md CLOUDKEYLOG-1).
const envAllowKeyInDBLog = "SBCI_ALLOW_KEY_IN_DB_LOG"

// installTenantContextKey is migrate's step after the lineage: when a key is
// configured, install it as the current key (other keys keep verifying for
// store.TenantKeyOverlap, so a rotation does not cut off processes still on
// the old key). It reports the key id, never the key. The key travels as a
// bound parameter, so it first refuses while the server, as this login's
// session sees it, would log statement parameters (a managed PostgreSQL may
// ship with slow-statement logging on: OVH logs every statement over 1 s
// with its parameters in full).
func installTenantContextKey(ctx context.Context, pool *pgxpool.Pool) (string, error) {
	key, err := tenantContextKeyFromEnv()
	if err != nil || key == nil {
		return "", err
	}
	settings, err := readKeyLogSettings(ctx, pool)
	if err != nil {
		return "", err
	}
	if err := keyLogDecision(tenantctx.KeyLogExposure(settings), os.Getenv(envAllowKeyInDBLog)); err != nil {
		return "", err
	}
	id, err := store.InstallTenantContextKey(ctx, pool, key, true)
	if err != nil {
		return "", err
	}
	return id, nil
}

// readKeyLogSettings reads tenantctx.KeyLogSettings as the migrating login's
// session sees them (per-role and per-database settings included). A setting
// the server does not have (pgaudit not loaded) is simply absent.
func readKeyLogSettings(ctx context.Context, pool *pgxpool.Pool) (map[string]string, error) {
	rows, err := pool.Query(ctx, `SELECT name, setting FROM pg_settings WHERE name = ANY($1)`, tenantctx.KeyLogSettings)
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

// keyLogDecision refuses to send the key while any exposure reason applies,
// unless allow is "1" (then it warns and goes on).
func keyLogDecision(reasons []string, allow string) error {
	if len(reasons) == 0 {
		return nil
	}
	if strings.TrimSpace(allow) == "1" {
		slog.Default().Warn("observer-cloud migrate: installing the tenant context key although the database may write it to its log; rotate the key and purge the log afterwards",
			"reasons", strings.Join(reasons, "; "), "override", envAllowKeyInDBLog)
		return nil
	}
	return fmt.Errorf("refusing to send the tenant context key: the database would write it to its log (%s); turn that logging off for the migrating login's session or the server (log_min_duration_statement = -1, or log_parameter_max_length = 0), or set %s=1 to accept it and then rotate the key and purge the log (docs/security.md CLOUDKEYLOG-1)",
		strings.Join(reasons, "; "), envAllowKeyInDBLog)
}
