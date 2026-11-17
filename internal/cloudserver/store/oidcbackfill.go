package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/oidcissuer"
)

// oidcbackfill.go holds the reads and the one write behind the operator verb
// `observer-cloud oidc register-client` (managed-SaaS plan 07 wave 16 lane
// control-plane; lead decision W16-D7; docs/security.md CPSIGN-13): an org
// provisioned before the provisioning hook registered its platform OIDC
// client (orgoidcclient.go), or on a cloud whose tenant domain was unset at
// the time, has no client, and its owner cannot sign in on its tenant host.
//
// Two roles, because no one role reads both sides: the org registry (class
// M) is read through the worker role, whose outbox policies see every org
// row and whose column grants cover org_id, slug, kind and status (0058,
// 0089, 0092); oidc_clients (class S) is read and written through the
// operator role (sbci_app, 0052). The write is EnsureOIDCClientTx, the same
// idempotent ensure the provisioning hook runs, so the verb never rewrites a
// registered client.

// OIDCBackfillOrg is one org as the backfill sees it.
type OIDCBackfillOrg struct {
	OrgID  string
	Slug   string
	Kind   OrgKind
	Status string
}

// OIDCClientState is one registered client as the backfill sees it.
type OIDCClientState struct {
	ClientID     string
	OrgID        string
	RedirectURIs []string
	Disabled     bool
}

// OrgsForOIDCBackfill returns the org orgID, or every org when orgID is
// empty, ordered by org id (purged orgs included: the verb's rule table
// decides). ErrNotFound when orgID names no org (or is malformed). Run it
// on a worker-role store.
func (s *Store) OrgsForOIDCBackfill(ctx context.Context, orgID string) ([]OIDCBackfillOrg, error) {
	var out []OIDCBackfillOrg
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		q := `SELECT org_id::text, slug, kind, status FROM orgs ORDER BY org_id`
		args := []any{}
		if orgID != "" {
			q = `SELECT org_id::text, slug, kind, status FROM orgs WHERE org_id = $1::uuid`
			args = append(args, orgID)
		}
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o OIDCBackfillOrg
			var kind string
			if err := rows.Scan(&o.OrgID, &o.Slug, &kind, &o.Status); err != nil {
				return err
			}
			o.Kind = OrgKind(kind)
			out = append(out, o)
		}
		return rows.Err()
	})
	if isInvalidUUIDErr(err) || (err == nil && orgID != "" && len(out) == 0) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.OrgsForOIDCBackfill: %w", err)
	}
	return out, nil
}

// OIDCClientsByOrg returns every registered platform OIDC client keyed by
// its org id. Run it on the operator-role store.
func (s *Store) OIDCClientsByOrg(ctx context.Context) (map[string]OIDCClientState, error) {
	out := map[string]OIDCClientState{}
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT client_id, org_id::text, redirect_uris, disabled_at IS NOT NULL FROM oidc_clients`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c OIDCClientState
			if err := rows.Scan(&c.ClientID, &c.OrgID, &c.RedirectURIs, &c.Disabled); err != nil {
				return err
			}
			out[c.OrgID] = c
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.OIDCClientsByOrg: %w", err)
	}
	return out, nil
}

// EnsureOIDCClient registers c in a transaction of its own unless the same
// client is already there (EnsureOIDCClientTx); a client registered
// differently is ErrOIDCClientConflict and nothing is written. Run it on the
// operator-role store.
func (s *Store) EnsureOIDCClient(ctx context.Context, c oidcissuer.Client) error {
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return EnsureOIDCClientTx(ctx, tx, c)
	})
	if errors.Is(err, ErrOIDCClientConflict) {
		return err
	}
	if err != nil {
		return fmt.Errorf("cloudserver/store.EnsureOIDCClient: %w", err)
	}
	return nil
}
