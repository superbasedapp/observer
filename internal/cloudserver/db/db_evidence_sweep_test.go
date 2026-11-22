package db_test

// db_evidence_sweep_test.go pins the hardening cloud migration 0151 gives
// sbci_sweep_expired_evidence before it grants the function to sbci_worker
// (findings 2026-11-22 CLOUD-01). 0005 created the sweep with unqualified
// relation names under `SET search_path = public`, the shape 0027 fixed for
// sbci_sweep_retention (Sol F1): an application role holds the default TEMP
// privilege, and pg_temp is searched before public for relations unless the
// search_path lists it explicitly, so a caller's own
// `CREATE TEMP TABLE evidence_objects (...)` shadowed the real table for the
// whole SECURITY DEFINER body. The caller then chose which tenant's evidence
// blobs the definer (BYPASSRLS sbci_defs) deleted, and a trigger on the
// shadow table would run as sbci_defs. 0151 schema-qualifies both tables and
// pins `search_path = pg_catalog, public, pg_temp`. Since 0153 no application
// role holds TEMP; the test gives sbci_worker TEMP on its own database
// (grantAttackerTemp) to model an attacker who kept it, so the sweep is
// proven safe without relying on the revoke.

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
)

// TestSweepExpiredEvidenceIgnoresTempTableShadow drives the attack as the
// worker role: on one pinned session it becomes sbci_worker, shadows
// evidence_objects with a temp table naming another tenant's live evidence as
// expired, and runs the sweep. The live blob and its object must survive.
func TestSweepExpiredEvidenceIgnoresTempTableShadow(t *testing.T) {
	pool := cloudtestpg.NewDB(t)
	ctx := context.Background()

	// A victim account with one live (unexpired) evidence object and blob,
	// seeded as the test's superuser.
	var victim string
	if err := pool.QueryRow(ctx,
		`INSERT INTO accounts (status) VALUES ('active') RETURNING account_id::text`).Scan(&victim); err != nil {
		t.Fatalf("create victim account: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO evidence_objects (account_id, blob_ref, upload_digest, evidence_content_digest, expires_at)
		 VALUES ($1::uuid, 'evidence/live', 'sha256:u', 'sha256:c', now() + interval '1 hour')`, victim); err != nil {
		t.Fatalf("seed live evidence object: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO evidence_blobs (account_id, blob_ref, ciphertext) VALUES ($1::uuid, 'evidence/live', '\x00')`, victim); err != nil {
		t.Fatalf("seed live evidence blob: %v", err)
	}

	grantAttackerTemp(t, pool, "sbci_worker")
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire pinned connection: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET ROLE sbci_worker`); err != nil {
		t.Fatalf("SET ROLE sbci_worker: %v", err)
	}
	defer func() { _, _ = conn.Exec(context.Background(), `RESET ROLE`) }()

	if _, err := conn.Exec(ctx,
		`CREATE TEMP TABLE evidence_objects (
		    account_id uuid, blob_ref text, expires_at timestamptz, deleted_at timestamptz
		 ) ON COMMIT PRESERVE ROWS`); err != nil {
		t.Fatalf("sbci_worker could not create the pg_temp.evidence_objects shadow (the test granted it TEMP): %v", err)
	}
	if _, err := conn.Exec(ctx,
		`INSERT INTO pg_temp.evidence_objects (account_id, blob_ref, expires_at)
		 VALUES ($1::uuid, 'evidence/live', now() - interval '1 hour')`, victim); err != nil {
		t.Fatalf("seed shadow row: %v", err)
	}
	// The attacker owns the shadow, so it can let the definer read and write
	// it; without this the shadowed body fails on the temp table's ACL instead.
	if _, err := conn.Exec(ctx, `GRANT ALL ON pg_temp.evidence_objects TO PUBLIC`); err != nil {
		t.Fatalf("grant the shadow to PUBLIC: %v", err)
	}

	var deleted int
	if err := conn.QueryRow(ctx, `SELECT sbci_sweep_expired_evidence(now())`).Scan(&deleted); err != nil {
		t.Fatalf("sbci_sweep_expired_evidence as sbci_worker with a pg_temp shadow: %v", err)
	}
	if deleted != 0 {
		t.Errorf("the sweep deleted %d blobs, want 0: it resolved evidence_objects to the caller's temp shadow", deleted)
	}

	var blobs int
	var objectDeleted bool
	if err := pool.QueryRow(ctx,
		`SELECT (SELECT count(*) FROM public.evidence_blobs WHERE account_id = $1::uuid),
		        (SELECT deleted_at IS NOT NULL FROM public.evidence_objects WHERE account_id = $1::uuid)`,
		victim).Scan(&blobs, &objectDeleted); err != nil {
		t.Fatalf("read victim evidence: %v", err)
	}
	if blobs != 1 || objectDeleted {
		t.Fatalf("victim's live evidence after the shadowed sweep: blobs=%d deleted=%v; want the blob kept and the object live", blobs, objectDeleted)
	}

	var owner, cfg string
	var secdef bool
	if err := pool.QueryRow(ctx,
		`SELECT pg_get_userbyid(proowner), prosecdef, coalesce(array_to_string(proconfig, ','), '')
		   FROM pg_proc WHERE proname = 'sbci_sweep_expired_evidence'`).Scan(&owner, &secdef, &cfg); err != nil {
		t.Fatalf("introspect sbci_sweep_expired_evidence: %v", err)
	}
	if owner != "sbci_defs" || !secdef || cfg != "search_path=pg_catalog, public, pg_temp" {
		t.Errorf("sbci_sweep_expired_evidence shape: owner=%q secdef=%v config=%q; want sbci_defs, true, search_path=pg_catalog, public, pg_temp", owner, secdef, cfg)
	}
}
